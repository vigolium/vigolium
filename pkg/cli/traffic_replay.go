package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// replayInReplace overwrites each stored response with its replay response.
// Shared by the HTTP and browser replay paths; set via `traffic --in-replace`.
var replayInReplace bool

// runTrafficReplayFlow is invoked from runTraffic when --replay is set. It
// queries the matching records (same filters as the listing view) and
// re-sends each one, printing an original-vs-replay comparison. Records are
// replayed concurrently up to --concurrency so an operator can throttle the
// load they put on an intercepting proxy (Burp). With --with-browser each
// record's URL is loaded in a real browser routed through --proxy instead of
// the raw HTTP client.
func runTrafficReplayFlow(ctx context.Context, db *database.DB, fuzzyTerm string) error {
	filters, err := buildTrafficFilters(fuzzyTerm)
	if err != nil {
		return err
	}

	qb := database.NewQueryBuilder(db, filters)
	records, err := qb.Execute(ctx)
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}
	if len(records) == 0 {
		fmt.Println("No matching records found.")
		return nil
	}

	concurrency := trafficReplayConcurrency
	if concurrency < 1 {
		concurrency = 1
	}

	mode := "HTTP client"
	if trafficReplayBrowser {
		mode = "browser"
		if globalProxy == "" {
			fmt.Printf("%s --with-browser without --proxy: browser traffic isn't being routed to an intercepting proxy\n",
				terminal.WarnPrefix())
		}
	}
	fmt.Printf("Replaying %d request(s) via %s (concurrency %d)...\n\n", len(records), mode, concurrency)

	repo := database.NewRepository(db)
	var client *http.Client
	if !trafficReplayBrowser {
		client = buildReplayClient()
	}

	var (
		wg      sync.WaitGroup
		printMu sync.Mutex
		sem     = make(chan struct{}, concurrency)
	)

	for _, rec := range records {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(rec *database.HTTPRecord) {
			defer wg.Done()
			defer func() { <-sem }()

			// Each record renders into its own buffer so the per-record
			// block (header line + comparison table) prints atomically and
			// concurrent replays don't interleave their output.
			var buf strings.Builder
			var rErr error
			if trafficReplayBrowser {
				rErr = browserReplayRecord(ctx, &buf, rec)
			} else {
				rErr = replayRecord(ctx, &buf, client, repo, rec)
			}
			if rErr != nil {
				fmt.Fprintf(&buf, "%s Failed to replay %s %s: %v\n",
					terminal.ErrorPrefix(), rec.Method, rec.URL, rErr)
			}

			printMu.Lock()
			fmt.Print(buf.String())
			fmt.Println()
			printMu.Unlock()
		}(rec)
	}
	wg.Wait()

	return nil
}

// buildReplayClient creates a simple HTTP client for replaying requests.
func buildReplayClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for replay
	}

	if globalProxy != "" {
		if proxyURL, err := url.Parse(globalProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   globalTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// replayRecord reconstructs and re-sends a single stored request, writing the
// comparison to w.
func replayRecord(ctx context.Context, w io.Writer, client *http.Client, repo *database.Repository, rec *database.HTTPRecord) error {
	if len(rec.RawRequest) == 0 {
		return fmt.Errorf("no raw request stored")
	}

	// Reconstruct request from stored raw data
	hrr, err := httpmsg.ParseRawRequestWithURL(string(rec.RawRequest), rec.URL)
	if err != nil {
		return fmt.Errorf("failed to parse raw request: %w", err)
	}

	retryReq, err := hrr.BuildRetryableRequest()
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}

	// Extract standard *http.Request
	stdReq := retryReq.Request.WithContext(ctx)

	// Execute
	start := time.Now()
	resp, err := client.Do(stdReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	elapsed := time.Since(start)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Display comparison
	displayReplayComparison(w, rec, resp, body, elapsed)

	// --in-replace: update stored response
	if replayInReplace {
		rawResp := buildRawResponseHeaders(resp)
		rawResp = append(rawResp, body...)

		contentType := resp.Header.Get("Content-Type")

		update := &database.RecordResponseUpdate{
			StatusCode:            resp.StatusCode,
			StatusPhrase:          resp.Status,
			ResponseHTTPVersion:   resp.Proto,
			ResponseContentType:   contentType,
			ResponseContentLength: int64(len(body)),
			RawResponse:           rawResp,
			ResponseTimeMs:        elapsed.Milliseconds(),
		}

		if err := repo.UpdateRecordResponse(ctx, rec.UUID, update); err != nil {
			fmt.Fprintf(w, "  %s Failed to update record: %v\n", terminal.WarnPrefix(), err)
		} else {
			fmt.Fprintf(w, "  %s Record %s response replaced\n", terminal.SuccessSymbol(), rec.UUID[:min(8, len(rec.UUID))])
		}
	}

	return nil
}

// browserReplayRecord re-issues a stored record's URL through a real browser
// (rod), routed via --proxy so an intercepting proxy like Burp sees genuine
// browser traffic — real TLS fingerprint, JS execution, and subresource
// loads. Only the URL is replayed: a browser navigation is a GET, so the
// original method/body of non-GET records is not reproduced (noted in the
// output). Stored auth headers (Cookie/Authorization) are forwarded so the
// retrieval runs under the captured session.
func browserReplayRecord(ctx context.Context, w io.Writer, rec *database.HTTPRecord) error {
	if rec.URL == "" {
		return fmt.Errorf("record has no URL to load")
	}

	res, err := spitolas.ProbeURL(ctx, spitolas.ProbeConfig{
		URL:      rec.URL,
		ProxyURL: globalProxy,
		// The point of browser replay is to feed an intercepting proxy, so
		// route loopback targets through it too (Chrome bypasses them by default).
		ProxyAllowLoopback: true,
		Headers:            browserReplayHeaders(rec),
		NavTimeout:         globalTimeout,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "%s %s %s\n",
		terminal.Cyan(rec.Method), rec.URL,
		terminal.Gray(fmt.Sprintf("[%s]", rec.UUID[:min(8, len(rec.UUID))])))

	if rec.Method != "" && rec.Method != http.MethodGet {
		fmt.Fprintf(w, "  %s browser replay issues a GET navigation; original %s method/body not reproduced\n",
			terminal.WarnPrefix(), rec.Method)
	}

	if res != nil {
		if res.FinalURL != "" && res.FinalURL != rec.URL {
			fmt.Fprintf(w, "  %s redirected to %s\n", terminal.InfoSymbol(), res.FinalURL)
		}
		if res.Title != "" {
			fmt.Fprintf(w, "  title: %s\n", clicommon.Truncate(res.Title, 60))
		}
		for _, d := range res.Dialogs {
			fmt.Fprintf(w, "  %s JS dialog fired (%s): %s\n",
				terminal.WarnPrefix(), d.Type, clicommon.Truncate(d.Message, 80))
		}
	}
	return nil
}

// browserReplayHeaders pulls the session-bearing headers out of a stored
// request so the browser navigation runs authenticated. Lookups are
// case-insensitive because stored header casing varies (HTTP/2 lowercases).
func browserReplayHeaders(rec *database.HTTPRecord) map[string]string {
	hdrs := rec.RequestHeadersMap()
	if len(hdrs) == 0 {
		return nil
	}
	lower := make(map[string]string, len(hdrs))
	for name, vals := range hdrs {
		if len(vals) > 0 {
			lower[strings.ToLower(name)] = vals[0]
		}
	}
	out := map[string]string{}
	for _, h := range []string{"Authorization", "Cookie", "User-Agent"} {
		if v := lower[strings.ToLower(h)]; v != "" {
			out[h] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// displayReplayComparison writes a side-by-side comparison of original vs replay.
func displayReplayComparison(w io.Writer, rec *database.HTTPRecord, newResp *http.Response, newBody []byte, elapsed time.Duration) {
	fmt.Fprintf(w, "%s %s %s\n", terminal.Cyan(rec.Method), rec.URL, terminal.Gray(fmt.Sprintf("[%s]", rec.UUID[:min(8, len(rec.UUID))])))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "ORIGINAL", "REPLAY")

	origStatus := fmt.Sprintf("%d", rec.StatusCode)
	newStatus := fmt.Sprintf("%d", newResp.StatusCode)
	tbl.AddRow("Status",
		colorStatus(origStatus, rec.StatusCode),
		colorStatus(newStatus, newResp.StatusCode))

	tbl.AddRow("Time",
		fmt.Sprintf("%dms", rec.ResponseTimeMs),
		fmt.Sprintf("%dms", elapsed.Milliseconds()))

	tbl.AddRow("Size",
		fmt.Sprintf("%d bytes", rec.ResponseContentLength),
		fmt.Sprintf("%d bytes", len(newBody)))

	tbl.AddRow("Content-Type",
		clicommon.Truncate(rec.ResponseContentType, 30),
		clicommon.Truncate(newResp.Header.Get("Content-Type"), 30))

	fmt.Fprint(w, tbl.Render())

	if rec.StatusCode != newResp.StatusCode {
		fmt.Fprintf(w, "  %s Status code changed: %d → %d\n",
			terminal.WarnPrefix(), rec.StatusCode, newResp.StatusCode)
	}
}

// colorStatus applies color based on HTTP status code range.
func colorStatus(text string, code int) string {
	switch {
	case code >= 500:
		return terminal.Red(text)
	case code >= 400:
		return terminal.Yellow(text)
	case code >= 300:
		return terminal.Cyan(text)
	case code >= 200:
		return terminal.Green(text)
	default:
		return text
	}
}

// buildRawResponseHeaders reconstructs raw HTTP response header bytes from http.Response.
func buildRawResponseHeaders(resp *http.Response) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	for key, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", key, v)
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}
