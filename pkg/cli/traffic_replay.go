package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var replayInReplace bool

var trafficReplayCmd = &cobra.Command{
	Use:   "replay [search-term]",
	Short: "Replay stored HTTP requests and compare responses",
	Long:  "Re-send stored HTTP requests and display a side-by-side comparison of original vs new response.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runTrafficReplay,
}

func init() {
	trafficCmd.AddCommand(trafficReplayCmd)

	trafficReplayCmd.Flags().BoolVar(&replayInReplace, "in-replace", false, "Replace stored response with the new replay response")
}

func runTrafficReplay(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	var fuzzyTerm string
	if len(args) == 1 {
		fuzzyTerm = args[0]
	}

	filters, err := buildTrafficFilters(fuzzyTerm)
	if err != nil {
		return err
	}

	ctx := context.Background()
	qb := database.NewQueryBuilder(db, filters)
	records, err := qb.Execute(ctx)
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No matching records found.")
		return nil
	}

	fmt.Printf("Replaying %d request(s)...\n\n", len(records))

	client := buildReplayClient()
	repo := database.NewRepository(db)

	for _, rec := range records {
		if err := replayRecord(ctx, client, repo, rec); err != nil {
			fmt.Printf("%s Failed to replay %s %s: %v\n",
				terminal.ErrorPrefix(), rec.Method, rec.URL, err)
		}
		fmt.Println()
	}

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

// replayRecord reconstructs and re-sends a single stored request.
func replayRecord(ctx context.Context, client *http.Client, repo *database.Repository, rec *database.HTTPRecord) error {
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
	displayReplayComparison(rec, resp, body, elapsed)

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
			fmt.Printf("  %s Failed to update record: %v\n", terminal.WarnPrefix(), err)
		} else {
			fmt.Printf("  %s Record %s response replaced\n", terminal.SuccessSymbol(), rec.UUID[:8])
		}
	}

	return nil
}

// displayReplayComparison shows a side-by-side comparison of original vs replay.
func displayReplayComparison(rec *database.HTTPRecord, newResp *http.Response, newBody []byte, elapsed time.Duration) {
	fmt.Printf("%s %s %s\n", terminal.Cyan(rec.Method), rec.URL, terminal.Gray(fmt.Sprintf("[%s]", rec.UUID[:8])))

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
		truncate(rec.ResponseContentType, 30),
		truncate(newResp.Header.Get("Content-Type"), 30))

	tbl.Print()

	if rec.StatusCode != newResp.StatusCode {
		fmt.Printf("  %s Status code changed: %d → %d\n",
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
