package tool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// ---------- web_fetch ----------
//
// Dual-mode:
//   - Default: plain HTTP(S) GET/POST via net/http. Fast, no browser.
//   - mode="browser": drives Chromium via spitolas (CDP) for JS-rendered
//     pages, SPAs, login-gated content. Spawns a fresh headless browser,
//     navigates, optionally waits for a selector, then returns the
//     post-render DOM. When the tool is wired with a capture sink, every
//     XHR/fetch the page issues during render is persisted as an
//     http_record (source="web-fetch-browser") so query_records sees the
//     real network surface, not just the document.
//
// The tool keeps a single schema so the model doesn't have to choose two
// different tools — it decides per-call via the `mode` parameter.

type webFetchTool struct {
	client *http.Client

	// captureSink + captureProject, when both set, persist every successful
	// fetch (HTTP and browser modes) as an http_record under source=
	// "web-fetch" / "web-fetch-browser". Lets query_records / inspect_record /
	// replay_request immediately act on whatever the agent just fetched
	// without a separate ingest step. Nil sink disables capture.
	captureSink    spitolas.CaptureSink
	captureProject string
}

// NewWebFetch returns the no-capture variant. Used by TUI chat, tests, and
// other callers that don't have a database wired.
func NewWebFetch() Tool {
	return &webFetchTool{client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWebFetchWithCapture wires a CaptureSink so every successful fetch is
// persisted to the project DB. Records appear in query_records under
// source="web-fetch" (HTTP mode) or "web-fetch-browser" (rendered HTML).
// Pass nil sink or empty projectUUID to fall back to the no-capture variant.
func NewWebFetchWithCapture(sink spitolas.CaptureSink, projectUUID string) Tool {
	if sink == nil || projectUUID == "" {
		return NewWebFetch()
	}
	return &webFetchTool{
		client:         &http.Client{Timeout: 30 * time.Second},
		captureSink:    sink,
		captureProject: projectUUID,
	}
}

func (*webFetchTool) Name() string     { return "web_fetch" }
func (*webFetchTool) Label() string    { return "Fetch URL" }
func (*webFetchTool) Category() string { return CategoryBuiltin }

// IsReadOnly gates whether the engine may fan this tool out concurrently with
// other read-only calls. The capture-enabled variant persists an http_record
// to the project DB on every successful fetch — regardless of HTTP method, and
// browser mode writes many records per call — so it is NOT parallel-safe:
// concurrent capturing fetches race on the shared record store. It can also
// issue arbitrary (state-changing) methods. Only the no-capture variant
// (TUI/query, no DB wired) is genuinely read-only.
func (w *webFetchTool) IsReadOnly() bool { return w.captureSink == nil }
func (*webFetchTool) Description() string {
	return "Fetch a URL. Default mode is plain HTTP (fast, returns raw response, one record persisted). Set mode='browser' to render via headless Chromium (handles JS SPAs, client-side routing) — every XHR/fetch the page issues during render is also captured, so a single browser fetch typically produces many http_records. Use browser mode when the initial HTTP response is empty or missing content that clearly depends on JavaScript. HTTP-mode returns Details.record_uuid; browser-mode persists multiple records — call query_records with the target hostname to enumerate them."
}
func (*webFetchTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "HTTP or HTTPS URL."},
			"mode": map[string]any{
				"type":        "string",
				"enum":        []string{"http", "browser"},
				"description": "'http' = raw HTTP request (fast, one record); 'browser' = render with headless Chromium via CDP (also captures every XHR/fetch issued during render).",
				"default":     "http",
			},
			"method":  map[string]any{"type": "string", "default": "GET", "description": "HTTP method (http mode only)."},
			"headers": map[string]any{"type": "object", "description": "Extra request headers (http mode only)."},
			"body":    map[string]any{"type": "string", "description": "Request body (http mode only)."},
			"max_bytes": map[string]any{
				"type":        "integer",
				"description": "Truncate response body after N bytes. Default 512000.",
				"default":     512000,
			},
			"wait_selector": map[string]any{
				"type":        "string",
				"description": "(browser mode) CSS selector to wait for before grabbing HTML.",
			},
			"wait_ms": map[string]any{
				"type":        "integer",
				"description": "(browser mode) Extra ms to wait after load. Default 1500.",
				"default":     1500,
			},
		},
		"required": []string{"url"},
	}
}

func (w *webFetchTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return Result{Content: "error: url is required", IsError: true}, nil
	}
	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "http"
	}

	switch mode {
	case "browser":
		return w.executeBrowser(ctx, url, args)
	default:
		return w.executeHTTP(ctx, url, args)
	}
}

func (w *webFetchTool) executeHTTP(ctx context.Context, url string, args map[string]any) (Result, error) {
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	var bodyReader io.Reader
	if bodyStr, ok := args["body"].(string); ok && bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Result{Content: fmt.Sprintf("bad request: %v", err), IsError: true}, nil
	}
	req.Header.Set("User-Agent", "olium/0.1 (+https://vigolium.com)")
	if headers, ok := args["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return Result{Content: fmt.Sprintf("request failed: %v", err), IsError: true}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap so a response landing exactly on maxBytes
	// isn't misreported as truncated. Trim the sentinel byte back off when the
	// body actually overflowed.
	limited := io.LimitReader(resp.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Result{Content: fmt.Sprintf("read body: %v", err), IsError: true}, nil
	}

	truncated := int64(len(raw)) > maxBytes
	if truncated {
		raw = raw[:maxBytes]
	}
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP/%d %s\n", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		fmt.Fprintf(&out, "%s: %s\n", k, strings.Join(vs, ", "))
	}
	out.WriteString("\n")
	out.Write(raw)
	if truncated {
		fmt.Fprintf(&out, "\n\n[truncated at %d bytes]", maxBytes)
	}

	details := map[string]any{
		"mode":         "http",
		"status":       resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"bytes":        len(raw),
		"truncated":    truncated,
	}

	// Persist for downstream tools (query_records, inspect_record,
	// replay_request). Capture failures are non-fatal — the model still
	// gets the body even if persistence breaks.
	if recUUID, perr := w.persistHTTPFetch(ctx, req, resp, raw); perr == nil && recUUID != "" {
		details["record_uuid"] = recUUID
	}

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}

// persistHTTPFetch serialises the just-completed request/response pair into
// raw HTTP bytes and hands it to the capture sink. Returns the new record's
// UUID (or empty when capture is disabled or fails). All errors are
// surfaced to the caller as a flag, not propagated — fetch already succeeded
// and the model has the body, so a persistence hiccup shouldn't fail the
// tool call.
func (w *webFetchTool) persistHTTPFetch(ctx context.Context, req *http.Request, resp *http.Response, body []byte) (string, error) {
	if w.captureSink == nil || w.captureProject == "" {
		return "", nil
	}

	host, port := splitHostPort(req.URL)
	scheme := req.URL.Scheme
	svc, err := httpmsg.NewService(host, port, scheme)
	if err != nil {
		return "", err
	}

	rawReq := buildRawRequest(req)
	rawResp := buildRawResponse(resp, body)

	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, rawReq),
		httpmsg.NewHttpResponse(rawResp),
	)
	return w.captureSink.SaveRecord(ctx, rr, "web-fetch", w.captureProject)
}

// buildRawRequest serialises a sent net/http.Request back to wire bytes
// (request line + headers + body). Stable header ordering so the
// request_hash stays deterministic across calls.
func buildRawRequest(req *http.Request) []byte {
	var b bytes.Buffer

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)

	// Host header up front (some servers care about ordering).
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)

	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header.Values(k) {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")

	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			if data, err := io.ReadAll(rc); err == nil {
				b.Write(data)
			}
			_ = rc.Close()
		}
	}
	return b.Bytes()
}

// buildRawResponse rebuilds the response wire bytes from a *http.Response +
// already-read body. Used by capture paths where we've consumed resp.Body
// into a buffer.
func buildRawResponse(resp *http.Response, body []byte) []byte {
	var b bytes.Buffer
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&b, "%s %s\r\n", proto, resp.Status)

	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header.Values(k) {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	// Synthesize Content-Length when missing so downstream parsers don't
	// have to guess where the body ends.
	if resp.Header.Get("Content-Length") == "" && len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// splitHostPort returns hostname + numeric port, defaulting to 80/443 per
// scheme when the URL omits it.
func splitHostPort(u *urlpkg.URL) (string, int) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			return host, 443
		}
		return host, 80
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// executeBrowser drives spitolas (Chromium via CDP) for JS-rendered pages.
// Spitolas does what agent-browser used to: navigate, wait, grab the
// post-JS DOM. The big win over agent-browser is CDP-level network capture
// — every XHR/fetch the page issues during render is persisted, not just
// the final document. When the tool is wired with a capture sink, those
// requests land in query_records under source="web-fetch-browser" with no
// extra plumbing.
func (w *webFetchTool) executeBrowser(ctx context.Context, url string, args map[string]any) (Result, error) {
	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}
	waitMS := 1500
	if v, ok := args["wait_ms"].(float64); ok && int(v) > 0 {
		waitMS = int(v)
	}
	waitSel, _ := args["wait_selector"].(string)

	cfg := spitolas.ProbeConfig{
		URL:          url,
		WaitSelector: waitSel,
		WaitExtra:    time.Duration(waitMS) * time.Millisecond,
		NavTimeout:   45 * time.Second,
		CollectHTML:  true,
	}
	// When wired, pump every XHR/fetch the browser issues straight into
	// the project DB. Source is distinct from browser_probe so the agent
	// can tell which tool surfaced the traffic.
	if w.captureSink != nil && w.captureProject != "" {
		cfg.CaptureSink = w.captureSink
		cfg.CaptureProjectUUID = w.captureProject
		cfg.CaptureSource = "web-fetch-browser"
	}

	res, err := spitolas.ProbeURL(ctx, cfg)
	if err != nil {
		// Render the partial result if spitolas got us a final URL despite
		// the error — useful when navigation fails late (e.g. JS errors).
		msg := fmt.Sprintf("browser fetch failed: %v", err)
		if res != nil && res.FinalURL != "" {
			msg += fmt.Sprintf(" (final_url=%s)", res.FinalURL)
		}
		return Result{Content: msg, IsError: true}, nil
	}

	html := res.HTML
	truncated := false
	if int64(len(html)) > maxBytes {
		html = html[:maxBytes] + fmt.Sprintf("\n\n[truncated at %d bytes]", maxBytes)
		truncated = true
	}

	var out strings.Builder
	fmt.Fprintf(&out, "URL: %s\nTitle: %s\n\n", res.FinalURL, res.Title)
	out.WriteString(html)

	details := map[string]any{
		"mode":      "browser",
		"url":       res.FinalURL,
		"title":     res.Title,
		"bytes":     len(res.HTML),
		"truncated": truncated,
	}
	if len(res.Dialogs) > 0 {
		details["dialogs"] = len(res.Dialogs)
	}
	// CDP capture writes records asynchronously and there can be many per
	// page (one per XHR). We don't have a single "the" record_uuid to
	// surface like HTTP mode does — the agent should call query_records
	// with host=<final_url's host> to enumerate what was captured.
	if cfg.CaptureSink != nil {
		details["capture"] = "records persisted under source='web-fetch-browser'; use query_records to enumerate"
	}

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}
