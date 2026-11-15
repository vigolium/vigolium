package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/requestinput"
	"github.com/vigolium/vigolium/pkg/requestscheme"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// maxScanRequestDuration caps how long a single /api/scan-request or
// /api/scan-url scan can run before the executor context is cancelled.
// Without this cap, a module that hangs on a slow upstream (or spawns a
// goroutine that never returns) leaves the executor's drain loop spinning
// forever with inFlight>0, and the scan goroutine never exits — tying up
// resources and masking the underlying hang.
const maxScanRequestDuration = 15 * time.Minute

// scanSessionLog bundles a runtime.log file with a mutex for concurrent-safe
// writes. Mirrors internal/runner.Runner.writeSessionLog so server-initiated
// scans produce the same per-session artifact operators expect.
type scanSessionLog struct {
	mu sync.Mutex
	f  *os.File
}

// openScanSessionLog creates {sessions_dir}/{scanID}/runtime.log. Returns nil
// if directory creation or file open fails — the scan keeps running, just
// without the persistent log (the stderr stream is unaffected).
func openScanSessionLog(scanID string, settings *config.Settings) *scanSessionLog {
	var sessionsDir string
	if settings != nil {
		sessionsDir = settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	} else {
		sessionsDir = config.ExpandPath("~/.vigolium/native-sessions/")
	}
	dir := filepath.Join(sessionsDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		zap.L().Warn("failed to create scan session dir",
			zap.String("scan_uuid", scanID), zap.String("dir", dir), zap.Error(err))
		return nil
	}
	path := filepath.Join(dir, config.RuntimeLogFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		zap.L().Warn("failed to open runtime log",
			zap.String("scan_uuid", scanID), zap.String("path", path), zap.Error(err))
		return nil
	}
	return &scanSessionLog{f: f}
}

// write appends a timestamped, ANSI-stripped copy of line to the log file.
// Safe for concurrent use; no-op when sl or sl.f is nil.
func (sl *scanSessionLog) write(line string) {
	if sl == nil || sl.f == nil {
		return
	}
	plain := terminal.StripANSI(line)
	if !strings.HasSuffix(plain, "\n") {
		plain += "\n"
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	_, _ = sl.f.WriteString("[" + time.Now().Format("15:04:05") + "] " + plain)
}

// close flushes and closes the underlying log file.
func (sl *scanSessionLog) close() {
	if sl == nil || sl.f == nil {
		return
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	_ = sl.f.Close()
	sl.f = nil
}

// emitScanLine writes line to stderr and mirrors it into the session log.
// Used for the scan lifecycle lines (Scanning header, traffic, finding,
// status, completion) the user expects from server-initiated scans.
func emitScanLine(sl *scanSessionLog, line string) {
	fmt.Fprint(os.Stderr, line)
	sl.write(line)
}

// colorModuleType returns the module-type string colored to distinguish
// active vs passive findings in streaming output. Matches the server
// console color scheme: active=BoldOrange (warm), passive=BoldBlue (cool).
func colorModuleType(t string) string {
	switch strings.ToLower(t) {
	case "active":
		return terminal.BoldOrange(t)
	case "passive":
		return terminal.BoldBlue(t)
	default:
		return t
	}
}

// scanShortID returns the first 8 chars of the scan UUID (with any leading
// "scan-" stripped) for compact display in per-line prefixes.
func scanShortID(scanID string) string {
	id := strings.TrimPrefix(scanID, "scan-")
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}

// severityBracket renders the `[<symbol> <severity>]` field used by the
// per-finding line. The symbol (e.g. ✖ for critical, ❖ for high) and the
// text share a single color matching the severity palette — warm oranges
// for high/active, magenta for critical, yellow for medium, green for low,
// cyan for suspect, blue for info.
func severityBracket(sev severity.Severity) string {
	sevStr := sev.String()
	inner := ""
	switch sev {
	case severity.Critical:
		inner = terminal.BoldMagenta("✖ " + sevStr)
	case severity.High:
		inner = terminal.BoldOrange("❖ " + sevStr)
	case severity.Medium:
		inner = terminal.BoldYellow("◆ " + sevStr)
	case severity.Low:
		inner = terminal.BoldGreen("• " + sevStr)
	case severity.Suspect:
		inner = terminal.BoldCyan("? " + sevStr)
	case severity.Info:
		inner = terminal.BoldBlue("◇ " + sevStr)
	default:
		inner = sevStr
	}
	return "[" + inner + "]"
}

// formatFindingLine renders a single finding as one line of console output.
// Format:
//
//	❯ scan-<uuid8> │ [type] [module-id] [<sym> severity] METHOD URL[ [evidence]]
//
// METHOD is elided when the result has no request attached (typical for
// passive findings). The URL is truncated to fit the terminal width and the
// optional trailing evidence bracket comes from result.ExtractedResults
// (e.g. baseline/attack comparison, fuzzing payload).
func formatFindingLine(scanID string, result *output.ResultEvent) string {
	prefix := terminal.Muted(terminal.SymbolChevron + " scan-" + scanShortID(scanID) + " " + terminal.SymbolPipe)

	typeStr := result.ModuleType
	if typeStr == "" {
		typeStr = "?"
	}

	// Method (best-effort — passive findings may lack result.Request)
	method := ""
	if result.Request != "" {
		if m, err := httpmsg.GetMethod([]byte(result.Request)); err == nil {
			method = m
		}
	}

	// Primary URL — prefer the matched location, fall back to the target.
	urlStr := result.Matched
	if urlStr == "" {
		urlStr = result.URL
	}

	// Evidence suffix built from ExtractedResults (comma-separated inside
	// a single bracket, matching format_screen.go's canonical form).
	suffix := ""
	if len(result.ExtractedResults) > 0 {
		suffix = " [" + output.EscapeOneLine(strings.Join(result.ExtractedResults, ",")) + "]"
	}
	if result.IsFuzzingResult && result.FuzzingParameter != "" {
		suffix += " [" + result.FuzzingParameter + "]"
	}

	// Visible-char accounting so the URL gets the remaining terminal width.
	// Hand-count the non-URL portion (ANSI escapes excluded).
	visibleLen := len("❯ scan-xxxxxxxx │ ") +
		len("[") + len(typeStr) + len("] ") +
		len("[") + len(result.ModuleID) + len("] ") +
		len("[") + len("✖ ") + len(result.Info.Severity.String()) + len("] ")
	if method != "" {
		visibleLen += len(method) + 1 // trailing space
	}

	if termWidth := terminal.TerminalWidth(); termWidth > 0 {
		remaining := termWidth - visibleLen - len(suffix)
		if remaining > 20 && len(urlStr) > remaining {
			urlStr = terminal.Truncate(urlStr, remaining)
		}
	}

	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(" [")
	b.WriteString(colorModuleType(typeStr))
	b.WriteString("] [")
	b.WriteString(terminal.White(result.ModuleID))
	b.WriteString("] ")
	b.WriteString(severityBracket(result.Info.Severity))
	if method != "" {
		b.WriteString(" ")
		b.WriteString(terminal.Bold(method))
	}
	b.WriteString(" ")
	b.WriteString(urlStr)
	if suffix != "" {
		b.WriteString(terminal.HiCyan(suffix))
	}
	b.WriteString("\n")
	return b.String()
}

// HandleScanURL handles POST /api/scan-url — scans a single URL asynchronously.
func (h *Handlers) HandleScanURL(c fiber.Ctx) error {
	var req ScanURLRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
	}

	if req.URL == "" {
		return respondError(c, fiber.StatusBadRequest, ErrMissingURL)
	}

	// Validate URL
	if _, err := url.ParseRequestURI(req.URL); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid URL: %w", err))
	}

	// Default method to GET
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// Build raw HTTP request from URL/method/body/headers
	rr, err := buildRequestFromParams(req.URL, method, req.Body, req.Headers)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to build request: %w", err))
	}

	// Parse module IDs
	var moduleIDs []string
	if req.Modules != "" {
		for _, m := range strings.Split(req.Modules, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				moduleIDs = append(moduleIDs, m)
			}
		}
	}

	settings, err := h.scanSettings(c)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, err)
	}

	// Scope admission, synchronously: a target the configured scope refuses is
	// a 422 now rather than a 202 for a scan that silently does nothing.
	if refused := refuseOutOfScope(c, settings, req.URL); refused != nil {
		return refused()
	}

	scanID := uuid.New().String()

	projectUUID := getProjectUUID(c)

	// Create scan record if database is available
	if h.repo != nil {
		ctx := context.Background()
		scan := database.NewSingleRequestScan(scanID, projectUUID, database.ScanNameScanURL, req.URL, req.Modules, "api")
		if err := h.repo.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}

	if !h.tryStartNativeScan(func() {
		h.runBackgroundURLScan(scanID, projectUUID, req.URL, rr, moduleIDs, req.NoPassive, probeStealth(settings))
	}) {
		if h.repo != nil {
			_ = h.repo.CompleteScan(context.Background(), scanID, "rejected: too many concurrent scans")
		}
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "too many concurrent scans; retry shortly")
	}

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID: projectUUID,
		ScanUUID:    scanID,
		Status:      "running",
		Message:     fmt.Sprintf("scan-url started for %s", req.URL),
	})
}

// HandleScanRequest handles POST /api/scan-request — scans a raw HTTP request asynchronously.
func (h *Handlers) HandleScanRequest(c fiber.Ctx) error {
	return h.handleScanRequest(c, h.tryStartNativeScan)
}

// handleScanRequest is HandleScanRequest with the background launcher
// injected (tests answer the request without running a scan).
func (h *Handlers) handleScanRequest(c fiber.Ctx, start func(func()) bool) error {
	var req ScanRequestRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
	}

	reqB64 := req.ReqBase64()
	if reqB64 == "" {
		return respondError(c, fiber.StatusBadRequest, ErrMissingRawRequest)
	}

	// Base64-decode the raw request
	rawBytes, err := base64.StdEncoding.DecodeString(reqB64)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to decode raw_request: %w", err))
	}

	// Parsed like `vigolium scan-request` parses it (requestinput): scope
	// admission on the inferred target first, so a refused target is never
	// contacted by the scheme probe, and again over the URL a probe moved it to.
	var (
		settings       *config.Settings
		settingsLoaded bool
		settingsErr    error
		refused        func() error
	)
	admit := func(target string) error {
		if !settingsLoaded {
			settingsLoaded = true
			settings, settingsErr = h.scanSettings(c)
		}
		if settingsErr != nil {
			return settingsErr
		}
		if refused = refuseOutOfScope(c, settings, target); refused != nil {
			return errScanTargetRefused
		}
		return nil
	}
	parsed, err := requestinput.Parse(c.Context(), string(rawBytes), requestinput.Options{
		Target:   req.TargetURL,
		NoProbe:  req.NoSchemeProbe,
		Resolver: scanRequestSchemeResolver,
		Admit:    admit,
	})
	switch {
	case refused != nil:
		return refused()
	case settingsErr != nil:
		return respondError(c, fiber.StatusInternalServerError, settingsErr)
	case errors.Is(err, requestinput.ErrEmpty):
		return respondError(c, fiber.StatusBadRequest, ErrMissingRawRequest)
	case err != nil:
		return respondErrorMsg(c, fiber.StatusBadRequest, ErrInvalidRawRequest.Error()+": "+err.Error())
	}
	rr := parsed.Request

	// Attach paired response if provided (Burp-style request+response)
	if respB64 := req.RespBase64(); respB64 != "" {
		rawRespBytes, decErr := base64.StdEncoding.DecodeString(respB64)
		if decErr != nil {
			return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to decode http_response_base64: %w", decErr))
		}
		if resp := httpmsg.NewHttpResponse(rawRespBytes); resp != nil {
			rr = rr.WithResponse(resp)
		}
	}

	// Parse module IDs
	var moduleIDs []string
	if req.Modules != "" {
		for _, m := range strings.Split(req.Modules, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				moduleIDs = append(moduleIDs, m)
			}
		}
	}

	target := rr.Target()

	scanID := uuid.New().String()
	projectUUID := getProjectUUID(c)

	// Create scan record if database is available
	if h.repo != nil {
		ctx := context.Background()
		scan := database.NewSingleRequestScan(scanID, projectUUID, database.ScanNameScanRequest, target, req.Modules, "api")
		if err := h.repo.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}

	if !start(func() {
		h.runBackgroundURLScan(scanID, projectUUID, target, rr, moduleIDs, req.NoPassive, probeStealth(settings))
	}) {
		if h.repo != nil {
			_ = h.repo.CompleteScan(context.Background(), scanID, "rejected: too many concurrent scans")
		}
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "too many concurrent scans; retry shortly")
	}

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:  projectUUID,
		ScanUUID:     scanID,
		Status:       "running",
		Message:      fmt.Sprintf("scan-request started for %s", target),
		Target:       target,
		SchemeSource: parsed.SchemeSource,
	})
}

// scanSettings resolves the request project's settings (the server's, plus
// X-Project-UUID's overlay) once per scan request. nil, nil when the server
// has no settings to judge by.
func (h *Handlers) scanSettings(c fiber.Ctx) (*config.Settings, error) {
	if h.settings == nil {
		return nil, nil
	}
	return h.settingsForProject(getProjectUUID(c))
}

// probeStealth is the project's spidering.stealth ("" = auto, also when there
// are no settings).
func probeStealth(settings *config.Settings) string {
	if settings == nil {
		return ""
	}
	return settings.Spidering.Stealth
}

// errScanTargetRefused ends requestinput.Parse when scope refuses the target;
// the handler answers with refuseOutOfScope's responder.
var errScanTargetRefused = errors.New("scan target refused by scope")

// scanRequestSchemeResolver replaces the scheme probe behind
// POST /api/scan-request (tests); nil is portsweep.ResolveScheme.
var scanRequestSchemeResolver requestscheme.Resolver

// refuseOutOfScope admits target against the request project's scope
// (scanSettings), the verdict the CLI direct path and the runner enforce. When
// scope refuses it, it returns the responder for 422 with details
// "no_targets_in_scope" (the apicontract code) and the rule in the message;
// nothing is created or sent. nil means admitted, or no settings to judge by.
func refuseOutOfScope(c fiber.Ctx, settings *config.Settings, target string) func() error {
	if settings == nil {
		return nil
	}
	adm := runner.AdmitTargets(settings.Scope, []string{target})
	if !adm.NoneAdmitted() {
		return nil
	}
	return func() error {
		// details keeps carrying the code for clients written before error_code.
		return respondErrorCode(c, fiber.StatusUnprocessableEntity, apicontract.CodeNoTargetsInScope,
			fmt.Sprintf("target rejected by scope: %s; nothing was scanned (fix the scope config)",
				runner.DescribeRejected(adm.Rejected, 0)), string(apicontract.CodeNoTargetsInScope))
	}
}

// buildRequestFromParams constructs an HttpRequestResponse from URL, method, body, and headers.
// This mirrors the CLI buildRequestFromFlags but takes a map of headers instead of a slice.
func buildRequestFromParams(target, method, body string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	method = strings.ToUpper(method)

	// Simple case: GET with no body or custom headers
	if method == "GET" && body == "" && len(headers) == 0 {
		return httpmsg.GetRawRequestFromURL(target)
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	path := u.RequestURI()
	host := u.Host

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	for k, v := range headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}

	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return httpmsg.ParseRawRequestWithURL(sb.String(), target)
}

// runBackgroundURLScan runs a single-record scan in a background goroutine
// and mirrors the CLI `vigolium scan` / `vigolium scan-request` console
// output: the `◆ Scanning` header, the baseline traffic line, streamed
// `◆ finding` lines, periodic `◆ [status]` lines, and a closing
// `✔ Native scan completed` line. Every line is also appended (ANSI-stripped,
// timestamped) to {sessions_dir}/{scanID}/runtime.log.
// tryStartNativeScan reserves an admission slot for a url/request background scan
// and launches fn on a tracked goroutine (so Close can wait for it and so a burst
// of requests can't spawn unbounded goroutines). Returns false when the
// concurrency limit is reached — the caller should reject with 503. The slot is
// released and the WaitGroup decremented when fn returns.
func (h *Handlers) tryStartNativeScan(fn func()) bool {
	if h.nativeScanSem == nil { // handler built without NewHandlers (tests): don't bound
		go fn()
		return true
	}
	select {
	case h.nativeScanSem <- struct{}{}:
	default:
		return false
	}
	h.nativeScanWG.Add(1)
	go func() {
		defer h.nativeScanWG.Done()
		defer func() { <-h.nativeScanSem }()
		fn()
	}()
	return true
}

// nativeScanContext returns the context url/request scans run under: derived from
// the server-lifetime runCtx so Close (via runCancel) stops them, falling back to
// Background for handlers built without a server context.
func (h *Handlers) nativeScanContext() (context.Context, context.CancelFunc) {
	parent := h.runCtx
	if parent == nil {
		parent = context.Background()
	}
	return context.WithCancel(parent)
}

func (h *Handlers) runBackgroundURLScan(scanID, projectUUID, target string, rr *httpmsg.HttpRequestResponse, moduleIDs []string, noPassive bool, stealth string) {
	// Any panic escaping this goroutine (nil deref in a module, panic inside
	// a goroutine spawned by a module, etc.) would otherwise take the entire
	// server process down. Recover here, log the stack, and mark the scan as
	// failed so /api/scan-request can keep serving requests.
	defer func() {
		if r := recover(); r != nil {
			stack := make([]byte, 8192)
			n := goruntime.Stack(stack, false)
			zap.L().Error("Background URL scan panicked",
				zap.String("scan_uuid", scanID),
				zap.Any("panic", r),
				zap.ByteString("stack", stack[:n]))
			// A panic is a failed assessment. Reachability is unknown here, so
			// the verdict claims none (reached=true): partial, stop reason error.
			panicErr := fmt.Errorf("panic: %v", r)
			h.completeSingleRequestScan(scanID, panicErr,
				runner.DirectScanCompletion(core.ExecutionReport{}, true, false, panicErr, database.TargetTally{}))
		}
	}()

	start := time.Now()
	zap.L().Info("Background URL scan started",
		zap.String("scan_uuid", scanID),
		zap.String("target", rr.Target()))

	// Module browser confirmations follow the server's --proxy and the
	// project's spidering.stealth, as on the CLI paths.
	defer spitolas.SetProbeDefaults(h.serverProxyURL(), stealth)()

	sl := openScanSessionLog(scanID, h.settings)
	defer sl.close()

	active, passive := getFilteredModulesServer(moduleIDs, noPassive)
	src := source.NewSingleSource(rr, moduleIDs)

	method := rr.Request().Method()

	// Mirror pkg/cli/scan_url.go:371-376 — the operator sees the same "about
	// to scan" line they'd see running the CLI directly.
	emitScanLine(sl, fmt.Sprintf("  %s Scanning %s %s with %s active + %s passive modules\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(method),
		terminal.Cyan(target),
		terminal.Orange(fmt.Sprintf("%d", len(active))),
		terminal.Orange(fmt.Sprintf("%d", len(passive)))))

	// Collect findings for the summary count at the end. The OnResult
	// callback below streams each one to the console + runtime.log as it
	// arrives.
	var mu sync.Mutex
	var findings []*output.ResultEvent

	// The executor's status ticker runs in its own goroutine and can fire
	// one last tick after Execute() returns. Gate status/finding output on
	// this flag so the [status] line never follows the completion line.
	var scanDone atomic.Bool

	// Forward-declared so OnStatus can read the executor's considered-module
	// counter (see pkg/cli/scan_url.go:416) — this is what lets the X/Y in
	// the status line actually reach parity.
	var scanExecutor *core.Executor

	// All per-line events (traffic, finding, status) share this prefix so
	// operators can tell every line belongs to the same scan at a glance.
	// Format: `❯ scan-<uuid8> │` (muted).
	scanPrefix := terminal.Muted(terminal.SymbolChevron + " scan-" + scanShortID(scanID) + " " + terminal.SymbolPipe)

	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	// Each concurrent lightweight scan gets its own behavioral requester state
	// (response observer, request clusterer, cookie jar) layered over the shared
	// transport, so two scans running at once on this server don't overwrite each
	// other's 5xx corroboration observer or coalesce identical requests across scans.
	scanRequester := h.httpRequester
	if cloned, err := h.httpRequester.CloneForScan(); err == nil {
		scanRequester = cloned
	} else {
		zap.L().Warn("failed to clone per-scan requester; falling back to shared requester", zap.Error(err))
	}

	executorCfg := core.ExecutorConfig{
		Workers:              concurrency,
		Services:             h.services,
		HTTPRequester:        scanRequester,
		Repository:           h.repo,
		ScanUUID:             scanID,
		ProjectUUID:          projectUUID,
		MaxFindingsPerModule: 50,
		// Hard upper bound: a module that hangs forever must not be able to
		// keep this goroutine alive indefinitely. The executor cancels its
		// context when MaxDuration elapses and Execute() returns.
		MaxDuration: maxScanRequestDuration,
		// Fire an early status tick so single-request scans show progress
		// well before the regular cadence would.
		StatusInterval:      2 * time.Minute,
		FirstStatusInterval: 10 * time.Second,
		OnTraffic: func(reqMethod, reqURL string, statusCode int, _ string) {
			emitScanLine(sl, fmt.Sprintf("%s [%s] %s %s\n",
				scanPrefix,
				terminal.Orange(fmt.Sprintf("%d", statusCode)),
				terminal.BoldCyan(reqMethod),
				terminal.Gray(reqURL)))
		},
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
			if result == nil || scanDone.Load() {
				return
			}
			emitScanLine(sl, formatFindingLine(scanID, result))
		},
		OnStatus: func(processed, total, findingsCount, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) {
			if scanDone.Load() {
				return
			}
			totalModules := activeCount + passiveCount
			scannedModules := distinctModules
			if scanExecutor != nil {
				scannedModules = scanExecutor.ConsideredModuleCount()
			}
			// `Records: P` is the executor's processed count; for
			// scan-request this moves 0 → 1 but the field is kept for
			// parity with scan-on-receive and multi-record endpoints.
			// `Modules: X/Y (A active, P passive[, T timed out])` shows
			// considered/registered with the active/passive split (and any
			// timed-out skips) so operators can see at a glance what ran.
			emitScanLine(sl, fmt.Sprintf("%s %s Records: %s | Findings: %s | Modules: %s | Runtime: %s\n",
				scanPrefix,
				terminal.BoldCyan("[status]"),
				terminal.HiBlue(fmt.Sprintf("%d", processed)),
				terminal.Orange(fmt.Sprintf("%d", findingsCount)),
				terminal.Yellow(terminal.FormatModuleProgress(scannedModules, totalModules, activeCount, passiveCount, timedOut)),
				terminal.Gray(elapsed.Round(time.Second).String())))
		},
	}

	scanExecutor = core.NewExecutor(executorCfg, src, active, passive)

	// Derive from the server-lifetime context so a graceful shutdown cancels this
	// scan instead of leaving it to run (up to MaxDuration) against a context
	// nothing can cancel.
	ctx, cancel := h.nativeScanContext()
	defer cancel()
	var errMsg string
	_, execErr := scanExecutor.Execute(ctx)
	scanDone.Store(true)
	if execErr != nil {
		errMsg = execErr.Error()
		zap.L().Error("Background URL scan failed",
			zap.String("scan_uuid", scanID), zap.Error(execErr))
		emitScanLine(sl, fmt.Sprintf("  %s %s %s\n",
			terminal.ErrorSymbol(),
			terminal.BoldRed("Scan error:"),
			terminal.Red(errMsg)))
	}

	elapsed := time.Since(start)
	zap.L().Info("Background URL scan completed",
		zap.String("scan_uuid", scanID),
		zap.Int("findings", len(findings)),
		zap.Duration("elapsed", elapsed))

	// Mirror pkg/cli/scan_url.go:652-657 — same ✔ symbol, same
	// "(METHOD N modules)" parenthetical, leading \n for blank-line spacer.
	modulesRun := len(active) + len(passive)
	emitScanLine(sl, fmt.Sprintf("\n%s Native scan completed: %s (%s %s) in %s\n",
		terminal.SuccessSymbol(),
		terminal.Cyan(target),
		method,
		terminal.Gray(fmt.Sprintf("%d modules", modulesRun)),
		terminal.BoldMagenta(elapsed.Round(time.Second).String())))

	// Complete the scan row with the coverage verdict the CLI direct path
	// computes for the same run: cancelled (server shutdown), unreachable target
	// and executor shortfalls are recorded instead of a bare "completed".
	rep := scanExecutor.Report()
	completion := runner.DirectScanCompletion(rep, rep.Responded > 0, ctx.Err() != nil, execErr,
		runner.DirectTargetTally(target, rep, scanExecutor.BaselineFailures()))
	h.completeSingleRequestScan(scanID, execErr, completion)
}

// completeSingleRequestScan finalizes a scan-url / scan-request row on a
// detached, bounded context: the scan's own context is already cancelled on a
// server shutdown, and finalizing on it would leave the row "running" forever.
func (h *Handlers) completeSingleRequestScan(scanID string, execErr error, c database.ScanCompletion) {
	if h.repo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.repo.CompleteScanWithOutcome(ctx, scanID, runner.DirectScanErrorMessage(execErr, c), c); err != nil {
		zap.L().Error("Failed to complete scan record",
			zap.String("scan_uuid", scanID), zap.Error(err))
	}
}

// getFilteredModulesServer returns active and passive modules based on module IDs and noPassive flag.
func getFilteredModulesServer(moduleIDs []string, noPassive bool) ([]modules.ActiveModule, []modules.PassiveModule) {
	var active []modules.ActiveModule
	var passive []modules.PassiveModule

	// Resolve fuzzy patterns to exact IDs
	resolved := modules.ResolveModulePatterns(moduleIDs)
	isAll := len(resolved) == 0 || (len(resolved) == 1 && resolved[0] == "all")

	if !isAll {
		active = modules.GetActiveModulesByIDs(resolved)
		if !noPassive {
			passive = modules.GetPassiveModulesByIDs(resolved)
		}
	} else {
		active = modules.GetActiveModules()
		if !noPassive {
			passive = modules.GetPassiveModules()
		}
	}

	return active, passive
}
