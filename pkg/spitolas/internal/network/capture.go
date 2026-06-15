package network

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

const (
	pendingTimeout  = 15 * time.Second // Timeout for pending requests (reduced from 30s)
	cleanupInterval = 5 * time.Second  // Cleanup check interval (reduced from 10s)
)

// authHeaders defines headers included in deduplication hash.
// Only authentication-related headers affect request uniqueness.
// Cookie is excluded as it changes frequently and adds noise.
var authHeaders = map[string]struct{}{
	"authorization":   {},
	"x-auth-token":    {},
	"x-api-key":       {},
	"x-access-token":  {},
	"x-csrf-token":    {},
	"x-xsrf-token":    {},
	"x-session-id":    {},
	"x-session-token": {},
}

// Capture handles HTTP traffic capture using Chrome DevTools Protocol.
// Uses browser-level event subscription to capture traffic from ALL pages.
type Capture struct {
	mu                     sync.Mutex
	writer                 Writer
	pending                map[proto.NetworkRequestID]*pendingEntry
	logged                 map[string]struct{} // Track logged entries by hash to prevent stderr duplicates
	seenHashes             map[string]bool     // Track written hashes to prevent file duplicates
	duplicateCount         int                 // Count skipped duplicates
	writtenCount           int                 // Count successfully written entries
	stopped                bool
	browser                *rod.Browser // Browser reference for fetching response bodies
	noColor                bool         // Disable colored output
	silent                 bool         // Disable stderr output
	includeResponseBody    bool         // Include response body in output
	includeResponseHeaders bool         // Include response headers in output
	// targetHost is the hostname used by the cross-origin stderr-log filter.
	// It starts as the input URL's host but is re-pointed via SetTargetHost when
	// the crawler adopts an off-host redirect target into scope, so the adopted
	// host's traffic is logged instead of being suppressed as cross-origin.
	// Atomic because it is read from the capture goroutines while the crawler
	// may update it during initial navigation.
	targetHost atomic.Pointer[string]
	phaseTag   string // Phase label for console log prefix (e.g. "spider")
	verbose    bool   // Show all traffic including static files
}

// pendingEntry tracks an in-flight request waiting for response.
type pendingEntry struct {
	entry     *TrafficEntry
	startTime time.Time
	sessionID proto.TargetSessionID // Track which page this request came from
}

// New creates a new traffic capture instance with the given Writer.
// The caller is responsible for creating the appropriate Writer (e.g. RepositoryWriter).
func New(writer Writer, noColor, silent, verbose, includeResponseBody, includeResponseHeaders bool, targetHost, phaseTag string) *Capture {
	c := &Capture{
		writer:                 writer,
		pending:                make(map[proto.NetworkRequestID]*pendingEntry),
		logged:                 make(map[string]struct{}),
		seenHashes:             make(map[string]bool),
		noColor:                noColor,
		silent:                 silent,
		verbose:                verbose,
		includeResponseBody:    includeResponseBody,
		includeResponseHeaders: includeResponseHeaders,
		phaseTag:               phaseTag,
	}
	c.SetTargetHost(targetHost)
	return c
}

// SetTargetHost re-points the cross-origin stderr-log filter at host. The
// crawler calls this after adopting an off-host redirect target into scope so
// the adopted host's traffic is logged rather than suppressed as cross-origin
// (records are written regardless of this filter). Safe to call concurrently
// with the capture goroutines.
func (c *Capture) SetTargetHost(host string) {
	c.targetHost.Store(&host)
}

// targetHostValue returns the current cross-origin filter host (empty if unset).
func (c *Capture) targetHostValue() string {
	if p := c.targetHost.Load(); p != nil {
		return *p
	}
	return ""
}

// Start begins capturing network traffic at the browser level.
// This captures traffic from ALL pages/tabs in the browser.
// The goroutine automatically exits when browser closes.
func (c *Capture) Start(browser *rod.Browser) error {
	c.browser = browser

	zap.L().Debug("Starting network capture",
		zap.Bool("include_body", c.includeResponseBody),
		zap.Bool("include_headers", c.includeResponseHeaders))

	go c.subscribeEvents(browser)
	go c.cleanupLoop()

	zap.L().Debug("Network capture event listeners started")
	return nil
}

// subscribeEvents subscribes to network events at browser level.
// Browser.EachEvent auto-enables Network domain for all pages.
// Callbacks receive sessionID to identify which page the event came from.
// The event loop exits automatically when browser closes.
func (c *Capture) subscribeEvents(browser *rod.Browser) {
	// Browser.EachEvent catches events from ALL pages
	// Callbacks can receive optional sessionID parameter
	// Return true to stop the event loop
	wait := browser.EachEvent(
		func(e *proto.NetworkRequestWillBeSent, sessionID proto.TargetSessionID) bool {
			c.onRequestWillBeSent(e, sessionID)
			return c.isStopped()
		},
		func(e *proto.NetworkResponseReceived, sessionID proto.TargetSessionID) bool {
			c.onResponseReceived(e, sessionID)
			return c.isStopped()
		},
		func(e *proto.NetworkLoadingFinished, sessionID proto.TargetSessionID) bool {
			c.onLoadingFinished(e, sessionID)
			return c.isStopped()
		},
		func(e *proto.NetworkLoadingFailed, sessionID proto.TargetSessionID) bool {
			c.onLoadingFailed(e)
			return c.isStopped()
		},
		// Service-worker targets run in their own CDP session, so their traffic —
		// e.g. a PWA service worker's install-time precache — is invisible to the
		// page-level Network domain. When Chrome auto-attaches one (see
		// enableServiceWorkerCapture below), enable Network on its session so those
		// requests flow through the same Network callbacks above and are captured
		// like page traffic.
		func(e *proto.TargetAttachedToTarget) bool {
			c.onWorkerAttached(browser, e)
			return c.isStopped()
		},
	)
	// Register the callbacks above FIRST, then turn on worker auto-attach, so no
	// attach event can race ahead of the handler.
	c.enableServiceWorkerCapture(browser)
	wait() // Blocks until callback returns true or browser closes
}

// enableServiceWorkerCapture turns on CDP auto-attach for service-worker targets
// so the browser captures their network traffic natively — the browser-native
// counterpart to the in-page service-worker priming. A service worker runs in a
// separate target/session, so the page-level Network domain never sees the
// requests it makes (its precache fetches); attaching to the worker's own session
// and enabling Network there does. Notes:
//   - Flatten delivers the worker's events over the same connection EachEvent
//     already listens on, tagged with the worker's sessionID — so the existing
//     Network callbacks handle them unchanged.
//   - The filter is restricted to service workers, so rod's page/tab management
//     (which uses target discovery, not browser-level auto-attach) is untouched.
//   - WaitForDebuggerOnStart pauses each worker until onWorkerAttached has enabled
//     Network on it, so its very first precache requests are not missed.
//
// Best-effort: a setup error is logged at debug and the crawl continues (the
// in-page priming still follows declared assets).
func (c *Capture) enableServiceWorkerCapture(browser *rod.Browser) {
	if err := serviceWorkerAutoAttachConfig().Call(browser); err != nil {
		zap.L().Debug("Service-worker network capture: auto-attach setup failed", zap.Error(err))
		return
	}
	zap.L().Debug("Service-worker network capture enabled (auto-attach)")
}

// serviceWorkerAutoAttachConfig is the CDP auto-attach request that drives
// service-worker network capture. Extracted as a pure value so its invariants can
// be unit-tested without a browser. It MUST stay scoped to service workers only:
// a broader filter (pages/tabs) would have rod's own target management and this
// auto-attach both managing the same sessions, risking stuck/paused sessions and
// browsers that don't get reaped. The trailing {Exclude:true} entry is the
// catch-all that drops every non-service-worker target.
func serviceWorkerAutoAttachConfig() proto.TargetSetAutoAttach {
	return proto.TargetSetAutoAttach{
		AutoAttach:             true,
		WaitForDebuggerOnStart: true,
		Flatten:                true,
		Filter: proto.TargetTargetFilter{
			{Type: string(proto.TargetTargetInfoTypeServiceWorker)},
			{Exclude: true}, // service workers only; exclude pages/tabs/other workers
		},
	}
}

// onWorkerAttached enables the Network domain on a freshly auto-attached
// service-worker session and releases the worker from its start-up pause, so the
// worker's fetches (its precache) are recorded. The CDP round-trips run on a
// goroutine so they never block the shared event loop; Network is enabled before
// the worker is resumed so no early request is missed. Best-effort — any error is
// logged at debug and the crawl continues.
func (c *Capture) onWorkerAttached(browser *rod.Browser, e *proto.TargetAttachedToTarget) {
	if browser == nil || e == nil || e.TargetInfo == nil {
		return
	}
	sid := e.SessionID
	url := e.TargetInfo.URL
	wtype := string(e.TargetInfo.Type)
	waiting := e.WaitingForDebugger
	go func() {
		browser.EnableDomain(sid, proto.NetworkEnable{})
		if waiting {
			req := proto.RuntimeRunIfWaitingForDebugger{}
			if _, err := browser.Call(browser.GetContext(), string(sid), req.ProtoReq(), req); err != nil {
				zap.L().Debug("Service-worker capture: runIfWaitingForDebugger failed",
					zap.String("url", url), zap.Error(err))
			}
		}
		zap.L().Debug("Captured service-worker target network",
			zap.String("type", wtype), zap.String("url", url))
	}()
}

// isStopped checks if capture has been stopped.
func (c *Capture) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// isSessionValid checks if a sessionID still has an active page in the browser.
// This prevents expensive CDP calls for stale/invalid sessions after navigation.
func (c *Capture) isSessionValid(sessionID proto.TargetSessionID) bool {
	if c.browser == nil {
		return false
	}
	pages, err := c.browser.Pages()
	if err != nil {
		return false
	}
	for _, page := range pages {
		if page.SessionID == sessionID {
			return true
		}
	}
	return false
}

// shouldSkipURL returns true if the URL should be ignored.
// Uses whitelist approach: only accept http:// and https:// schemes.
func shouldSkipURL(rawURL string) bool {
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		return false
	}
	return true
}

// onRequestWillBeSent handles request sent events.
func (c *Capture) onRequestWillBeSent(e *proto.NetworkRequestWillBeSent, sessionID proto.TargetSessionID) {
	// Skip internal browser URLs early (except whitelisted ones)
	if shouldSkipURL(e.Request.URL) {
		return
	}

	c.mu.Lock()

	// A 3xx redirect reuses the same RequestID: CDP fires another requestWillBeSent
	// for the redirect TARGET, carrying the previous hop's response in
	// RedirectResponse. Without handling it, the pending entry for that hop is
	// overwritten below and the intermediate URL is lost — exactly the URLs an SSO
	// chain is made of (an OAuth /oauth2/authorize, a SAML /idp/endpoint/HttpRedirect)
	// that only ever appear as a redirect. Finalize the hop with its redirect
	// response and emit it so every step of the chain is recorded.
	var redirectEntry *TrafficEntry
	if e.RedirectResponse != nil {
		if prev, ok := c.pending[e.RequestID]; ok {
			delete(c.pending, e.RequestID)
			prev.entry.Response = &ResponseData{
				Status:  e.RedirectResponse.Status,
				Headers: convertHeaders(e.RedirectResponse.Headers),
			}
			computeHTTPXFields(prev.entry)
			if !c.includeResponseBody {
				prev.entry.Response.Body = nil
			}
			if !c.includeResponseHeaders {
				prev.entry.Response.Headers = nil
			}
			redirectEntry = prev.entry
		}
	}

	headers := convertHeaders(e.Request.Headers)

	entry := &TrafficEntry{
		Timestamp:    time.Now(),
		ResourceType: string(e.Type),
		Request: RequestData{
			Method:  e.Request.Method,
			URL:     e.Request.URL,
			Headers: headers,
			Body:    []byte(e.Request.PostData),
		},
	}

	c.pending[e.RequestID] = &pendingEntry{
		entry:     entry,
		startTime: time.Now(),
		sessionID: sessionID,
	}

	c.mu.Unlock()

	// writeEntry takes the lock itself, so emit the finalized redirect hop after
	// releasing it.
	if redirectEntry != nil {
		c.writeEntry(redirectEntry)
	}

	zap.L().Debug("Network request captured",
		zap.String("method", e.Request.Method),
		zap.String("url", e.Request.URL),
		zap.String("type", string(e.Type)),
		zap.String("sessionID", string(sessionID)),
	)
}

// onResponseReceived handles response received events.
func (c *Capture) onResponseReceived(e *proto.NetworkResponseReceived, sessionID proto.TargetSessionID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pending, ok := c.pending[e.RequestID]
	if !ok {
		return
	}

	headers := convertHeaders(e.Response.Headers)

	pending.entry.Response = &ResponseData{
		Status:  e.Response.Status,
		Headers: headers,
	}

	zap.L().Debug("Network response received",
		zap.Int("status", e.Response.Status),
		zap.String("url", e.Response.URL),
		zap.String("mime_type", e.Response.MIMEType))
}

// computeHTTPXFields extracts httpx fields from response data.
// Called BEFORE potentially discarding headers/body.
// These fields are always computed regardless of includeBody/includeHeaders flags.
func computeHTTPXFields(entry *TrafficEntry) {
	if entry.Response == nil {
		return
	}

	// From headers: Content-Type and Server
	for k, v := range entry.Response.Headers {
		if strings.EqualFold(k, "Content-Type") {
			entry.ContentType = v
		}
		if strings.EqualFold(k, "Server") {
			entry.WebServer = v
		}
	}

	// From body: content_length, words, lines
	if len(entry.Response.Body) > 0 {
		entry.ContentLength = len(entry.Response.Body)
		// Only count words/lines for valid UTF-8 text
		if utf8.Valid(entry.Response.Body) {
			body := string(entry.Response.Body)
			entry.Words = len(strings.Fields(body))
			entry.Lines = strings.Count(body, "\n") + 1
		}
	}
}

// onLoadingFinished handles loading finished events.
func (c *Capture) onLoadingFinished(e *proto.NetworkLoadingFinished, sessionID proto.TargetSessionID) {
	c.mu.Lock()
	pending, ok := c.pending[e.RequestID]
	if !ok {
		c.mu.Unlock()
		return
	}
	delete(c.pending, e.RequestID)
	includeBody := c.includeResponseBody
	includeHeaders := c.includeResponseHeaders
	c.mu.Unlock()

	if pending.entry.Response != nil {
		// ALWAYS fetch body to compute httpx fields (content_length, words, lines)
		// Validate session BEFORE attempting to fetch response body
		if !c.isSessionValid(pending.sessionID) {
			zap.L().Debug("Skipping body fetch for invalid session",
				zap.String("sessionID", string(pending.sessionID)),
				zap.String("requestID", string(e.RequestID)),
				zap.String("url", pending.entry.Request.URL),
				zap.Duration("age", time.Since(pending.startTime)))
		} else {
			body, err := c.fetchResponseBody(pending.sessionID, e.RequestID)
			if err != nil {
				// Categorize error types for better debugging
				if errors.Is(err, context.DeadlineExceeded) {
					zap.L().Warn("Response body fetch timed out",
						zap.String("url", pending.entry.Request.URL),
						zap.Duration("timeout", 5*time.Second))
				} else if strings.Contains(err.Error(), "page not found") {
					zap.L().Debug("Page no longer exists for session",
						zap.String("sessionID", string(pending.sessionID)))
				} else {
					zap.L().Debug("Could not fetch body",
						zap.String("url", pending.entry.Request.URL),
						zap.Error(err))
				}
			} else {
				pending.entry.Response.Body = body
			}
		}

		// Compute httpx fields BEFORE potentially discarding data
		computeHTTPXFields(pending.entry)

		// Now apply flags to control what gets saved to parquet
		if !includeBody {
			pending.entry.Response.Body = nil
		}
		if !includeHeaders {
			pending.entry.Response.Headers = nil
		}
	}

	c.writeEntry(pending.entry)
}

// onLoadingFailed handles loading failed events.
func (c *Capture) onLoadingFailed(e *proto.NetworkLoadingFailed) {
	c.mu.Lock()
	pending, ok := c.pending[e.RequestID]
	if !ok {
		c.mu.Unlock()
		return
	}
	delete(c.pending, e.RequestID)
	c.mu.Unlock()

	pending.entry.Error = e.ErrorText

	c.writeEntry(pending.entry)
}

// fetchResponseBody fetches the response body for a completed request.
// Finds the page by sessionID and calls NetworkGetResponseBody on it with a timeout.
// CRITICAL: Uses context timeout to prevent hanging on stale/invalid sessions.
func (c *Capture) fetchResponseBody(sessionID proto.TargetSessionID, requestID proto.NetworkRequestID) ([]byte, error) {
	if c.browser == nil {
		return nil, fmt.Errorf("browser not set")
	}

	pages, err := c.browser.Pages()
	if err != nil {
		return nil, err
	}

	for _, page := range pages {
		if page.SessionID == sessionID {
			// Create page with timeout context FIRST
			// This prevents CDP call from hanging indefinitely
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// page.Context(ctx) returns NEW page instance with timeout context
			pageWithTimeout := page.Context(ctx)

			// Call() uses pageWithTimeout.GetContext() internally
			result, err := proto.NetworkGetResponseBody{
				RequestID: requestID,
			}.Call(pageWithTimeout)

			if err != nil {
				// Categorize timeout errors for better debugging
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, fmt.Errorf("timeout fetching body after 5s: %w", err)
				}
				return nil, err
			}

			if result.Base64Encoded {
				return base64.StdEncoding.DecodeString(result.Body)
			}
			return []byte(result.Body), nil
		}
	}

	return nil, fmt.Errorf("page not found for sessionID: %s", sessionID)
}

// staticContentTypes lists MIME type substrings that identify static resources.
var staticContentTypes = []string{"font", "image", "video", "audio"}

// staticExtensions lists URL path extensions for static resources suppressed from stderr.
var staticExtensions = map[string]bool{
	".css": true, ".map": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".avif": true, ".bmp": true,
	".mp4": true, ".mp3": true, ".wav": true, ".ogg": true, ".webm": true,
}

// shouldLogEntry returns true if the entry should be printed to stderr.
// Static content (304 cache revalidations, static content-types, static URL extensions)
// is always suppressed. Cross-origin requests are suppressed unless verbose mode is enabled.
func (c *Capture) shouldLogEntry(entry *TrafficEntry) bool {
	// Always suppress static content (304 cache revalidations, static content-types,
	// and static URL extensions) regardless of verbose mode.
	if entry.Response != nil && entry.Response.Status == 304 {
		if u, err := url.Parse(entry.Request.URL); err == nil {
			path := u.Path
			if dot := strings.LastIndex(path, "."); dot != -1 {
				if staticExtensions[strings.ToLower(path[dot:])] {
					return false
				}
			}
		}
	}

	// Check content-type for static resources
	if entry.Response != nil {
		ct := ""
		if v, ok := entry.Response.Headers["content-type"]; ok {
			ct = strings.ToLower(v)
		} else if v, ok := entry.Response.Headers["Content-Type"]; ok {
			ct = strings.ToLower(v)
		}
		for _, s := range staticContentTypes {
			if strings.Contains(ct, s) {
				return false
			}
		}
	}

	// Check URL extension
	if u, err := url.Parse(entry.Request.URL); err == nil {
		ext := ""
		path := u.Path
		if dot := strings.LastIndex(path, "."); dot != -1 {
			ext = strings.ToLower(path[dot:])
		}
		if ext != "" && staticExtensions[ext] {
			return false
		}
	}

	if c.verbose {
		return true
	}

	// Suppress 404s (probe noise — e.g. service-worker / PWA manifest priming
	// requests that 404 on sites not using them). Records are still written to
	// the DB, just not printed. Mirrors the discovery phase's 404 suppression.
	if entry.Response != nil && entry.Response.Status == 404 {
		return false
	}

	// Suppress cross-origin requests (host doesn't relate to target)
	if th := c.targetHostValue(); th != "" {
		if u, err := url.Parse(entry.Request.URL); err == nil {
			reqHost := strings.ToLower(u.Hostname())
			target := strings.ToLower(th)
			if reqHost != target && !strings.Contains(reqHost, target) {
				return false
			}
		}
	}

	return true
}

// catchAllAssetExtensions are URL path suffixes whose response must be JavaScript
// or JSON to be a real asset. A service worker, framework bundle, or web-app
// manifest is never legitimately served as text/html — the browser refuses to
// register a worker or parse a manifest delivered as HTML — so an HTML body on
// one of these paths is a SPA/PWA catch-all soft-404 (the index shell returned
// for an unknown route), not an endpoint.
var catchAllAssetExtensions = []string{".js", ".mjs", ".json", ".webmanifest"}

// isCatchAllAssetShell reports whether entry is a catch-all soft-404: a 2xx
// response on a JS/JSON asset path (see catchAllAssetExtensions) whose body came
// back as text/html. A worker/bundle/manifest is never legitimately served as
// HTML, so an HTML body on such a path is the SPA index shell a catch-all host
// returns for an unknown route — whatever requested it (a framework runtime, a
// service worker, or a discovery-queued asset fetch that flows through the
// browser). The dedup hash keys on the URL path, so without this guard each
// distinct such path persists as its own record and feeds dynamic-assessment a
// per-path copy of the home page.
//
// Called on the hot capture path (every entry), so it is ordered cheapest-first:
// a raw string suffix test rejects all non-asset traffic before any URL parse or
// content-type work, and it never re-parses the URL that computeHash parses on
// the kept path.
func isCatchAllAssetShell(entry *TrafficEntry) bool {
	if entry == nil || entry.Response == nil {
		return false
	}
	// Most selective check first: only JS/JSON asset paths can be a shell. Strip
	// any query/fragment, then suffix-match the lowercased tail — no URL parse.
	tail := entry.Request.URL
	if i := strings.IndexAny(tail, "?#"); i >= 0 {
		tail = tail[:i]
	}
	tail = strings.ToLower(tail)
	isAsset := false
	for _, ext := range catchAllAssetExtensions {
		if strings.HasSuffix(tail, ext) {
			isAsset = true
			break
		}
	}
	if !isAsset {
		return false
	}
	// Only a 2xx body can masquerade as a served asset.
	if entry.Response.Status < 200 || entry.Response.Status >= 300 {
		return false
	}
	// A real asset is served as JS/JSON; an HTML body on an asset path is the shell.
	// Prefer the precomputed httpx field, falling back to the header map for entries
	// written without computeHTTPXFields (direct writes / the load-failed path).
	ct := strings.ToLower(entry.ContentType)
	if ct == "" {
		if v, ok := entry.Response.Headers["content-type"]; ok {
			ct = strings.ToLower(v)
		} else if v, ok := entry.Response.Headers["Content-Type"]; ok {
			ct = strings.ToLower(v)
		}
	}
	return strings.Contains(ct, "text/html")
}

// writeEntry writes a traffic entry via the Writer interface and prints log to stderr.
// Skips writing to file if hash already exists (deduplication).
func (c *Capture) writeEntry(entry *TrafficEntry) {
	// Drop catch-all soft-404 asset shells: JS/JSON asset paths that come back as
	// the SPA index.html (a catch-all host serving its shell for unknown routes).
	// They are not real endpoints, so keep them out of the DB (and thus out of
	// dynamic-assessment); a distinct path per shell otherwise defeats the
	// body-blind dedup hash. Still surfaced on the console under verbose for
	// debugging.
	if isCatchAllAssetShell(entry) {
		if !c.silent && c.verbose {
			printLog(entry, c.noColor, c.phaseTag)
		}
		zap.L().Debug("Dropping catch-all soft-404 asset shell",
			zap.String("url", entry.Request.URL),
			zap.String("content_type", entry.ContentType))
		return
	}

	entry.Hash = computeHash(entry)
	entry.TargetHost = c.targetHostValue()

	c.mu.Lock()

	// Drop late events that arrive after Close() niled the writer. The browser's
	// CDP event goroutine keeps delivering NetworkLoadingFailed/Finished events
	// after the crawl loop terminates, and onLoadingFailed/onLoadingFinished
	// release the lock before calling writeEntry — so Close() can win the race
	// and set c.writer = nil. Without this guard, c.writer.Write below panics
	// with a nil-pointer dereference.
	if c.stopped || c.writer == nil {
		c.mu.Unlock()
		return
	}

	// Check if hash already written to file
	_, alreadyWritten := c.seenHashes[entry.Hash]
	if alreadyWritten {
		// Duplicate detected - skip file write
		c.duplicateCount++

		// Still handle stderr logging independently
		_, alreadyLogged := c.logged[entry.Hash]
		if !alreadyLogged {
			c.logged[entry.Hash] = struct{}{}
		}
		noColor := c.noColor
		silent := c.silent
		c.mu.Unlock()

		// Print log OUTSIDE mutex if not already logged, not silent, and not noisy
		if !alreadyLogged && !silent && c.shouldLogEntry(entry) {
			printLog(entry, noColor, c.phaseTag)
		}

		// Debug log for duplicate skip
		zap.L().Debug("Skipped duplicate entry",
			zap.String("hash", entry.Hash),
			zap.String("url", entry.Request.URL))
		return
	}

	// Hash is NEW - mark as seen and write to file
	c.seenHashes[entry.Hash] = true
	err := c.writer.Write(entry)
	if err == nil {
		c.writtenCount++
	}
	noColor := c.noColor
	silent := c.silent

	// Check if already logged (stderr dedup)
	_, alreadyLogged := c.logged[entry.Hash]
	if !alreadyLogged {
		c.logged[entry.Hash] = struct{}{}
	}
	c.mu.Unlock()

	if err != nil {
		zap.L().Error("Failed to write traffic entry", zap.Error(err))
		return
	}

	// Print log OUTSIDE mutex - fmt.Fprintf to stderr is atomic
	if !alreadyLogged && !silent && c.shouldLogEntry(entry) {
		printLog(entry, noColor, c.phaseTag)
	}
}

// cleanupLoop periodically cleans up stale pending requests.
func (c *Capture) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupStalePending()
		default:
			if c.isStopped() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// cleanupStalePending removes pending requests that have timed out or have invalid sessions.
// CRITICAL: Uses 2-phase approach to avoid deadlock.
// Phase 1: Collect candidates (with lock)
// Phase 2: Validate sessions (WITHOUT lock - browser.Pages() may hold internal locks)
// Phase 3: Delete stale entries (with lock)
func (c *Capture) cleanupStalePending() {
	// Phase 1: Identify candidates by age (with lock)
	c.mu.Lock()
	now := time.Now()
	var candidates []struct {
		id        proto.NetworkRequestID
		sessionID proto.TargetSessionID
		age       time.Duration
	}

	for id, entry := range c.pending {
		age := now.Sub(entry.startTime)
		if age > pendingTimeout {
			candidates = append(candidates, struct {
				id        proto.NetworkRequestID
				sessionID proto.TargetSessionID
				age       time.Duration
			}{id, entry.sessionID, age})
		}
	}
	c.mu.Unlock()

	// Phase 2: Validate sessions (WITHOUT lock - safe to call browser methods)
	var toDelete []proto.NetworkRequestID
	for _, cand := range candidates {
		// Check if session still valid
		if !c.isSessionValid(cand.sessionID) {
			toDelete = append(toDelete, cand.id)
		}
	}

	// Phase 3: Delete stale entries (with lock)
	if len(toDelete) > 0 {
		c.mu.Lock()
		for _, id := range toDelete {
			delete(c.pending, id)
		}
		c.mu.Unlock()

		zap.L().Debug("Cleaned up stale pending requests",
			zap.Int("count", len(toDelete)))
	}
}

// computeHash generates a SHA256 hash for deduplication based on:
// method, path, param names, auth headers, request body, response content-type, status, server header.
func computeHash(entry *TrafficEntry) string {
	h := sha256.New()

	// 1. Method
	h.Write([]byte(entry.Request.Method))

	// 2. Full URL path (scheme://host/path, no query)
	parsedURL, err := url.Parse(entry.Request.URL)
	if err == nil {
		h.Write([]byte(parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path))

		// 3. Param names only, sorted alphabetically
		var paramNames []string
		for k := range parsedURL.Query() {
			paramNames = append(paramNames, k)
		}
		sort.Strings(paramNames)
		h.Write([]byte(strings.Join(paramNames, ",")))
	} else {
		h.Write([]byte(entry.Request.URL))
	}

	// 4. Authentication headers only (sorted by key)
	if len(entry.Request.Headers) > 0 {
		var authKeys []string
		for k := range entry.Request.Headers {
			if _, ok := authHeaders[strings.ToLower(k)]; ok {
				authKeys = append(authKeys, k)
			}
		}
		sort.Strings(authKeys)
		for _, k := range authKeys {
			h.Write([]byte(strings.ToLower(k)))
			h.Write([]byte(entry.Request.Headers[k]))
		}
	}

	// 5. Request body
	h.Write(entry.Request.Body)

	// 6-8. Response fields (only if response exists)
	if entry.Response != nil {
		// Content-Type
		if ct, ok := entry.Response.Headers["content-type"]; ok {
			h.Write([]byte(ct))
		} else if ct, ok := entry.Response.Headers["Content-Type"]; ok {
			h.Write([]byte(ct))
		}

		// Status code (2 bytes)
		h.Write([]byte{byte(entry.Response.Status >> 8), byte(entry.Response.Status)})

		// Server header
		if srv, ok := entry.Response.Headers["server"]; ok {
			h.Write([]byte(srv))
		} else if srv, ok := entry.Response.Headers["Server"]; ok {
			h.Write([]byte(srv))
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// convertHeaders converts NetworkHeaders to map[string]string.
func convertHeaders(headers proto.NetworkHeaders) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v.String()
	}
	return result
}

// Close stops capture and closes the writer.
// Note: The capture goroutine exits automatically when browser closes.
func (c *Capture) Close() error {
	c.mu.Lock()
	c.stopped = true
	writer := c.writer
	writtenCount := c.writtenCount
	duplicateCount := c.duplicateCount
	c.writer = nil
	c.mu.Unlock()

	// Log statistics BEFORE closing writer (only if duplicates exist)
	if duplicateCount > 0 {
		zap.L().Debug("Network capture statistics",
			zap.Int("written", writtenCount),
			zap.Int("duplicates_skipped", duplicateCount),
			zap.Int("total_processed", writtenCount+duplicateCount))
	}

	if writer != nil {
		return writer.Close()
	}
	return nil
}
