package spitolas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// An unlock walk opens a single-page app with forged client state (an
// UnlockProfile) and visits its routes, so the views a client-side gate hides
// from an anonymous visitor render and send their real API calls.
//
// What the walk establishes, and what it does not:
//
//   - Seeds are data, never source. The storage seeds reach the page as a JSON
//     string literal that a fixed init script parses; no profile string is ever
//     concatenated into script source, and routes reach the page as CDP call
//     arguments.
//   - Stubs are confined: only a request on the profile's origin can match one,
//     and a matching request is answered in the browser (Fetch.fulfillRequest)
//     without reaching the target. A stubbed response is never stored and never
//     reported as traffic.
//   - Writes are recorded, not sent: every request with a method other than
//     GET, HEAD or OPTIONS is failed in the browser and reported by shape
//     (method, URL, header names, a clipped body). AllowWrites lets in-scope
//     writes through; out-of-scope writes are always failed.
//   - Every real in-scope exchange is stored through the sink. The request is
//     real; the page state that produced it was forged, which the sink records
//     on the row (the CLI adds the client-unlocked remark).
//
// The guarantee covers the walk's own tab: its frames on the same process,
// its dedicated workers and its navigations. Popups are disabled (window.open
// returns null) and service workers are bypassed, because both run outside the
// tab's interceptor. Out-of-process cross-origin iframes and shared workers
// are also outside it.

// UnlockWalkSink stores the real exchanges an unlock walk observed and
// returns each stored record's UUID.
type UnlockWalkSink interface {
	SaveUnlockWalkRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse) (string, error)
}

// UnlockWalkConfig configures one UnlockWalk.
type UnlockWalkConfig struct {
	// Profile is the forged client state (from ParseUnlockProfile).
	Profile *UnlockProfile
	// Sink stores real in-scope exchanges; nil stores nothing (requests are
	// still reported, without record UUIDs).
	Sink UnlockWalkSink
	// InScope admits a URL off the profile's origin as in scope. nil admits
	// only the origin itself.
	InScope func(u *url.URL) bool
	// AllowWrites lets in-scope requests with a state-changing method reach
	// the target. Off by default: they are failed in the browser and reported.
	AllowWrites bool
	// ProxyURL routes the browser through a proxy.
	ProxyURL string
	// Headed shows the browser window; VIGOLIUM_BROWSER_HEADED also does.
	Headed bool
	// NavTimeout bounds each full navigation (default 30s).
	NavTimeout time.Duration
}

// UnlockRequest is one real request a route sent.
type UnlockRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	// Type is the browser's resource type (Document, XHR, Fetch, …).
	Type string `json:"type,omitempty"`
	// Status is the response status, 0 when no response was observed.
	Status int `json:"status,omitempty"`
	// RecordUUID is the stored record holding this exchange, empty when it was
	// not stored (no response, no sink, or the store refused it).
	RecordUUID string `json:"record_uuid,omitempty"`
}

// UnlockAbortedWrite is the shape of a state-changing request the walk failed
// in the browser. It was never sent.
type UnlockAbortedWrite struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	ContentType string   `json:"content_type,omitempty"`
	HeaderNames []string `json:"header_names,omitempty"`
	// Body is the request body, clipped to 8 KiB; BodyBytes is its full size.
	Body          string `json:"body,omitempty"`
	BodyBytes     int    `json:"body_bytes,omitempty"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
}

// UnlockStubHit is one request a stub answered.
type UnlockStubHit struct {
	// Stub is the stub's index in the profile.
	Stub   int    `json:"stub"`
	Method string `json:"method"`
	Path   string `json:"path"`
	URL    string `json:"url"`
}

// UnlockStubRef names a stub by index, method and path.
type UnlockStubRef struct {
	Stub   int    `json:"stub"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// UnlockRouteResult is what one navigation of the walk observed.
type UnlockRouteResult struct {
	// Route is the profile's route as written ("/" for the landing load).
	Route string `json:"route"`
	// URL is the route resolved on the origin.
	URL string `json:"url"`
	// Navigation is how the route was reached: "load" (the landing page),
	// "client" (history.pushState plus popstate) or "full" (a page load, when
	// the client navigation failed or the app did not react to it).
	Navigation string `json:"navigation"`
	FinalURL   string `json:"final_url"`
	// Redirected is true when the page settled anywhere but URL (a client-side
	// guard sending the visitor to a login page, typically).
	Redirected bool   `json:"redirected"`
	Title      string `json:"title,omitempty"`
	// TextSample is the start of the page's visible text, at most 200
	// characters.
	TextSample    string               `json:"text_sample,omitempty"`
	Requests      []UnlockRequest      `json:"requests"`
	AbortedWrites []UnlockAbortedWrite `json:"aborted_writes"`
	StubsHit      []UnlockStubHit      `json:"stubs_hit"`
	Error         string               `json:"error,omitempty"`
}

// UnlockWalkTotals sums a walk.
type UnlockWalkTotals struct {
	Routes     int `json:"routes"`
	Rendered   int `json:"rendered"`
	Redirected int `json:"redirected"`
	// RealRequests counts the real requests reported across the landing load
	// and every route.
	RealRequests int `json:"real_requests"`
	// RecordsStored counts the distinct records the walk's exchanges are
	// stored as (an exchange already in the store counts once, as its row).
	RecordsStored int `json:"records_stored"`
	StoreErrors   int `json:"store_errors,omitempty"`
	AbortedWrites int `json:"aborted_writes"`
	// AbortedOutOfScope counts state-changing requests to out-of-scope URLs,
	// failed and not reported by shape.
	AbortedOutOfScope int `json:"aborted_out_of_scope"`
	StubsHit          int `json:"stubs_hit"`
}

// UnlockWalkResult is the outcome of UnlockWalk.
type UnlockWalkResult struct {
	Origin  string              `json:"origin"`
	Landing UnlockRouteResult   `json:"landing"`
	Routes  []UnlockRouteResult `json:"routes"`
	// RoutesSkipped are the profile's routes past maxRoutes, not visited.
	RoutesSkipped []string         `json:"routes_skipped,omitempty"`
	StubsNeverHit []UnlockStubRef  `json:"stubs_never_hit"`
	WritesAllowed bool             `json:"writes_allowed"`
	Totals        UnlockWalkTotals `json:"totals"`
}

// unlockAbortedBodyCap clips an aborted write's body in the report.
const unlockAbortedBodyCap = 8 << 10

// unlockTextSampleRunes bounds a route's text sample.
const unlockTextSampleRunes = 200

// unlockIdle is the quiet period that counts as the network settling.
const unlockIdle = 500 * time.Millisecond

// unlockSeedScript writes the storage seeds before the app's scripts run. It
// is fixed source: the seeds arrive as one JSON string literal (%s), parsed
// here, so no profile string ever becomes script text. A document on any
// other origin (a third-party frame) is left alone.
const unlockSeedScript = `(function (raw) {
  var seed;
  try { seed = JSON.parse(raw); } catch (e) { return; }
  if (!seed || location.origin !== seed.origin) return;
  var put = function (name, items) {
    if (!items) return;
    try {
      var store = window[name];
      Object.keys(items).forEach(function (k) { store.setItem(k, items[k]); });
    } catch (e) {}
  };
  put('localStorage', seed.localStorage);
  put('sessionStorage', seed.sessionStorage);
})(%s);`

// unlockTabGuardScript keeps the app in the walk's tab: a popup is a new
// target the tab's interceptor does not see, so window.open opens nothing.
const unlockTabGuardScript = `(function () {
  try { window.open = function () { return null; }; } catch (e) {}
})();`

// unlockClientNavScript navigates the app client-side: pushState to the
// target, then the events a history or hash router listens for. The target is
// a call argument, never part of the source.
const unlockClientNavScript = `(target) => {
  const before = location.href;
  const next = new URL(target, before);
  history.pushState(null, '', next.href);
  dispatchEvent(new PopStateEvent('popstate', { state: null }));
  if (next.hash !== new URL(before).hash) {
    dispatchEvent(new HashChangeEvent('hashchange', { oldURL: before, newURL: next.href }));
  }
  return true;
}`

// unlockTextScript reads the page's visible text, whitespace collapsed.
const unlockTextScript = `() => ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim().slice(0, 4000)`

// unlockSeedJSON is the storage seed document unlockSeedScript reads, as a
// JSON string literal ready to sit in script source. json.Marshal of a string
// escapes quotes, backslashes, control characters, <, >, & and U+2028/U+2029,
// so the literal cannot end early or break out of a script element.
func unlockSeedJSON(p *UnlockProfile) (string, error) {
	doc, err := json.Marshal(struct {
		Origin         string            `json:"origin"`
		LocalStorage   map[string]string `json:"localStorage,omitempty"`
		SessionStorage map[string]string `json:"sessionStorage,omitempty"`
	}{p.Origin, p.LocalStorage, p.SessionStorage})
	if err != nil {
		return "", err
	}
	lit, err := json.Marshal(string(doc))
	if err != nil {
		return "", err
	}
	return string(lit), nil
}

// unlockReportedTypes are the resource types a route's request list reports:
// navigations and API calls. Scripts, styles and media are still stored, just
// not listed per route.
var unlockReportedTypes = []proto.NetworkResourceType{
	proto.NetworkResourceTypeDocument,
	proto.NetworkResourceTypeXHR,
	proto.NetworkResourceTypeFetch,
	proto.NetworkResourceTypeEventSource,
	proto.NetworkResourceTypeOther,
}

// unlockPausedTypes are paused on every origin: the types that can carry a
// write method (so a third-party write is failed too) and the API calls an
// in-scope host other than the origin receives.
var unlockPausedTypes = append(browser.WriteCapableResourceTypes(), proto.NetworkResourceTypeEventSource)

// unlockBucket collects what one navigation caused.
type unlockBucket struct {
	requests []UnlockRequest
	aborted  []UnlockAbortedWrite
	stubs    []UnlockStubHit
}

// storedExchange is what the walk's writer stored for one method and URL.
type storedExchange struct {
	status int
	uuid   string
}

// unlockWalk is one walk's state, shared by the interceptor, the capture
// writer and the navigation loop.
type unlockWalk struct {
	ctx     context.Context
	cfg     UnlockWalkConfig
	profile *UnlockProfile
	origin  *url.URL

	// current is the bucket index requests are attributed to: 0 the landing
	// load, i+1 the profile's route i.
	current atomic.Int32

	mu                sync.Mutex
	buckets           []*unlockBucket
	stubHits          []int
	stored            map[string]storedExchange
	storeErrors       int
	abortedOutOfScope int
}

func (w *unlockWalk) inScope(u *url.URL) bool {
	if sameUnlockOrigin(w.origin, u) {
		return true
	}
	return w.cfg.InScope != nil && w.cfg.InScope(u)
}

func exchangeKey(method, rawURL string) string {
	return strings.ToUpper(method) + " " + rawURL
}

// decide is the walk's interceptor: stub, fail or continue each paused
// request, recording it on the current navigation first.
func (w *unlockWalk) decide(e *proto.FetchRequestPaused) browser.InterceptDecision {
	req := e.Request
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return browser.InterceptDecision{Verdict: browser.InterceptContinue}
	}
	method := strings.ToUpper(req.Method)

	w.mu.Lock()
	defer w.mu.Unlock()
	b := w.buckets[w.current.Load()]

	if i := w.profile.matchStub(w.origin, method, u); i >= 0 {
		s := w.profile.Stubs[i]
		w.stubHits[i]++
		b.stubs = append(b.stubs, UnlockStubHit{Stub: i, Method: s.Method, Path: s.Path, URL: req.URL})
		return browser.InterceptDecision{Verdict: browser.InterceptFulfill, Status: s.Status, ContentType: s.ContentType, Body: []byte(s.Body)}
	}

	inScope := w.inScope(u)
	if !safeUnlockMethod(method) {
		switch {
		case inScope && w.cfg.AllowWrites:
			b.requests = append(b.requests, UnlockRequest{Method: method, URL: req.URL, Type: string(e.ResourceType)})
			return browser.InterceptDecision{Verdict: browser.InterceptContinue}
		case inScope:
			b.aborted = append(b.aborted, abortedShape(method, req))
		default:
			w.abortedOutOfScope++
		}
		return browser.InterceptDecision{Verdict: browser.InterceptFail}
	}
	if inScope && slices.Contains(unlockReportedTypes, e.ResourceType) {
		b.requests = append(b.requests, UnlockRequest{Method: method, URL: req.URL, Type: string(e.ResourceType)})
	}
	return browser.InterceptDecision{Verdict: browser.InterceptContinue}
}

// abortedShape is the reported shape of a failed write: header names (never
// their values) and the body clipped to unlockAbortedBodyCap.
func abortedShape(method string, req *proto.NetworkRequest) UnlockAbortedWrite {
	out := UnlockAbortedWrite{Method: method, URL: req.URL}
	for name, v := range req.Headers {
		out.HeaderNames = append(out.HeaderNames, strings.ToLower(name))
		if strings.EqualFold(name, "Content-Type") {
			out.ContentType = v.Str()
		}
	}
	slices.Sort(out.HeaderNames)
	body := []byte(req.PostData)
	if len(body) == 0 {
		for _, entry := range req.PostDataEntries {
			if entry != nil {
				body = append(body, entry.Bytes...)
			}
		}
	}
	out.BodyBytes = len(body)
	if len(body) > unlockAbortedBodyCap {
		body = body[:unlockAbortedBodyCap]
		out.BodyTruncated = true
	}
	out.Body = strings.ToValidUTF8(string(body), "\uFFFD")
	return out
}

// Write is the capture writer: it stores real in-scope exchanges and drops
// everything the walk forged or never sent. The drop rules are decided from
// the exchange itself, not from request ids, so a stubbed or failed request
// is dropped even when its network events reach the capture in any order:
//
//   - an exchange a stub matches was answered by the stub (the interceptor
//     answers every such request), so it is never stored;
//   - a state-changing request without AllowWrites was failed in the browser;
//   - an exchange with no response (failed, cancelled) has nothing to store;
//   - an out-of-scope exchange is not the walk's to store.
func (w *unlockWalk) Write(entry *network.TrafficEntry) error {
	if entry == nil || entry.Response == nil || entry.Error != "" || entry.Response.Status <= 0 {
		return nil
	}
	u, err := url.Parse(entry.Request.URL)
	if err != nil || !w.inScope(u) {
		return nil
	}
	method := strings.ToUpper(entry.Request.Method)
	if w.profile.matchStub(w.origin, method, u) >= 0 {
		return nil
	}
	if !safeUnlockMethod(method) && !w.cfg.AllowWrites {
		return nil
	}
	rec := storedExchange{status: entry.Response.Status}
	if w.cfg.Sink != nil {
		rr, cerr := network.ToHttpRequestResponse(entry)
		if cerr != nil {
			return cerr
		}
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 10*time.Second)
		id, serr := w.cfg.Sink.SaveUnlockWalkRecord(saveCtx, rr)
		cancel()
		if serr != nil {
			zap.L().Debug("unlock walk: store exchange", zap.String("url", entry.Request.URL), zap.Error(serr))
			w.mu.Lock()
			w.storeErrors++
			w.mu.Unlock()
		}
		rec.uuid = id
	}
	w.mu.Lock()
	w.stored[exchangeKey(method, entry.Request.URL)] = rec
	w.mu.Unlock()
	return nil
}

// Close satisfies network.Writer; Write stores synchronously.
func (w *unlockWalk) Close() error { return nil }

// UnlockWalk applies cfg.Profile to a fresh headless browser, loads the
// origin's root, visits each route (up to maxRoutes) and reports what every
// navigation rendered and sent. See the comment at the top of this file for
// what is stored, stubbed and failed.
func UnlockWalk(ctx context.Context, cfg UnlockWalkConfig) (*UnlockWalkResult, error) {
	p := cfg.Profile
	if p == nil {
		return nil, errors.New("UnlockWalk: a profile is required")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	origin, _ := parseUnlockOrigin(p.Origin)
	settle := time.Duration(p.SettleMs) * time.Millisecond

	routes := p.Routes
	var skipped []string
	if len(routes) > p.MaxRoutes {
		routes, skipped = routes[:p.MaxRoutes], routes[p.MaxRoutes:]
	}

	w := &unlockWalk{
		ctx:      ctx,
		cfg:      cfg,
		profile:  p,
		origin:   origin,
		buckets:  make([]*unlockBucket, len(routes)+1),
		stubHits: make([]int, len(p.Stubs)),
		stored:   map[string]storedExchange{},
	}
	for i := range w.buckets {
		w.buckets[i] = &unlockBucket{}
	}

	br, err := launchProbeBrowser(ctx, probeBrowserOptions{
		URL:        p.Origin,
		Headed:     cfg.Headed,
		ProxyURL:   cfg.ProxyURL,
		NavTimeout: probeNavTimeout(cfg.NavTimeout),
	})
	if err != nil {
		return nil, fmt.Errorf("UnlockWalk: %w", err)
	}
	defer func() { _ = br.Close() }()

	capture := network.New(w, true, true, false, true, true, origin.Hostname(), "unlock-walk")
	if err := capture.Start(br.RodBrowser()); err != nil {
		return nil, fmt.Errorf("UnlockWalk: start capture: %w", err)
	}
	captureClosed := false
	closeCapture := func() {
		if !captureClosed {
			captureClosed = true
			if cerr := capture.Close(); cerr != nil {
				zap.L().Debug("UnlockWalk: capture close", zap.Error(cerr))
			}
		}
	}
	defer closeCapture()

	page, err := br.NewPage()
	if err != nil {
		return nil, fmt.Errorf("UnlockWalk: open page: %w", err)
	}
	if err := w.preparePage(page); err != nil {
		return nil, err
	}

	res := &UnlockWalkResult{Origin: p.Origin, RoutesSkipped: skipped, WritesAllowed: cfg.AllowWrites}

	root := origin.ResolveReference(&url.URL{Path: "/"})
	res.Landing = UnlockRouteResult{Route: "/", URL: root.String(), Navigation: "load"}
	if nerr := page.NavigateCtx(ctx, root.String()); nerr != nil {
		res.Landing.Error = nerr.Error()
	}
	settlePage(page, settle)
	text := pageText(page)
	w.observe(page, root, text, &res.Landing)

	for i, route := range routes {
		if ctx.Err() != nil {
			break
		}
		target, _ := resolveUnlockRoute(origin, route)
		r := UnlockRouteResult{Route: route, URL: target.String()}
		text = w.visit(ctx, page, int32(i+1), target, settle, text, &r)
		res.Routes = append(res.Routes, r)
	}

	// The capture's body workers finish their writes on close, so every
	// stored exchange is known before the requests are joined to records.
	closeCapture()
	w.finish(res)
	return res, ctx.Err()
}

// preparePage installs the walk on a fresh tab before its first navigation:
// service workers bypassed, popups disabled, storage seeds, cookies, then the
// interceptor.
func (w *unlockWalk) preparePage(page *browser.Page) error {
	if err := page.BypassServiceWorker(); err != nil {
		return fmt.Errorf("UnlockWalk: bypass service workers: %w", err)
	}
	if _, err := page.RodPage().EvalOnNewDocument(unlockTabGuardScript); err != nil {
		return fmt.Errorf("UnlockWalk: install the tab guard: %w", err)
	}
	if len(w.profile.LocalStorage) > 0 || len(w.profile.SessionStorage) > 0 {
		lit, err := unlockSeedJSON(w.profile)
		if err != nil {
			return fmt.Errorf("UnlockWalk: encode storage seeds: %w", err)
		}
		if _, err := page.RodPage().EvalOnNewDocument(fmt.Sprintf(unlockSeedScript, lit)); err != nil {
			return fmt.Errorf("UnlockWalk: install the storage seeds: %w", err)
		}
	}
	if len(w.profile.Cookies) > 0 {
		cookies := make([]*http.Cookie, 0, len(w.profile.Cookies))
		for _, c := range w.profile.Cookies {
			cookies = append(cookies, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Secure: w.origin.Scheme == "https"})
		}
		if err := page.SetCookies(cookies); err != nil {
			return fmt.Errorf("UnlockWalk: set cookies: %w", err)
		}
	}
	ic := &browser.Interceptor{
		Patterns: []string{w.origin.String() + "/*"},
		Types:    unlockPausedTypes,
		Decide:   w.decide,
	}
	if err := page.InstallInterceptor(ic); err != nil {
		return fmt.Errorf("UnlockWalk: install the interceptor: %w", err)
	}
	return nil
}

// visit reaches one route: a client-side navigation first, a full page load
// when that failed or the app neither changed its text nor sent a request.
// before is the page's text as the previous navigation left it; visit returns
// the text this route settled on, which the next route takes as its before.
func (w *unlockWalk) visit(ctx context.Context, page *browser.Page, idx int32, target *url.URL, settle time.Duration, before string, r *UnlockRouteResult) string {
	w.current.Store(idx)
	r.Navigation = "client"
	_, navErr := page.EvalWithArgs(unlockClientNavScript, target.String())
	after := ""
	if navErr == nil {
		settlePage(page, settle)
		after = pageText(page)
	}
	if navErr != nil || (after == before && w.bucketEmpty(idx)) {
		r.Navigation = "full"
		if err := page.NavigateCtx(ctx, target.String()); err != nil {
			r.Error = err.Error()
		}
		settlePage(page, settle)
		after = pageText(page)
	}
	w.observe(page, target, after, r)
	return after
}

func (w *unlockWalk) bucketEmpty(idx int32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	b := w.buckets[idx]
	return len(b.requests) == 0 && len(b.aborted) == 0 && len(b.stubs) == 0
}

// observe reads where the page settled; text is what it shows (pageText).
func (w *unlockWalk) observe(page *browser.Page, target *url.URL, text string, r *UnlockRouteResult) {
	r.FinalURL, _ = page.URL()
	r.Redirected = !sameRouteTarget(target, r.FinalURL)
	r.Title, _ = page.Title()
	r.TextSample = textutil.TruncateRunes(text, unlockTextSampleRunes)
}

// finish joins each route's requests to the exchanges the writer stored and
// fills the totals.
func (w *unlockWalk) finish(res *UnlockWalkResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fill := func(r *UnlockRouteResult, b *unlockBucket) {
		r.Requests = make([]UnlockRequest, 0, len(b.requests))
		for _, q := range b.requests {
			if s, ok := w.stored[exchangeKey(q.Method, q.URL)]; ok {
				q.Status, q.RecordUUID = s.status, s.uuid
			}
			r.Requests = append(r.Requests, q)
		}
		r.AbortedWrites = append([]UnlockAbortedWrite{}, b.aborted...)
		r.StubsHit = append([]UnlockStubHit{}, b.stubs...)
		res.Totals.RealRequests += len(r.Requests)
		res.Totals.AbortedWrites += len(r.AbortedWrites)
		res.Totals.StubsHit += len(r.StubsHit)
	}
	fill(&res.Landing, w.buckets[0])
	for i := range res.Routes {
		fill(&res.Routes[i], w.buckets[i+1])
		res.Totals.Routes++
		if res.Routes[i].Redirected {
			res.Totals.Redirected++
		} else if res.Routes[i].Error == "" {
			res.Totals.Rendered++
		}
	}
	uuids := map[string]bool{}
	for _, s := range w.stored {
		if s.uuid != "" {
			uuids[s.uuid] = true
		}
	}
	res.Totals.RecordsStored = len(uuids)
	res.Totals.StoreErrors = w.storeErrors
	res.Totals.AbortedOutOfScope = w.abortedOutOfScope
	res.StubsNeverHit = []UnlockStubRef{}
	for i, n := range w.stubHits {
		if n == 0 {
			s := w.profile.Stubs[i]
			res.StubsNeverHit = append(res.StubsNeverHit, UnlockStubRef{Stub: i, Method: s.Method, Path: s.Path})
		}
	}
}

// settlePage waits for the network to go quiet, bounded by max, then gives
// the app a moment to render what the last response carried.
func settlePage(page *browser.Page, max time.Duration) {
	page.WaitNetworkIdle(unlockIdle, max)
	time.Sleep(150 * time.Millisecond)
}

// pageText is the page's visible text ("" when it cannot be read).
func pageText(page *browser.Page) string {
	v, err := page.EvalWithArgs(unlockTextScript)
	if err != nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// sameRouteTarget reports whether the page settled on target: same origin,
// same path (a trailing slash aside) and, when target names a fragment route,
// the same fragment.
func sameRouteTarget(target *url.URL, final string) bool {
	f, err := url.Parse(final)
	if err != nil || !sameUnlockOrigin(target, f) {
		return false
	}
	norm := func(p string) string {
		if p = strings.TrimRight(p, "/"); p == "" {
			return "/"
		}
		return p
	}
	if norm(f.Path) != norm(target.Path) {
		return false
	}
	return target.Fragment == "" || strings.TrimRight(f.Fragment, "/") == strings.TrimRight(target.Fragment, "/")
}
