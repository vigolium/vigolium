// Package client_path_traversal_confirm browser-confirms Client-Side Path
// Traversal (CSPT). It is the active counterpart to the passive
// client_path_taint candidate detector: gated (fail-closed) on the
// cspt-candidate tech tag that module publishes, it drives a real browser to
// prove that a ../ segment in a URL-controlled source normalizes out of a
// client-side request path's intended prefix.
//
// The browser is reached only through the Navigate seam and candidate recovery
// only through the RecoverCandidates seam, so unit tests inject fakes and never
// launch a real browser or run jstangle. The flow-recognition primitives are
// shared with the passive detector via pkg/modules/infra/csptflow so the two
// modules never diverge.
package client_path_traversal_confirm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/csptflow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TechTagCSPTCandidate is the per-host tech tag the passive client_path_taint
// module publishes; this module is fail-closed on it. Aliased from the shared
// package so the value has a single source of truth.
const TechTagCSPTCandidate = csptflow.TechTagCSPTCandidate

const (
	probeNavTimeout         = 20 * time.Second
	probeWaitExtra          = 1500 * time.Millisecond
	captureProjectUUID      = "cspt-probe"
	captureSource           = "cspt-confirm"
	maxCandidatesPerRequest = 5

	// modulePriority runs the module after cheap modules — each confirm spawns
	// browsers.
	modulePriority = 200
)

// Candidate is a recovered CSPT candidate to confirm.
type Candidate struct {
	SourceParam  string // e.g. "location.hash" — selects the URL position to inject
	Prefix       string // constant request-path prefix (e.g. "/api/items/")
	Method       string // inferred method from static analysis (informational)
	Credentialed bool   // request carries credentials (raises severity)
}

// NavRequest is the input to the Navigate seam.
type NavRequest struct {
	URL        string
	Cookies    []*http.Cookie
	Headers    map[string]string
	NavTimeout time.Duration
	WaitExtra  time.Duration
}

// CapturedRequest is a request the browser made during navigation.
type CapturedRequest struct {
	URL    string
	Method string
}

type Module struct {
	modkit.BaseActiveModule

	budget *Budget

	// Navigate drives a browser to nav.URL and returns every request the browser
	// made. Defaults to a spitolas.ProbeURL-backed impl; tests inject a fake.
	Navigate func(ctx context.Context, nav NavRequest) ([]CapturedRequest, error)

	// RecoverCandidates re-derives CSPT candidates from the page JS. Defaults to
	// a jstangle-backed impl; tests inject a fake returning synthetic candidates.
	RecoverCandidates func(ctx context.Context, js, sourceURL string) []Candidate
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		budget: NewBudget(0, 0),
	}
	m.ModuleTags = ModuleTags
	m.Navigate = m.defaultNavigate
	m.RecoverCandidates = m.defaultRecoverCandidates
	return m
}

// Priority runs the module after cheap modules (browser probes are expensive).
func (m *Module) Priority() int { return modulePriority }

// RequiredTechs fail-closes the module on the cspt-candidate tag: unlike the
// executor's fail-open TechAware default, the ScanPerRequest gate below also
// rejects unknown hosts, so this module never runs without a candidate.
func (m *Module) RequiredTechs() []string { return []string{TechTagCSPTCandidate} }

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *vhttp.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return m.ScanPerRequestContext(context.Background(), ctx, httpClient, scanCtx)
}

// ScanPerInsertionPointContext / ScanPerHostContext are no-ops: the module is
// ScanScopeRequest only, but implementing the full ContextualActiveModule trio
// lets the executor thread cancellation into ScanPerRequestContext.
func (m *Module) ScanPerInsertionPointContext(_ context.Context, _ *httpmsg.HttpRequestResponse, _ httpmsg.InsertionPoint, _ *vhttp.Requester, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func (m *Module) ScanPerHostContext(_ context.Context, _ *httpmsg.HttpRequestResponse, _ *vhttp.Requester, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func (m *Module) ScanPerRequestContext(runCtx context.Context, ctx *httpmsg.HttpRequestResponse, _ *vhttp.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	u, err := ctx.URL()
	if err != nil || u == nil {
		return nil, nil
	}
	host := u.Host

	// HARD tech gate — fail CLOSED. Never run without an observed CSPT candidate.
	if !scanCtx.HasTech(host, TechTagCSPTCandidate) {
		return nil, nil
	}

	// In-scope HTML/JS responses only (the page whose JS builds the request).
	js := csptflow.ExtractJS(ctx, u)
	if js == "" {
		return nil, nil
	}

	release, ok := m.budget.Reserve(runCtx, host)
	if !ok {
		return nil, nil // browser budget exhausted for this scan/host
	}
	defer release()

	candidates := m.RecoverCandidates(runCtx, js, u.String())
	if len(candidates) == 0 {
		return nil, nil
	}

	cookies := cookiesFromRequest(ctx)
	var results []*output.ResultEvent
	seen := make(map[string]struct{}, len(candidates))
	for i, c := range candidates {
		if i >= maxCandidatesPerRequest {
			break
		}
		if strings.TrimSpace(c.Prefix) == "" {
			continue
		}
		key := c.SourceParam + "|" + c.Prefix + "|" + strings.ToUpper(c.Method)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		if cr := m.confirmCandidate(runCtx, u.String(), c, cookies); cr != nil {
			results = append(results, m.buildResult(ctx, u, cr))
		}
	}
	return results, nil
}

// defaultNavigate drives a real browser via spitolas.ProbeURL with an in-memory
// capture sink, returning every request the browser made.
func (m *Module) defaultNavigate(ctx context.Context, nav NavRequest) ([]CapturedRequest, error) {
	sink := &memSink{}
	_, err := spitolas.ProbeURL(ctx, spitolas.ProbeConfig{
		URL:                nav.URL,
		Cookies:            nav.Cookies,
		Headers:            nav.Headers,
		NavTimeout:         nav.NavTimeout,
		WaitExtra:          nav.WaitExtra,
		CaptureSink:        sink,
		CaptureSource:      captureSource,
		CaptureProjectUUID: captureProjectUUID, // activates the CDP network recorder
	})
	return sink.captured(), err
}

// defaultRecoverCandidates re-derives CSPT candidates from the page JS via
// jstangle (ProfileDOMSecurity), using the shared flow-recognition. Candidates
// without a known request-path prefix are dropped (nothing to reason an escape
// against), and the rest are deduped by source|prefix|method.
func (m *Module) defaultRecoverCandidates(ctx context.Context, js, sourceURL string) []Candidate {
	if strings.TrimSpace(js) == "" {
		return nil
	}
	scanner := csptflow.Scanner()
	if scanner == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, csptflow.ScanTimeout)
	defer cancel()
	res, err := scanner.ScanWithOptions(cctx, []byte(js), jstangle.ScanOptions{
		Profile: jstangle.ProfileDOMSecurity, SourceURL: sourceURL,
	})
	if err != nil || res == nil {
		return nil
	}

	var out []Candidate
	seen := make(map[string]struct{})
	for _, f := range csptflow.NetworkPathFlows(res.DomFlows, res.BrowserFlows) {
		if f.Prefix == "" {
			continue
		}
		key := f.Source + "|" + f.Prefix + "|" + f.Method
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Candidate{SourceParam: f.Source, Prefix: f.Prefix, Method: f.Method})
	}
	return out
}

func (m *Module) buildResult(ctx *httpmsg.HttpRequestResponse, u *urlutil.URL, cr *confirmResult) *output.ResultEvent {
	sev, primitive := severityFor(cr.Method, cr.Candidate.Credentialed)
	return &output.ResultEvent{
		URL:           u.String(),
		Host:          u.Host,
		Request:       string(ctx.Request().Raw()),
		Matched:       cr.NormPath,
		MatcherStatus: true,
		RecordKind:    output.RecordKindFinding,
		EvidenceGrade: output.EvidenceGradeDifferential,
		AdditionalEvidence: []string{
			"control (stays under prefix): " + cr.ControlMethod + " " + cr.ControlURL,
			"payload #1 (escaped): " + cr.Method + " " + cr.Payload1URL,
			"payload #2 (escaped): " + cr.Method + " " + cr.Payload2URL,
			"normalized escaped path: " + cr.NormPath,
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: describeConfirm(u.String(), cr, primitive),
			Severity:    sev,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
		},
	}
}

// severityFor grades the confirmed primitive: a plain GET path escape is
// Low/Firm; a credentialed or non-GET (state-changing) request is Medium/Firm.
func severityFor(method string, credentialed bool) (severity.Severity, string) {
	mth := strings.ToUpper(strings.TrimSpace(method))
	if mth == "" {
		mth = "GET"
	}
	stateChanging := mth != "GET" && mth != "HEAD"
	if credentialed || stateChanging {
		return severity.Medium, "credentialed or state-changing (" + mth + ") request primitive"
	}
	return severity.Low, "GET request primitive"
}

func describeConfirm(pageURL string, cr *confirmResult, primitive string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Browser-confirmed Client-Side Path Traversal on %s. ", pageURL)
	fmt.Fprintf(&b, "The URL source %s is concatenated onto the request-path prefix %q. ", cr.Candidate.SourceParam, cr.Candidate.Prefix)
	fmt.Fprintf(&b, "A benign control value stayed under the prefix, while a `../` payload made the browser send %s %s — the path normalized out of the prefix to %q. ",
		cr.Method, cr.Payload1URL, cr.NormPath)
	fmt.Fprintf(&b, "The escape reproduced across two distinct canaries (%s, %s). ", cr.Canary1, cr.Canary2)
	fmt.Fprintf(&b, "This is a %s: the page's own request was steered to an unintended endpoint. ", primitive)
	b.WriteString("The canary target is random and non-existent, so no live endpoint was invoked — only the path-escape primitive is proven.")
	return b.String()
}

func cookiesFromRequest(ctx *httpmsg.HttpRequestResponse) []*http.Cookie {
	if ctx == nil || ctx.Request() == nil {
		return nil
	}
	cookie := ctx.Request().Header("Cookie")
	if cookie == "" {
		return nil
	}
	h := http.Header{}
	h.Set("Cookie", cookie)
	return (&http.Request{Header: h}).Cookies()
}

// memSink is an in-memory spitolas.CaptureSink capturing every browser request.
type memSink struct {
	mu   sync.Mutex
	recs []*httpmsg.HttpRequestResponse
}

func (s *memSink) SaveRecord(_ context.Context, rr *httpmsg.HttpRequestResponse, _, _ string) (string, error) {
	s.mu.Lock()
	s.recs = append(s.recs, rr)
	s.mu.Unlock()
	return "", nil
}

func (s *memSink) SaveRecordBatch(_ context.Context, records []*httpmsg.HttpRequestResponse, _, _ string) ([]string, error) {
	s.mu.Lock()
	s.recs = append(s.recs, records...)
	s.mu.Unlock()
	return make([]string, len(records)), nil
}

func (s *memSink) captured() []CapturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CapturedRequest, 0, len(s.recs))
	for _, rr := range s.recs {
		if rr == nil || rr.Request() == nil {
			continue
		}
		u, err := rr.URL()
		if err != nil || u == nil {
			continue
		}
		out = append(out, CapturedRequest{URL: u.String(), Method: rr.Request().Method()})
	}
	return out
}
