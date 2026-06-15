package xss_light_scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// markerRe matches the alert marker this module embeds in its confirmation
// payloads (see newConfirmMarker).
var markerRe = regexp.MustCompile(`vigx[0-9a-f]+`)

// executingProbe simulates a browser that actually runs the injected script: it
// pulls the alert marker out of the navigated URL and reports it as a dialog,
// exactly as a real alert(marker) would surface.
func executingProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	m := markerRe.FindString(cfg.URL)
	if m == "" {
		return &spitolas.ProbeResult{}, nil
	}
	return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: m}}}, nil
}

// blockedProbe simulates a page that loads but never fires a dialog — the
// signature of a CSP-locked or non-executing reflection (the real Salesforce
// Aura false positive).
func blockedProbe(_ context.Context, _ spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	return &spitolas.ProbeResult{}, nil
}

// jsStringHandler reflects the discovered `body` parameter raw inside a
// double-quoted JS string — the JSStringDQBreakout context from the report.
func jsStringHandler(filter func(string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("body")
		if filter != nil {
			v = filter(v)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>var cfg = "` + v + `";</script></body></html>`))
	}
}

// scanParamDiscovery is the workhorse: spins up a server, runs the module with
// the given probe, and returns the findings.
func scanParamDiscovery(t *testing.T, h http.HandlerFunc, probe ProbeFunc) []*pdFinding {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?x=1")

	mod := NewParamDiscoveryScanner()
	mod.Probe = probe

	res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	out := make([]*pdFinding, 0, len(res))
	for _, e := range res {
		out = append(out, &pdFinding{
			param:       e.FuzzingParameter,
			severity:    e.Info.Severity,
			confidence:  e.Info.Confidence,
			description: e.Info.Description,
			request:     e.Request,
			evidence:    e.AdditionalEvidence,
		})
	}
	return out
}

type pdFinding struct {
	param       string
	severity    severity.Severity
	confidence  severity.Confidence
	description string
	request     string
	evidence    []string
}

// ---------------------------------------------------------------------------
// End-to-end confirmation tiers
// ---------------------------------------------------------------------------

func TestParamDiscovery_BrowserConfirmed_High(t *testing.T) {
	res := scanParamDiscovery(t, jsStringHandler(nil), executingProbe)
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	f := res[0]
	if f.param != "body" {
		t.Fatalf("expected finding on body, got %q", f.param)
	}
	if f.severity != severity.High {
		t.Errorf("expected High severity for a browser-confirmed popup, got %s", f.severity)
	}
	if f.confidence != severity.Certain {
		t.Errorf("expected Certain confidence, got %s", f.confidence)
	}
	if !strings.Contains(f.description, "browser-confirmed") {
		t.Errorf("description should note browser confirmation: %q", f.description)
	}
	// Evidence must surface the actual bytes that landed in the response so a
	// reviewer can see the executable payload reflected, not just a claim. The JS
	// double-quote context now breaks out with operator chaining (`"^alert(...)^"`)
	// which executes even inside an expression.
	if !sliceContainsSubstr(f.evidence, `"^alert(`) {
		t.Errorf("expected evidence to include the operator-chaining breakout snippet, got %v", f.evidence)
	}
}

func sliceContainsSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// jsExprHandler reflects the discovered `body` parameter inside a single-quoted
// JS string that sits in an *expression* (an array literal). A statement
// terminator injected here ('foo';alert()//') is a SyntaxError that aborts the
// whole <script> — only operator chaining ('foo'^alert()^'') executes.
func jsExprHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("body")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>var cfg = ['` + v + `'];</script></body></html>`))
	}
}

// opChainRe matches an operator-chaining breakout (decoded) carrying our marker.
var opChainRe = regexp.MustCompile("[\\^*/+-]alert\\(`(vigx[0-9a-f]+)`\\)[\\^*/+-]")

// expressionContextProbe models a browser on an expression-context page: it fires
// the alert ONLY when navigated with an operator-chaining payload, and stays
// silent for the statement-terminator form (which would SyntaxError in-browser).
func expressionContextProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	decoded, err := url.QueryUnescape(cfg.URL)
	if err != nil {
		decoded = cfg.URL
	}
	mm := opChainRe.FindStringSubmatch(decoded)
	if len(mm) < 2 {
		return &spitolas.ProbeResult{}, nil
	}
	return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: mm[1]}}}, nil
}

func TestParamDiscovery_OperatorChainingConfirmsExpressionContext(t *testing.T) {
	// The reflection is inside a JS expression where only operator chaining runs.
	// The old terminator-only confirm payload could never pop this; the new
	// operator-chaining candidates must drive it to a browser-confirmed High.
	res := scanParamDiscovery(t, jsExprHandler(), expressionContextProbe)
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	f := res[0]
	if f.severity != severity.High || f.confidence != severity.Certain {
		t.Fatalf("expected browser-confirmed High/Certain, got %s/%s", f.severity, f.confidence)
	}
	if !strings.Contains(f.description, "browser-confirmed") {
		t.Errorf("description should note browser confirmation: %q", f.description)
	}
}

func TestParamDiscovery_ReflectionOnly_LowWhenNoPopup(t *testing.T) {
	// Raw reflection survives (HTTP breakout) but the page never pops a dialog,
	// mirroring a CSP-locked Salesforce Aura response. Must downgrade to Low.
	res := scanParamDiscovery(t, jsStringHandler(nil), blockedProbe)
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	f := res[0]
	if f.severity != severity.Low {
		t.Errorf("expected Low severity when the popup is not confirmed, got %s", f.severity)
	}
	if f.confidence != severity.Tentative {
		t.Errorf("expected Tentative confidence, got %s", f.confidence)
	}
	if !strings.Contains(f.description, "reflection-only") {
		t.Errorf("description should flag reflection-only: %q", f.description)
	}
}

func TestParamDiscovery_DroppedWhenPayloadFiltered(t *testing.T) {
	// The app passes the bare canary characters (so the per-char heuristic flags
	// it) but strips the keywords a real payload needs. The executable signature
	// never survives, so the finding must be dropped entirely — no Low, no High.
	stripKeywords := func(s string) string {
		for _, kw := range []string{"alert", "onload", "onerror"} {
			s = strings.ReplaceAll(s, kw, "")
		}
		return s
	}
	res := scanParamDiscovery(t, jsStringHandler(stripKeywords), executingProbe)
	if len(res) != 0 {
		t.Fatalf("expected the reflection-only false positive to be dropped, got %d findings: %+v", len(res), res)
	}
}

func TestParamDiscovery_LowWhenNoBrowserAvailable(t *testing.T) {
	// Probe returns nil result + error (browser unavailable). HTTP breakout still
	// holds, so we report Low rather than dropping or claiming High.
	failing := func(_ context.Context, _ spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return nil, context.DeadlineExceeded
	}
	res := scanParamDiscovery(t, jsStringHandler(nil), failing)
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].severity != severity.Low {
		t.Errorf("expected Low when no browser is available, got %s", res[0].severity)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for the payload/signature mapping
// ---------------------------------------------------------------------------

func TestExecContextPayload_SignaturesAreSubstringsOfPayload(t *testing.T) {
	contexts := []ReflectionContext{
		HTMLGeneric, HTMLTagCloseAndInject, XMLGeneric,
		HTMLAfterTitleClose, HTMLAfterXMPClose, HTMLAfterNoscriptClose,
		HTMLAttributeValueDQBreakout, HTMLAttributeValueSQBreakout,
		HTMLAttributeValueBTBreakout, HTMLAttributeValueUnquotedBreakout,
		HTMLAttributeName,
		JSStringDQBreakout, JSStringSQBreakout, JSTemplateLiteral, JSCodeStatement,
		JSInEventHandlerDQ, JSInURLAttributeSQ,
		HTMLCommentBreakout, JSLineComment, JSBlockComment,
	}
	const marker = "vigxdeadbeef"
	for _, rc := range contexts {
		cands := execContextCandidates(rc, marker)
		if len(cands) == 0 {
			t.Errorf("%s: no candidates", rc)
		}
		for _, cand := range cands {
			if cand.payload == "" {
				t.Errorf("%s: empty payload", rc)
			}
			if !strings.Contains(cand.payload, marker) {
				t.Errorf("%s: payload missing marker: %q", rc, cand.payload)
			}
			if len(cand.signatures) == 0 {
				t.Errorf("%s: no signatures for %q", rc, cand.payload)
			}
			// Every signature must be a literal substring of the sent payload — else
			// the body check could never confirm a faithful reflection.
			for _, s := range cand.signatures {
				if !strings.Contains(cand.payload, s) {
					t.Errorf("%s: signature %q is not contained in payload %q", rc, s, cand.payload)
				}
			}
		}
	}
}

// TestExecContextCandidates_JSStringHasOperatorChaining locks in the fix: the
// JS-string contexts must offer operator-chaining breakouts ('^alert()^',
// '-alert()-'), not only the statement-terminator form, so a reflection sitting
// inside a JS expression can still be confirmed.
func TestExecContextCandidates_JSStringHasOperatorChaining(t *testing.T) {
	const marker = "vigxfeedface"
	cases := map[ReflectionContext]string{
		JSStringSQBreakout: "'",
		JSStringDQBreakout: `"`,
	}
	for rc, q := range cases {
		cands := execContextCandidates(rc, marker)
		var hasXOR, hasMinus, hasTerm bool
		for _, c := range cands {
			switch {
			case strings.HasPrefix(c.payload, q+"^"):
				hasXOR = true
			case strings.HasPrefix(c.payload, q+"-"):
				hasMinus = true
			case strings.HasPrefix(c.payload, q+";"):
				hasTerm = true
			}
		}
		if !hasXOR || !hasMinus {
			t.Errorf("%s: expected operator-chaining payloads (xor=%v minus=%v) in %d candidates", rc, hasXOR, hasMinus, len(cands))
		}
		if !hasTerm {
			t.Errorf("%s: expected the statement-terminator fallback to remain", rc)
		}
		// Operator chaining is most general, so it must be tried first.
		if len(cands) > 0 && !strings.HasPrefix(cands[0].payload, q+"^") {
			t.Errorf("%s: expected XOR chaining first, got %q", rc, cands[0].payload)
		}
	}
}

func TestPrefixByName(t *testing.T) {
	if got := prefixByName("none"); got.Name != "none" {
		t.Errorf("prefixByName(none) = %q", got.Name)
	}
	if got := prefixByName("crlf"); got.Name != "crlf" {
		t.Errorf("prefixByName(crlf) = %q", got.Name)
	}
	// Unknown falls back to the no-prefix variant.
	if got := prefixByName("does-not-exist"); got.Name != "none" {
		t.Errorf("prefixByName(unknown) fallback = %q, want none", got.Name)
	}
}

func TestDistinctContexts(t *testing.T) {
	analyses := []*EscapeAnalysis{
		{Context: JSStringDQBreakout},
		{Context: JSStringDQBreakout},
		{Context: HTMLGeneric},
		nil,
		{Context: HTMLAttributeValueDQBreakout},
		{Context: JSCodeStatement},
	}
	got := distinctContexts(analyses, maxConfirmContexts)
	if len(got) != maxConfirmContexts {
		t.Fatalf("expected %d distinct contexts, got %d (%v)", maxConfirmContexts, len(got), got)
	}
	if got[0] != JSStringDQBreakout || got[1] != HTMLGeneric || got[2] != HTMLAttributeValueDQBreakout {
		t.Errorf("unexpected dedup/order: %v", got)
	}
}
