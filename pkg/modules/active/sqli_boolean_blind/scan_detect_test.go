package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const (
	truePage  = "<html><body>Product: Deluxe Widget — in stock. SKU present. A fine widget for all your needs, with many words to make this page substantial.</body></html>"
	falsePage = "<html><body>No product found.</body></html>"
	errorPage = "<html><body>SQL syntax error near unexpected token; the query was aborted by the database engine.</body></html>"
)

var (
	condRe    = regexp.MustCompile(`(AND|OR)\s+(\d+)\s*(=|<>)\s*(\d+)`)
	invalidRe = regexp.MustCompile(`AND\s+\d+\s+\d+`)
)

// evalBool simulates a numeric SQL boolean sink: SELECT ... WHERE id=<value>.
// The base row (id starting "1") exists, so an AND-combined truth value gates
// whether the product page renders; a malformed expression yields a SQL error.
func evalBool(raw string) string {
	v := raw
	for _, c := range []string{"-- -", "--", "#"} {
		if i := strings.Index(v, c); i >= 0 {
			v = v[:i]
		}
	}
	v = strings.TrimSpace(v)
	baseTrue := strings.HasPrefix(v, "1")

	if invalidRe.MatchString(v) {
		return errorPage
	}
	mm := condRe.FindStringSubmatch(v)
	if mm == nil {
		if baseTrue {
			return truePage
		}
		return falsePage
	}
	logic, x, cmp, y := mm[1], mm[2], mm[3], mm[4]
	cmpRes := x == y
	if cmp == "<>" {
		cmpRes = x != y
	}
	res := baseTrue && cmpRes
	if logic == "OR" {
		res = baseTrue || cmpRes
	}
	if res {
		return truePage
	}
	return falsePage
}

func boolVulnerableHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}
}

// TestScanPerRequest_DetectsBooleanSQLi drives the full scan against a boolean
// sink and requires a confirmed finding.
func TestScanPerRequest_DetectsBooleanSQLi(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(boolVulnerableHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a boolean-blind SQLi finding against a boolean sink")
	assert.Equal(t, "id", res[0].FuzzingParameter)
}

// TestScanPerRequest_NoFalsePositive_Static ensures a constant page never yields
// a finding (TRUE/FALSE never diverge).
func TestScanPerRequest_NoFalsePositive_Static(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static page must not yield a boolean-blind finding")
}

// TestScanPerRequest_NoFalsePositive_DynamicNoise ensures a page that varies
// per request (independent of the payload) does not trip detection — the
// difflib ratio collapses the dynamic token and the multi-round confirmation
// would reject any residual differential.
func TestScanPerRequest_NoFalsePositive_DynamicNoise(t *testing.T) {
	t.Parallel()
	var counter int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		counter++
		// A long varying digit run (collapsed by the normalizer) plus otherwise
		// identical content — simulates timestamps/counters, not SQL behavior.
		_, _ = fmt.Fprintf(w, "%s<!-- req 100%05d -->", truePage, counter)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "dynamic-but-payload-independent noise must not yield a finding")
}

// TestScanPerRequest_NoFalsePositive_StatusFlip is the key regression: a sink
// whose FALSE branch returns a 3xx redirect (different status, not 200) must
// NOT be reported, even though the bodies differ — a status flip is a classic
// boolean-blind false positive.
func TestScanPerRequest_NoFalsePositive_StatusFlip(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Behaves like a boolean sink but emits a 302 (with a small body) for the
		// FALSE branch instead of a 200 no-row page.
		if evalBool(r.URL.Query().Get("id")) == falsePage {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200↔302 status-flip differential must not be reported")
}

// TestScanPerRequest_NoFalsePositive_SmallDiff ensures a tiny TRUE/FALSE body
// difference (below the substantial-size gate) is not reported.
func TestScanPerRequest_NoFalsePositive_SmallDiff(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same large page for both branches, differing by only a few bytes.
		if evalBool(r.URL.Query().Get("id")) == falsePage {
			_, _ = fmt.Fprint(w, truePage+" .")
			return
		}
		_, _ = fmt.Fprint(w, truePage)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a tiny body-size differential must not be reported")
}

// TestScanPerRequest_WAFEvasion confirms detection still works when the sink
// drops plain payloads (spaces) but accepts comment-spaced ones, given a WAF
// was recorded for the host.
func TestScanPerRequest_WAFEvasion(t *testing.T) {
	t.Parallel()
	// This sink emulates a WAF that signatures exact-uppercase SQL keywords:
	// any value containing "AND"/"OR"/"UNION" is blocked (403). Only the
	// case-flipped mutator (AnD/oR) evades it. Allowed values are evaluated
	// case-insensitively as a boolean sink.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Contains(v, "AND") || strings.Contains(v, "OR") || strings.Contains(v, "UNION") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "blocked by WAF")
			return
		}
		_, _ = fmt.Fprint(w, evalBool(strings.ToUpper(v)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	// Without a recorded WAF, plain payloads are blocked → no finding.
	scNoWAF := &modkit.ScanContext{}
	res, err := New().ScanPerRequest(rr, client, scNoWAF)
	require.NoError(t, err)
	assert.Empty(t, res, "plain payloads should be blocked, yielding no finding")

	// With a recorded WAF, comment-spaced variants get through and confirm.
	sc := &modkit.ScanContext{WAFStack: modkit.NewWAFRegistry()}
	urlx, _ := rr.URL()
	sc.MarkWAF(urlx.Host, "generic")
	res, err = New().ScanPerRequest(modtest.Request(t, srv.URL+"/item?id=1"), client, sc)
	require.NoError(t, err)
	require.NotEmpty(t, res, "WAF-evasion variants should detect the boolean sink")
}

// TestConfirmLogic_Confirms exercises the multi-factor battery directly on a
// boolean sink: every factor (AND/OR oracle, multi-round, comparison-operator
// variation, invalid-syntax probe) is satisfied.
func TestConfirmLogic_Confirms(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(boolVulnerableHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	ok, err := New().confirmLogic(rr, client, ip, "1", "", "-- -")
	require.NoError(t, err)
	assert.True(t, ok, "boolean sink should pass the logic battery")
}

// TestConfirmLogic_RejectsValidityIgnorer ensures the invalid-syntax factor
// rejects an endpoint that renders the same page regardless of SQL validity.
func TestConfirmLogic_RejectsValidityIgnorer(t *testing.T) {
	t.Parallel()
	// This sink evaluates all valid boolean conditions correctly (so the
	// divergence, multi-round and comparison-operator factors all pass) but
	// never raises an error on malformed SQL — it renders the TRUE page instead.
	// Only the invalid-syntax factor can catch this as a false positive.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if invalidRe.MatchString(v) {
			_, _ = fmt.Fprint(w, truePage) // ignores SQL validity
			return
		}
		_, _ = fmt.Fprint(w, evalBool(v))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	ok, err := New().confirmLogic(rr, client, ip, "1", "", "-- -")
	require.NoError(t, err)
	assert.False(t, ok, "an endpoint that ignores SQL validity must be rejected")
}
