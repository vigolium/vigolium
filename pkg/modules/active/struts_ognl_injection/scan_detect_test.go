package struts_ognl_injection

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestOgnlResultMatchesProduct pins the core detection invariant: the marker the
// module searches for must equal the actual product of the operands it injects. A
// prior hardcoded literal (1614244871) did not, so the module looked for a product
// no real target returns. Guarding it prevents that class of silent false negative.
func TestOgnlResultMatchesProduct(t *testing.T) {
	want := strconv.Itoa(ognlMultA * ognlMultB)
	assert.Equal(t, want, ognlResult,
		"ognlResult must equal %d*%d (=%s) so the detector matches a genuinely evaluated expression", ognlMultA, ognlMultB, want)
}

// ognlMulRe matches the N*M expression inside an injected OGNL payload (e.g.
// %{41273*39127}); the test backends use it to emulate a real evaluator so the
// module's fresh-operand reflection-tracking confirmation also evaluates.
var ognlMulRe = regexp.MustCompile(`(\d+)\*(\d+)`)

// evalOGNL returns the product of the first N*M expression found in s, as a
// string, or "" when s carries no such expression — emulating server-side OGNL
// arithmetic evaluation for any operands the module injects.
func evalOGNL(s string) string {
	parts := ognlMulRe.FindStringSubmatch(s)
	if parts == nil {
		return ""
	}
	a, _ := strconv.Atoi(parts[1])
	b, _ := strconv.Atoi(parts[2])
	return strconv.Itoa(a * b)
}

// TestScanPerInsertionPoint_DetectsParamOGNL drives the parameter-level scan
// against a server that evaluates an OGNL expression supplied in a query param
// (CVE-2017-5638 / Struts2 style) and echoes the arithmetic result into the
// body. Seeing the product (1614244871) confirms expression evaluation.
func TestScanPerInsertionPoint_DetectsParamOGNL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		w.WriteHeader(http.StatusOK)
		// Emulate a real OGNL evaluator: compute any injected N*M (so the module's
		// fresh-operand confirmation evaluates too), else echo the raw value.
		if product := evalOGNL(v); product != "" {
			_, _ = w.Write([]byte("Welcome " + product))
			return
		}
		_, _ = w.Write([]byte("Welcome " + v))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?name=guest")
	ip := modtest.InsertionPoint(t, rr, "name")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an OGNL finding when the evaluated product appears in the body")
}

// TestScanPerInsertionPoint_CoincidentalResultDropped is the generic-value false
// positive: the server emits the fixed product (1614244871) regardless of input —
// a static id / old timestamp — and never evaluates any expression. The primary
// match fires, but the reflection-tracking confirmation's fresh products never
// appear, so the candidate is dropped.
func TestScanPerInsertionPoint_CoincidentalResultDropped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// 1614244871 is baked into the page, not produced by evaluating the payload.
		_, _ = w.Write([]byte("order " + ognlResult + " confirmed"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?name=guest")
	ip := modtest.InsertionPoint(t, rr, "name")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "the fixed product appearing in the page by coincidence (no evaluation) must not be flagged")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that reflects the
// raw expression without evaluating it yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the raw value back — the unevaluated expression, never the product.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome " + r.URL.Query().Get("name")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?name=guest")
	ip := modtest.InsertionPoint(t, rr, "name")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that does not evaluate OGNL must not yield a finding")
}

// TestScanPerRequest_DetectsContentTypeOGNL drives the Content-Type header OGNL
// scan against a server that evaluates an OGNL expression supplied in the
// Content-Type header and echoes the arithmetic result into the body.
func TestScanPerRequest_DetectsContentTypeOGNL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		// Emulate a real OGNL evaluator so the fresh-operand confirmation evaluates too.
		if product := evalOGNL(ct); product != "" {
			_, _ = w.Write([]byte("evaluated: " + product))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/struts/action.do")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an OGNL finding when the Content-Type expression product appears in the body")
}

// ognlAddHeaderRe extracts the marker from an addHeader('X-Struts-Test','<marker>')
// OGNL payload so a test backend can emulate genuine evaluation by echoing the
// marker back as a real response header.
var ognlAddHeaderRe = regexp.MustCompile(`addHeader\('` + strutsTestHeader + `','([^']+)'\)`)

// TestScanPerRequest_DetectsHeaderAddOGNL drives the Content-Type scan against a
// server that genuinely evaluates the addHeader() OGNL payload — surfacing the
// injected marker as a real X-Struts-Test RESPONSE HEADER (never in the body). The
// module must confirm via the parsed header and via a fresh-marker re-injection.
func TestScanPerRequest_DetectsHeaderAddOGNL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		// Emulate OGNL res.addHeader(): reflect the injected marker as a real header
		// for whatever value the module (or its fresh-marker confirmation) picks.
		if parts := ognlAddHeaderRe.FindStringSubmatch(ct); parts != nil {
			w.Header().Set(strutsTestHeader, parts[1])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/struts/action.do")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an OGNL finding when the addHeader marker is returned as a real response header")
}

// TestScanPerRequest_ReflectedContentTypeErrorNotFlagged is the Snapchat
// camera-kit / gRPC gateway false positive: a 415 "Content-Type '<payload>' is not
// supported" error echoes the injected Content-Type verbatim into the body AND into
// a Grpc-Message header value. The reflected text carries both "X-Struts-Test" and
// the baked marker (1614888671), yet no OGNL ever ran and no genuine X-Struts-Test
// header exists — so the module must NOT report a finding.
func TestScanPerRequest_ReflectedContentTypeErrorNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		// Reflect the whole Content-Type into a header VALUE and the body, exactly as
		// an API gateway rejecting an unsupported content type does. Never sets a
		// real X-Struts-Test header key and never evaluates the arithmetic.
		w.Header().Set("Grpc-Message", "Content-Type '"+ct+"' is not supported")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_, _ = w.Write([]byte("Content-Type '" + ct + "' is not supported"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/snapchat.cdp.cof.CircumstancesService/targetingQuery")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an error page that reflects the injected Content-Type verbatim must not be flagged as OGNL evaluation")
}

// TestScanPerRequest_NoFalsePositive ensures a server that ignores the
// Content-Type header yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/struts/action.do")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores the Content-Type header must not yield a finding")
}
