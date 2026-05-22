package struts_ognl_injection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// ognlExpr is the multiplication the module injects; a vulnerable server
// evaluates it and the product (ognlResult) surfaces in the response.
const ognlExpr = "41273*39127"

// TestScanPerInsertionPoint_DetectsParamOGNL drives the parameter-level scan
// against a server that evaluates an OGNL expression supplied in a query param
// (CVE-2017-5638 / Struts2 style) and echoes the arithmetic result into the
// body. Seeing the product (1614244871) confirms expression evaluation.
func TestScanPerInsertionPoint_DetectsParamOGNL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(v, ognlExpr) {
			_, _ = w.Write([]byte("Welcome " + ognlResult))
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
		if strings.Contains(ct, ognlExpr) {
			_, _ = w.Write([]byte("evaluated: " + ognlResult))
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
