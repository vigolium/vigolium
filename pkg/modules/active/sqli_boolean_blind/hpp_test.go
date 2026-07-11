package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// sqlMetaRe flags a value that looks like SQL injection — a quote, comment, or a
// boolean keyword/comparison. A simulated front-end filter uses it to reject the
// FIRST occurrence of the parameter.
var sqlMetaRe = regexp.MustCompile(`(?i)('|--|#|\bAND\b|\bOR\b|\bUNION\b|\bSELECT\b|=)`)

// idValues returns every value of the ?id query parameter in wire order, so the
// handler can distinguish which occurrence a duplicate carries.
func idValues(r *http.Request) []string { return r.URL.Query()["id"] }

// hppSplitHandler simulates a proxy/backend parser split: a front-end WAF
// inspects the FIRST occurrence of ?id and blocks anything SQL-ish — so a plain
// single-parameter probe is rejected and the normal path is inconclusive — while
// the backend boolean sink evaluates the LAST occurrence. Only a payload-last
// duplicate (id=benign&id=payload) slips the benign value past the filter and
// reaches the oracle, which is exactly what HTTP Parameter Pollution delivers.
func hppSplitHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vals := idValues(r)
		var first, last string
		if len(vals) > 0 {
			first, last = vals[0], vals[len(vals)-1]
		}
		if sqlMetaRe.MatchString(first) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "blocked by WAF")
			return
		}
		_, _ = fmt.Fprint(w, evalBool(last))
	}
}

// hppFilteredEchoHandler blocks SQL-ish first occurrences (like a WAF) and
// accepts benign duplicates cleanly, but the backend has NO boolean sink: it
// returns a constant page regardless of the last value. HPP fully engages (every
// gate passes) yet must produce NO finding, because no TRUE/FALSE differential
// exists — proving the pollution fallback keeps the confirmation bar intact.
func hppFilteredEchoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vals := idValues(r)
		var first string
		if len(vals) > 0 {
			first = vals[0]
		}
		if sqlMetaRe.MatchString(first) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "blocked by WAF")
			return
		}
		_, _ = fmt.Fprint(w, truePage) // constant — no boolean logic on the last value
	}
}

// TestScanPerRequest_DetectsBooleanSQLi_ViaHPP is the key HPP regression: the
// plain single-parameter probe is blocked (front-end filter), so the normal path
// is inconclusive, but a payload-last duplicate reaches the boolean oracle. The
// scan must produce a confirmed finding carrying the HPP bypass metadata.
func TestScanPerRequest_DetectsBooleanSQLi_ViaHPP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(hppSplitHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a boolean-blind SQLi finding delivered via HTTP Parameter Pollution")

	f := res[0]
	assert.Equal(t, "id", f.FuzzingParameter)
	require.NotNil(t, f.Metadata, "HPP finding must carry annotation metadata")
	assert.Equal(t, "http-parameter-pollution", f.Metadata["bypass-strategy"])
	assert.NotEmpty(t, f.Metadata["duplicate-ordering"], "HPP finding must record the working duplicate ordering")
	assert.NotEmpty(t, f.Metadata["channels"], "HPP finding must record the polluted channel(s)")

	// The bypass rationale is recorded in the evidence for reviewers.
	var sawEvidence bool
	for _, e := range f.AdditionalEvidence {
		if regexp.MustCompile(`(?i)parameter pollution`).MatchString(e) {
			sawEvidence = true
			break
		}
	}
	assert.True(t, sawEvidence, "HPP finding must include a parameter-pollution evidence line")
}

// TestScanPerRequest_NoFalsePositive_HPPDuplicateEcho ensures that a
// duplicate-accepting endpoint which filters plain payloads but has no boolean
// sink does NOT yield a finding, even though the HPP fallback fully engages.
func TestScanPerRequest_NoFalsePositive_HPPDuplicateEcho(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(hppFilteredEchoHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a duplicate-accepting endpoint with no boolean sink must not yield a finding")
}
