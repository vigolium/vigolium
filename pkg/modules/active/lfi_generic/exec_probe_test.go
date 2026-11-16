package lfi_generic

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// productRe reads the two operands out of the code a probe carries.
var productRe = regexp.MustCompile(`(\d+)\*(\d+)`)

// evaluate stands in for an interpreter: it computes the product the probe's
// code asks for, or "" when src holds no expression.
func evaluate(src string) string {
	m := productRe.FindStringSubmatch(src)
	if m == nil {
		return ""
	}
	a, _ := strconv.ParseInt(m[1], 10, 64)
	b, _ := strconv.ParseInt(m[2], 10, 64)
	return strconv.FormatInt(a*b, 10)
}

// dataWrapperSource decodes the PHP a data:// payload carries.
func dataWrapperSource(v string) (string, bool) {
	const prefix = "data://text/plain;base64,"
	if !strings.HasPrefix(v, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, prefix))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func scanFile(t *testing.T, handler http.HandlerFunc) []string {
	t.Helper()
	res := scanFileResults(t, handler)
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.VulnClass)
	}
	return out
}

func scanFileResults(t *testing.T, handler http.HandlerFunc) []*resultView {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "file"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	views := make([]*resultView, 0, len(res))
	for _, r := range res {
		views = append(views, &resultView{
			VulnClass: r.VulnClass, Severity: r.Info.Severity, Name: r.Info.Name,
			Extracted: r.ExtractedResults, Request: r.Request, Response: r.Response,
		})
	}
	return views
}

type resultView struct {
	VulnClass string
	Severity  severity.Severity
	Name      string
	Extracted []string
	Request   string
	Response  string
}

// A data:// include that evaluates the PHP prints the product, which the
// request never held: the finding is code execution, not a file read.
func TestExecProbe_DataWrapperEvaluated(t *testing.T) {
	t.Parallel()
	res := scanFileResults(t, func(w http.ResponseWriter, r *http.Request) {
		if src, ok := dataWrapperSource(r.URL.Query().Get("file")); ok {
			_, _ = w.Write([]byte("<html>" + evaluate(src) + "</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>welcome</html>"))
	})
	require.Len(t, res, 1)
	got := res[0]
	assert.Equal(t, execVulnClass, got.VulnClass)
	assert.Equal(t, severity.Critical, got.Severity)
	assert.Contains(t, got.Name, "Code Execution")
	assert.Contains(t, got.Name, execWrapperData)
	require.Len(t, got.Extracted, 2)
	product := got.Extracted[1]
	assert.Contains(t, got.Response, product)
	assert.NotContains(t, got.Request, product, "the product is never sent")
}

// A target that reads the data:// URL as text returns the PHP source, never
// the product: it is a wrapper read (the module's file-read finding), never
// execution.
func TestExecProbe_DataWrapperReadAsTextIsNotExecution(t *testing.T) {
	t.Parallel()
	res := scanFileResults(t, func(w http.ResponseWriter, r *http.Request) {
		if src, ok := dataWrapperSource(r.URL.Query().Get("file")); ok {
			_, _ = w.Write([]byte("<pre>" + src + "</pre>"))
			return
		}
		_, _ = w.Write([]byte("<html>welcome</html>"))
	})
	require.Len(t, res, 1, "a text read of the wrapper is still a stream-wrapper read")
	assert.Empty(t, res[0].VulnClass, "a text read must not be reported as execution")
	assert.Equal(t, severity.Undefined, res[0].Severity, "the read keeps the module's own severity")
}

// The decoded source echoed back with the operands is not the product.
func TestExecProbe_OperandsReflectedIsNotExecution(t *testing.T) {
	t.Parallel()
	classes := scanFile(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"echo":"` + r.URL.Query().Get("file") + `"}`))
	})
	assert.Empty(t, classes, "an endpoint that reflects the probe must yield nothing")
}

// expect:// runs the rest of the URL in a shell; the shell's arithmetic prints
// the product.
func TestExecProbe_ExpectWrapperEvaluated(t *testing.T) {
	t.Parallel()
	res := scanFileResults(t, func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("file"); strings.HasPrefix(v, "expect://echo $((") {
			_, _ = w.Write([]byte(evaluate(v) + "\n"))
			return
		}
		_, _ = w.Write([]byte("<html>welcome</html>"))
	})
	require.Len(t, res, 1)
	assert.Equal(t, execVulnClass, res[0].VulnClass)
	assert.Contains(t, res[0].Name, execWrapperExpect)
}

// php://input includes the request body; the probe puts the PHP there.
func TestExecProbe_PHPInputEvaluated(t *testing.T) {
	t.Parallel()
	res := scanFileResults(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("file") == "php://input" {
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write([]byte(evaluate(string(body))))
			return
		}
		_, _ = w.Write([]byte("<html>welcome</html>"))
	})
	require.Len(t, res, 1)
	assert.Equal(t, execVulnClass, res[0].VulnClass)
	assert.Contains(t, res[0].Name, execWrapperInput)
}

// A confirmed read that also evaluates wrappers is reported once, as
// execution: the probes upgrade the read.
func TestExecProbe_UpgradesConfirmedRead(t *testing.T) {
	t.Parallel()
	passwd := passwdEcho("file")
	res := scanFileResults(t, func(w http.ResponseWriter, r *http.Request) {
		if src, ok := dataWrapperSource(r.URL.Query().Get("file")); ok {
			_, _ = w.Write([]byte(evaluate(src)))
			return
		}
		passwd(w, r)
	})
	require.Len(t, res, 1)
	assert.Equal(t, execVulnClass, res[0].VulnClass)
}

// A read that does not evaluate wrappers stays a read.
func TestExecProbe_ReadWithoutExecutionStaysRead(t *testing.T) {
	t.Parallel()
	res := scanFileResults(t, passwdEcho("file"))
	require.Len(t, res, 1)
	assert.Empty(t, res[0].VulnClass)
	assert.Contains(t, res[0].Response, "root:x:0:0")
}

func TestNewExecProbes(t *testing.T) {
	t.Parallel()
	probes := newExecProbes(randomOperands, true)
	require.Len(t, probes, 3)
	for _, p := range probes {
		assert.GreaterOrEqual(t, p.a, int64(execOperandMin))
		assert.LessOrEqual(t, p.a, int64(execOperandMax))
		assert.Equal(t, strconv.FormatInt(p.a*p.b, 10), p.product)
		assert.NotContains(t, p.payload, p.product, "%s payload must not carry the product", p.wrapper)
		assert.NotContains(t, string(p.body), p.product)
	}
	src, ok := dataWrapperSource(probes[0].payload)
	require.True(t, ok)
	assert.Contains(t, src, injectionMarker, "the reflected-payload guard still recognises our PHP")

	noInput := newExecProbes(randomOperands, false)
	require.Len(t, noInput, 2, "php://input is skipped when the insertion point is in the body")
	for _, p := range noInput {
		assert.NotEqual(t, execWrapperInput, p.wrapper)
	}
}

func TestConfirmExecution(t *testing.T) {
	t.Parallel()
	const product = "80779853376"
	tests := []struct {
		name, data, baseline, request string
		want                          bool
	}{
		{name: "product in response", data: "<b>" + product + "</b>", want: true},
		{name: "product at body edges", data: product, want: true},
		{name: "product already in baseline", data: product, baseline: "id " + product, want: false},
		{name: "product inside a longer number", data: "ts=9" + product + "1", want: false},
		{name: "product in the request", data: product, request: "GET /?x=" + product, want: false},
		{name: "operands only", data: "123456*654321", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, confirmExecution(tc.data, tc.baseline, tc.request, product))
		})
	}
	assert.False(t, confirmExecution("x", "", "", ""), "an empty product never confirms")
}
