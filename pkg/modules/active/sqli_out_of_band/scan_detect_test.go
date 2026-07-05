package sqli_out_of_band

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// fakeOAST is a minimal modkit.OASTProvider that hands out a fixed host and
// records the injection type and each planted payload.
type fakeOAST struct {
	host           string
	injectionTypes []string
	payloads       []string
}

func (f *fakeOAST) GenerateURL(_, _, injectionType, _, _ string) string {
	f.injectionTypes = append(f.injectionTypes, injectionType)
	return f.host
}
func (f *fakeOAST) RecordPayload(_, payload string) { f.payloads = append(f.payloads, payload) }
func (f *fakeOAST) Enabled() bool                   { return true }

// TestScanPerInsertionPoint_PlantsOOBSQLPayloads verifies the module injects the
// per-DBMS out-of-band SQL functions pointing at the unique OAST host, labelled
// with a "sql" injection type so callbacks classify as blind SQL injection.
func TestScanPerInsertionPoint_PlantsOOBSQLPayloads(t *testing.T) {
	t.Parallel()

	const oastHost = "sqlnonce123.oast.example"
	var (
		mu      sync.Mutex
		targets []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.URL.RawQuery)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/items?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")
	oast := &fakeOAST{host: oastHost}

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	assert.Empty(t, res, "OOB SQLi returns no synchronous finding; confirmation is via callback")

	require.NotEmpty(t, oast.injectionTypes)
	for _, it := range oast.injectionTypes {
		assert.Contains(t, it, "sql", "injection type must contain 'sql' so callbacks classify as SQLi")
	}

	// Every DBMS out-of-band function was planted with the OAST host.
	joined := strings.Join(oast.payloads, "\n")
	for _, fn := range []string{"LOAD_FILE", "xp_dirtree", "UTL_INADDR", "UTL_HTTP", "TO PROGRAM"} {
		assert.Contains(t, joined, fn, "expected %s payload", fn)
	}
	assert.Contains(t, joined, oastHost)

	// And the fuzzed requests actually reached the server carrying the host.
	mu.Lock()
	defer mu.Unlock()
	var reached bool
	for _, q := range targets {
		if strings.Contains(q, oastHost) {
			reached = true
			break
		}
	}
	assert.True(t, reached, "expected a fuzzed request carrying the OAST host, got %v", targets)
}

// TestScanPerInsertionPoint_NoOASTNoOp verifies the module is a no-op when OAST
// is unavailable (there is no in-band confirmation path).
func TestScanPerInsertionPoint_NoOASTNoOp(t *testing.T) {
	t.Parallel()
	client := modtest.Requester(t)
	rr := modtest.Request(t, "http://example.com/items?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
