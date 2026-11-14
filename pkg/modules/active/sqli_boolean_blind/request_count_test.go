package sqli_boolean_blind

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const staticPage = "<html><body><h1>Catalogue</h1><p>Some stable content that does not change.</p></body></html>"

// The step-1 baseline is fetched once per record, not once per insertion
// point (ECON-6): three parameters, one unmodified request.
func TestRecordBaselineFetchedOncePerRecord(t *testing.T) {
	const original = "a=1&b=2&c=3"
	var unmodified atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == original {
			unmodified.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(staticPage))
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/list?"+original)
	// Query points only, so the unmodified query identifies baseline requests
	// (header points keep the query unchanged).
	sc := &modkit.ScanContext{InsertionPoints: queryOnlyProvider{}}
	_, err := New().ScanPerRequest(rr, modtest.Requester(t), sc)
	require.NoError(t, err)
	require.Equal(t, int64(1), unmodified.Load(), "unmodified baseline requests")
}

// After maxConsecutiveBlockedPairs blocked plain pairs the rest of the plain
// pairs are skipped (ECON-6).
func TestBlockedPairsStopEarly(t *testing.T) {
	var payloadPairs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q["id"]) == 1 && q.Get("id") != "1" {
			if q.Get("id") != "1"+hppBlockProbe { // the HPP fallback's gate probe
				payloadPairs.Add(1)
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked"))
			return
		}
		if len(q["id"]) > 1 { // HPP fallback channels
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked"))
			return
		}
		_, _ = w.Write([]byte(staticPage))
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/item?id=1")
	_, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	plain := len(getPayloadsForValue("1"))
	require.Greater(t, plain, maxConsecutiveBlockedPairs, "fixture assumes more plain pairs than the cutoff")
	// Each tested pair sends TRUE and FALSE.
	if got := payloadPairs.Load(); got > int64(2*maxConsecutiveBlockedPairs) {
		t.Fatalf("payload requests = %d, want <= %d (stop after %d blocked pairs; %d plain pairs exist)",
			got, 2*maxConsecutiveBlockedPairs, maxConsecutiveBlockedPairs, plain)
	}
}

// queryOnlyProvider hands modules only the URL query value points.
type queryOnlyProvider struct{}

func (queryOnlyProvider) GetInsertionPoints(raw []byte, _ string, nested bool) ([]httpmsg.InsertionPoint, error) {
	pts, err := httpmsg.CreateAllInsertionPoints(raw, nested)
	if err != nil {
		return nil, err
	}
	var out []httpmsg.InsertionPoint
	for _, p := range pts {
		if p.Type() == httpmsg.INS_PARAM_URL {
			out = append(out, p)
		}
	}
	return out, nil
}
