package sqli_time_blind

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/command_injection_timing"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

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

// The timing baseline is measured once per record and shared by every
// insertion point and by both time-based modules (ECON-6): 3 points × 2
// modules used to cost 24 unmodified requests; now TimingBaselineSamples.
func TestTimingBaselineSharedAcrossPointsAndModules(t *testing.T) {
	const original = "a=1&b=2&c=3"
	var unmodified atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == original {
			unmodified.Add(1)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?"+original)
	sc := &modkit.ScanContext{InsertionPoints: queryOnlyProvider{}}

	_, err := New().ScanPerRequest(rr, client, sc)
	require.NoError(t, err)
	_, err = command_injection_timing.New().ScanPerRequest(rr, client, sc)
	require.NoError(t, err)
	require.Equal(t, int64(modkit.TimingBaselineSamples), unmodified.Load())
}
