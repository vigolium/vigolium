package core

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// ipRecorder is a per-insertion-point module that records the points it is
// handed and reports a finding carrying its mutated request on each.
type ipRecorder struct {
	activeStub
	mu   sync.Mutex
	seen []string
}

func (m *ipRecorder) CanProcess(*httpmsg.HttpRequestResponse) bool { return true }

func (m *ipRecorder) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.mu.Lock()
	m.seen = append(m.seen, ip.Name())
	m.mu.Unlock()
	return nil, nil
}

func TestRunActivePerIP_InsertionPointFilter(t *testing.T) {
	mod := &ipRecorder{activeStub: activeStub{id: "rec", scopes: modules.ScanScopeInsertionPoint}}
	e := NewExecutor(ExecutorConfig{
		Workers: 1,
		InsertionPointFilter: func(ip httpmsg.InsertionPoint) bool {
			return ip.Type() == httpmsg.INS_PARAM_URL && ip.Name() == "b"
		},
	}, nil, []modules.ActiveModule{mod}, nil)

	_, item := makeTestItem("example.com", "/x?a=1&b=2", "<html></html>")
	elig := computeEligibility(item)
	tr := e.newItemTracker(context.Background(), work.NewWithModules(item, nil), false)
	e.runActivePerInsertionPoint(context.Background(), nil, item, &allModulesFilter, &elig, tr, "")
	tr.done()
	<-tr.finished

	assert.Equal(t, []string{"b"}, mod.seen, "only the point the filter accepts may be scanned")
}

// TestProcessResults_PersistsReplayContext: a per-insertion-point finding
// carries the scanned item's record, the point and the injected value onto the
// findings row.
func TestProcessResults_PersistsReplayContext(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	_, rr := makeTestItem("example.com", "/x?a=1&b=2", "<html>body</html>")
	const originUUID = "origin-record-uuid"
	e.caches.requestUUIDs.Store(rr.Request().ID(), originUUID)

	pts, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	require.NoError(t, err)
	ip := httpmsg.FindInsertionPoint(pts, "URL_PARAM", "b")
	require.NotNil(t, ip)

	mod := &ipRecorder{activeStub: activeStub{id: "rec", scopes: modules.ScanScopeInsertionPoint}}
	e.processResults(ctx, []*output.ResultEvent{{
		URL:      "https://example.com/x?a=1&b=evil",
		Request:  string(ip.BuildRequest([]byte("evil'\""))),
		Response: "HTTP/1.1 200 OK\r\n\r\nzzz",
	}}, mod, rr, ip)

	findings := loadFindings(t, db)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, originUUID, f.OriginRecordUUID)
	require.NotNil(t, f.InsertionPoint)
	assert.Equal(t, "URL_PARAM", f.InsertionPoint.Type)
	assert.Equal(t, "b", f.InsertionPoint.Name)
	assert.Equal(t, "evil'\"", f.Payload)
}

// TestProcessResults_ReplayContextKeepsModuleValues: a module that names
// another point keeps it, and no payload is derived for the wrong point.
func TestProcessResults_ReplayContextKeepsModuleValues(t *testing.T) {
	e := &Executor{caches: scanCaches{requestUUIDs: newShardedMap(1)}}
	_, rr := makeTestItem("example.com", "/x?a=1&b=2", "")
	pts, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	require.NoError(t, err)
	ip := httpmsg.FindInsertionPoint(pts, "URL_PARAM", "b")

	r := &output.ResultEvent{FuzzingParameter: "a", Request: string(ip.BuildRequest([]byte("x")))}
	e.setReplayContext(r, rr, ip)
	assert.Equal(t, "a", r.FuzzingParameter)
	assert.Empty(t, r.InsertionPointType)
	assert.Empty(t, r.Payload)

	r = &output.ResultEvent{}
	e.setReplayContext(r, rr, ip)
	assert.Equal(t, "b", r.FuzzingParameter)
	assert.Equal(t, "URL_PARAM", r.InsertionPointType)
	assert.Empty(t, r.Payload, "an unmodified request carries no payload")
}
