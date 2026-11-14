package core

import (
	"context"
	"sync"
	"testing"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// typeRecorder is a per-insertion-point module that records the point types it
// was handed.
type typeRecorder struct {
	activeStub
	types modules.InsertionPointTypeSet
	mu    sync.Mutex
	seen  map[httpmsg.InsertionPointType]int
}

func (m *typeRecorder) AllowedInsertionPointTypes() modules.InsertionPointTypeSet { return m.types }

func (m *typeRecorder) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.mu.Lock()
	m.seen[ip.Type()]++
	m.mu.Unlock()
	return nil, nil
}

// Parameter-name and entire-body points reach only modules that opt in:
// a module on AllInsertionPointTypes never sees them, one that adds
// ParamNameTypes / EntireBodyTypes does.
func TestExtraInsertionPointsAreOptIn(t *testing.T) {
	names := &typeRecorder{
		activeStub: activeStub{id: "names", scopes: modules.ScanScopeInsertionPoint, canProc: true},
		types:      modkit.AllInsertionPointTypes | modkit.ParamNameTypes | modkit.EntireBodyTypes,
		seen:       map[httpmsg.InsertionPointType]int{},
	}
	plain := &typeRecorder{
		activeStub: activeStub{id: "plain", scopes: modules.ScanScopeInsertionPoint, canProc: true},
		types:      modkit.AllInsertionPointTypes,
		seen:       map[httpmsg.InsertionPointType]int{},
	}

	raw := "POST /p?q=1 HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=b"
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("x.test", 80, false), []byte(raw))
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nok")))

	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, &sliceSource{}, []modules.ActiveModule{names, plain}, nil)
	e.processItem(context.Background(), work.NewWithModules(rr, nil))

	for _, ty := range []httpmsg.InsertionPointType{httpmsg.INS_PARAM_NAME_URL, httpmsg.INS_PARAM_NAME_BODY, httpmsg.INS_ENTIRE_BODY} {
		if names.seen[ty] == 0 {
			t.Errorf("opted-in module never got type %s", ty)
		}
		if plain.seen[ty] != 0 {
			t.Errorf("AllInsertionPointTypes module got opt-in type %s", ty)
		}
	}
	if plain.seen[httpmsg.INS_PARAM_URL] == 0 {
		t.Error("plain module lost its value points")
	}
}
