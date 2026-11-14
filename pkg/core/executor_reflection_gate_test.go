package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

type reflectionStub struct {
	activeStub
	calls atomic.Int64
}

func (m *reflectionStub) AllowedInsertionPointTypes() modules.InsertionPointTypeSet {
	return modkit.NewInsertionPointTypeSet(httpmsg.INS_PARAM_URL)
}
func (m *reflectionStub) RequiresReflection() modkit.ReflectionNeed { return modkit.ReflectBody }
func (m *reflectionStub) ScanPerInsertionPoint(*httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.calls.Add(1)
	return nil, nil
}

// A reflection-aware module runs on a point only when the shared canary probe
// saw the value come back; a blocked probe fails open (ECON-2).
func TestReflectionGate(t *testing.T) {
	run := func(handler http.HandlerFunc) int64 {
		srv := httptest.NewServer(handler)
		defer srv.Close()
		mod := &reflectionStub{activeStub: activeStub{id: "refl", scopes: modules.ScanScopeInsertionPoint, canProc: true}}
		e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true, HTTPRequester: modtest.Requester(t)},
			&sliceSource{}, []modules.ActiveModule{mod}, nil)
		rr := modtest.Response(modtest.Request(t, srv.URL+"/s?q=hello"), "text/html", "ok")
		e.processItem(context.Background(), work.NewWithModules(rr, nil))
		return mod.calls.Load()
	}

	if n := run(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>") }); n != 1 {
		t.Errorf("reflected point: module ran %d times, want 1", n)
	}
	if n := run(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "<p>static</p>") }); n != 0 {
		t.Errorf("non-reflected point: module ran %d times, want 0", n)
	}
	if n := run(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }); n != 1 {
		t.Errorf("blocked probe must fail open: module ran %d times, want 1", n)
	}
}
