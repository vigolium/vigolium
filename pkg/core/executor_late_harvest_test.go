package core

import (
	"context"
	"sync"
	"testing"
	"time"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// lateModule is a per-request module that takes `delay` and returns one Firm
// finding, optionally marking some of its requests refused.
type lateModule struct {
	activeStub
	delay   time.Duration
	refused bool
}

func (m *lateModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, client *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	time.Sleep(m.delay)
	if m.refused {
		if cs := client.CallStats(); cs != nil {
			cs.Refused.Add(1)
		}
	}
	return []*output.ResultEvent{{
		ModuleID: m.id,
		URL:      item.Target(),
		Info:     output.Info{Name: "late", Severity: severity.Medium, Confidence: severity.Firm},
	}}, nil
}

func runLateModule(t *testing.T, mod *lateModule, timeout time.Duration) []*output.ResultEvent {
	t.Helper()
	var mu sync.Mutex
	var got []*output.ResultEvent
	e := NewExecutor(ExecutorConfig{
		Workers: 1, SkipBaseline: true, ActiveModuleTimeout: timeout,
		HTTPRequester: newAbandonTestRequester(t),
		OnResult: func(r *output.ResultEvent) {
			mu.Lock()
			got = append(got, r)
			mu.Unlock()
		},
	}, &sliceSource{}, []modules.ActiveModule{mod}, nil)
	item, _ := makeTestItem("late.example.test", "/x", "<html>ok</html>")
	e.processItem(context.Background(), item)
	e.pool.taskWG.Wait() // the harvester runs on taskWG
	mu.Lock()
	defer mu.Unlock()
	return got
}

// A call that overran its per-module timeout still delivers what it found
// (MISS-20). It had requests refused after the timeout, so the finding is
// downgraded to Tentative with a note.
func TestLateFindingHarvestedAsTentative(t *testing.T) {
	mod := &lateModule{activeStub: activeStub{id: "late", scopes: modules.ScanScopeRequest, canProc: true},
		delay: 300 * time.Millisecond, refused: true}
	// Timeout 200ms, module needs 300ms: the harvester waits min(timeout, 30s).
	got := runLateModule(t, mod, 200*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("got %d results, want the late finding", len(got))
	}
	if got[0].Info.Confidence != severity.Tentative {
		t.Fatalf("confidence = %v, want Tentative for a late result with refused requests", got[0].Info.Confidence)
	}
	if got[0].Metadata["late_result"] != true {
		t.Fatalf("late finding not marked late_result: %v", got[0].Metadata)
	}
}

// An on-time call without refusals keeps its confidence.
func TestOnTimeFindingKeepsConfidence(t *testing.T) {
	mod := &lateModule{activeStub: activeStub{id: "ontime", scopes: modules.ScanScopeRequest, canProc: true}}
	got := runLateModule(t, mod, 5*time.Second)
	if len(got) != 1 || got[0].Info.Confidence != severity.Firm {
		t.Fatalf("got %+v, want one Firm finding", got)
	}
}
