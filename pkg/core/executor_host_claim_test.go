package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// perHostScripted is a per-host active module whose n-th call returns errs[n]
// (nil past the end).
type perHostScripted struct {
	activeStub
	calls atomic.Int32
	errs  []error
}

func (m *perHostScripted) ScanPerHost(*httpmsg.HttpRequestResponse, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	n := int(m.calls.Add(1)) - 1
	if n < len(m.errs) {
		return nil, m.errs[n]
	}
	return nil, nil
}

func runPerHostItems(t *testing.T, mod modules.ActiveModule, n int) {
	t.Helper()
	items := make([]*work.WorkItem, n)
	for i := range items {
		items[i], _ = makeTestItem("claims.test", fmt.Sprintf("/p%d", i), "ok")
	}
	// processItem waits for the item's tasks, so each item's per-host run has
	// finished (and released or kept its claim) before the next item.
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, &sliceSource{}, []modules.ActiveModule{mod}, nil)
	for _, it := range items {
		e.processItem(context.Background(), it)
	}
}

// A per-host run that failed transiently (quarantined host, transport error,
// abandoned request) gives its claim back, so a later item for the same origin
// retries it — at most twice in total (MISS-19). Before, the claim was taken
// before the run and never released: one transient failure skipped the module
// for the origin for the rest of the scan.
func TestPerHostClaimReleasedOnTransientFailure(t *testing.T) {
	mod := &perHostScripted{
		activeStub: activeStub{id: "perhost-retry", scopes: modules.ScanScopeHost, canProc: true},
		errs:       []error{fmt.Errorf("probe: %w", hosterrors.ErrUnresponsiveHost)},
	}
	runPerHostItems(t, mod, 4)
	if got := mod.calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (failed once transiently, retried once, then claimed)", got)
	}

	always := &perHostScripted{
		activeStub: activeStub{id: "perhost-dead", scopes: modules.ScanScopeHost, canProc: true},
		errs: []error{protohttp.ErrRequestAbandoned, protohttp.ErrRequestAbandoned,
			protohttp.ErrRequestAbandoned, protohttp.ErrRequestAbandoned, protohttp.ErrRequestAbandoned},
	}
	runPerHostItems(t, always, 5)
	if got := always.calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (bounded retries)", got)
	}

	// A module error that is not transient keeps the claim.
	plain := &perHostScripted{
		activeStub: activeStub{id: "perhost-bug", scopes: modules.ScanScopeHost, canProc: true},
		errs:       []error{errors.New("parse failure")},
	}
	runPerHostItems(t, plain, 3)
	if got := plain.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 (non-transient error keeps the claim)", got)
	}
}
