package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// A module that outlives its per-module timeout keeps running — a goroutine
// cannot be killed — but it must stop generating HTTP load the moment the
// executor gives up on it. Before the abandon signal it kept issuing requests
// against the phase-bound requester, stealing per-host concurrency from live
// work to produce findings that are discarded by definition.
func TestRunActiveWithTimeout_AbandonedModuleStopsIssuingRequests(t *testing.T) {
	reqClient := newAbandonTestRequester(t)

	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 50 * time.Millisecond}}
	_, item := makeTestItem("example.com", "/", "ok")

	var (
		abandonedErr atomic.Bool
		loopDone     = make(chan struct{})
		release      = make(chan struct{})
	)

	res := e.runActiveWithTimeout(context.Background(),
		func(_ context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
			// Outlive the timeout, then keep trying to send — exactly what a
			// timed-out module's loop does.
			<-release
			_, _, execErr := client.Execute(item, http.Options{})
			abandonedErr.Store(errors.Is(execErr, http.ErrRequestAbandoned))
			close(loopDone)
			return []*output.ResultEvent{{}}, nil
		},
		&fakeActiveModule{id: "zombie"}, item, reqClient, func() {}, 0)
	got, completed := res.events, res.completed

	if completed {
		t.Fatal("expected completed=false: the module overran its per-module timeout")
	}
	if got != nil {
		t.Fatalf("timed-out module results must be discarded, got %d", len(got))
	}

	// The wrapper has returned, so the abandon context is cancelled. Let the
	// zombie try to send.
	close(release)
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("abandoned module never finished — Execute did not return promptly")
	}
	if !abandonedErr.Load() {
		t.Fatal("an abandoned module's Execute must return ErrRequestAbandoned instead of sending")
	}
}

// The abandon signal must not fire on the normal path: a module that finishes
// inside its timeout keeps a fully working requester throughout.
func TestRunActiveWithTimeout_CompletedModuleNotAbandoned(t *testing.T) {
	reqClient := newAbandonTestRequester(t)

	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 5 * time.Second}}
	_, item := makeTestItem("example.com", "/", "ok")

	want := []*output.ResultEvent{{}}
	var sawAbandon atomic.Bool

	res := e.runActiveWithTimeout(context.Background(),
		func(_ context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
			// No network here: just prove the abandon gate is open. A real send
			// would need a live server, and the gate is checked before dialing.
			_, _, execErr := client.Execute(item, http.Options{})
			sawAbandon.Store(errors.Is(execErr, http.ErrRequestAbandoned))
			return want, nil
		},
		&fakeActiveModule{id: "prompt"}, item, reqClient, func() {}, 0)
	got, completed := res.events, res.completed

	if !completed {
		t.Fatal("expected completed=true for a module inside its timeout")
	}
	if len(got) != 1 {
		t.Fatalf("expected the module's result to survive, got %d", len(got))
	}
	if sawAbandon.Load() {
		t.Fatal("a module still inside its timeout must not be marked abandoned")
	}
}

// newAbandonTestRequester builds a real Requester (the abandon gate lives in
// Execute, so a stub would not exercise it).
func newAbandonTestRequester(t *testing.T) *http.Requester {
	t.Helper()
	opts := types.DefaultOptions()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r, err := http.NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return r
}
