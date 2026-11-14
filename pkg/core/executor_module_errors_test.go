package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// lockedBuffer is a bytes.Buffer safe for the emitter's writes and the test's
// read.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureEvents installs a process emitter writing to a buffer for the test's
// duration. Tests using it must not be parallel: the emitter is process-global.
func captureEvents(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(buf, "scan-f6"))
	t.Cleanup(func() { scanevents.Install(prev) })
	return buf
}

// moduleErrorEvents returns the module.error events for moduleID.
func moduleErrorEvents(t *testing.T, buf *lockedBuffer, moduleID string) []scanevents.Event {
	t.Helper()
	var out []scanevents.Event
	sc := bufio.NewScanner(bytes.NewBufferString(buf.String()))
	for sc.Scan() {
		var ev scanevents.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", sc.Text(), err)
		}
		if ev.Type == scanevents.TypeModuleError && ev.ModuleID == moduleID {
			out = append(out, ev)
		}
	}
	return out
}

func eventCounts(evs []scanevents.Event) []int64 {
	out := make([]int64, 0, len(evs))
	for _, ev := range evs {
		if ev.Count == nil {
			out = append(out, -1)
			continue
		}
		out = append(out, *ev.Count)
	}
	return out
}

func TestModuleErrorEventsRateLimited(t *testing.T) {
	buf := captureEvents(t)
	e, _ := newTestExecutor(ExecutorConfig{Phase: "dynamic-assessment"}, nil)
	mod := &trackingPassiveModule{id: "ext-boom"}
	_, item := makeTestItem("example.com", "/x", "<html>x</html>")

	failing := func(context.Context) ([]*output.ResultEvent, error) {
		return nil, errors.New("TypeError: cannot read property 'x' of undefined")
	}
	for i := 0; i < 205; i++ {
		if got := e.runPassiveWithTimeout(context.Background(), failing, mod, item); got != nil {
			t.Fatalf("a failed call must drop its events, got %d", len(got))
		}
	}

	evs := moduleErrorEvents(t, buf, "ext-boom")
	want := []int64{1, 2, 3, 100, 200}
	got := eventCounts(evs)
	if len(got) != len(want) {
		t.Fatalf("counts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("counts = %v, want %v", got, want)
		}
	}
	first := evs[0]
	if first.ErrorKind != ModuleErrorException {
		t.Errorf("error_kind = %q, want exception", first.ErrorKind)
	}
	if first.Phase != "dynamic-assessment" {
		t.Errorf("phase = %q, want dynamic-assessment", first.Phase)
	}
	if first.URL == "" || first.Message == "" {
		t.Errorf("event should carry url and message, got url=%q message=%q", first.URL, first.Message)
	}
	if n := e.ModuleErrors()["ext-boom"]; n != 205 {
		t.Errorf("ModuleErrors()[ext-boom] = %d, want 205", n)
	}
}

func TestModuleErrorUsesOwnerLedgerTotal(t *testing.T) {
	buf := captureEvents(t)
	var calls []string
	var mu sync.Mutex
	e, _ := newTestExecutor(ExecutorConfig{
		OnModuleError: func(id, kind string) int64 {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, id+"/"+kind)
			// The owner has already seen 99 failures from earlier executors.
			return 99 + int64(len(calls))
		},
	}, nil)
	mod := &trackingPassiveModule{id: "builtin-passive"}
	_, item := makeTestItem("example.com", "/x", "x")
	failing := func(context.Context) ([]*output.ResultEvent, error) { return nil, errors.New("bad") }
	for i := 0; i < 2; i++ {
		e.runPassiveWithTimeout(context.Background(), failing, mod, item)
	}
	if len(calls) != 2 || calls[0] != "builtin-passive/exception" {
		t.Fatalf("OnModuleError calls = %v", calls)
	}
	// Totals 100 and 101: only the 100th is emitted.
	got := eventCounts(moduleErrorEvents(t, buf, "builtin-passive"))
	if len(got) != 1 || got[0] != 100 {
		t.Fatalf("counts = %v, want [100]", got)
	}
}

// hintedPassive asks for an enforced timeout, so the watchdog path runs.
type hintedPassive struct {
	*trackingPassiveModule
	hint time.Duration
}

func (h hintedPassive) TimeoutHint() time.Duration { return h.hint }

var _ modules.TimeoutHinter = hintedPassive{}

func TestModuleErrorKindTimeout(t *testing.T) {
	buf := captureEvents(t)
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	mod := hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "slow-passive"}, hint: 20 * time.Millisecond}
	_, item := makeTestItem("example.com", "/slow", "x")
	release := make(chan struct{})
	defer close(release)
	e.runPassiveWithTimeout(context.Background(), func(context.Context) ([]*output.ResultEvent, error) {
		<-release
		return nil, nil
	}, mod, item)

	evs := moduleErrorEvents(t, buf, "slow-passive")
	if len(evs) != 1 || evs[0].ErrorKind != ModuleErrorTimeout {
		t.Fatalf("want one timeout event, got %+v", evs)
	}

	// The active wrapper's timeout arm, too.
	e2, _ := newTestExecutor(ExecutorConfig{ActiveModuleTimeout: 20 * time.Millisecond}, nil)
	amod := &activeStub{id: "slow-active", canProc: true}
	released := make(chan struct{})
	res := e2.runActiveWithTimeout(context.Background(),
		func(context.Context, *http.Requester) ([]*output.ResultEvent, error) {
			<-release
			return nil, nil
		}, amod, item, nil, func() { close(released) }, 0)
	completed := res.completed
	if completed {
		t.Fatal("the call should have timed out")
	}
	evs = moduleErrorEvents(t, buf, "slow-active")
	if len(evs) != 1 || evs[0].ErrorKind != ModuleErrorTimeout {
		t.Fatalf("want one active timeout event, got %+v", evs)
	}
}

func TestModuleErrorKindPanic(t *testing.T) {
	buf := captureEvents(t)
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	_, item := makeTestItem("example.com", "/boom", "x")

	// Inline passive path: the panic is recovered at the module, not the worker.
	pmod := &trackingPassiveModule{id: "panic-passive"}
	e.runPassiveWithTimeout(context.Background(), func(context.Context) ([]*output.ResultEvent, error) {
		panic("kaboom")
	}, pmod, item)

	// Active watchdog path.
	amod := &activeStub{id: "panic-active", canProc: true}
	released := make(chan struct{})
	e.runActiveWithTimeout(context.Background(),
		func(context.Context, *http.Requester) ([]*output.ResultEvent, error) { panic("boom") },
		amod, item, nil, func() { close(released) }, 0)
	<-released

	for _, id := range []string{"panic-passive", "panic-active"} {
		evs := moduleErrorEvents(t, buf, id)
		if len(evs) != 1 || evs[0].ErrorKind != ModuleErrorPanic {
			t.Fatalf("%s: want one panic event, got %+v", id, evs)
		}
	}
}

func TestModuleErrorKindClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{errors.New("x"), ModuleErrorException},
		{&modulePanicError{moduleID: "m", value: "v"}, ModuleErrorPanic},
		{context.DeadlineExceeded, ModuleErrorTimeout},
	}
	for _, c := range cases {
		if got := moduleErrorKind(c.err); got != c.want {
			t.Errorf("moduleErrorKind(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
