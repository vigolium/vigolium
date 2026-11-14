package harness

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func intPtr(v int) *int { return &v }

func TestAssertionFailure(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name  string
		tc    TestCase
		count int
		err   error
		fail  bool
	}{
		{"strict meets min", TestCase{Assertion: "strict", MinFindings: 1}, 2, nil, false},
		{"strict below min", TestCase{Assertion: "strict", MinFindings: 1}, 0, nil, true},
		{"strict module error", TestCase{Assertion: "strict", MinFindings: 1}, 3, boom, true},
		{"strict exact match", TestCase{Assertion: "strict", MinFindings: 1, ExpectedFindings: intPtr(2)}, 2, nil, false},
		{"strict exact mismatch", TestCase{Assertion: "strict", MinFindings: 1, ExpectedFindings: intPtr(2)}, 3, nil, true},
		{"negative zero", TestCase{Assertion: "negative"}, 0, nil, false},
		{"negative fires", TestCase{Assertion: "negative"}, 1, nil, true},
		{"negative module error", TestCase{Assertion: "negative"}, 0, boom, true},
		{"soft never fails", TestCase{Assertion: "soft", MinFindings: 1}, 0, boom, false},
		{"unknown assertion fails", TestCase{Assertion: "lenient"}, 5, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := AssertionFailure(c.tc, c.count, c.err)
			assert.Equal(t, c.fail, got != "", "AssertionFailure = %q", got)
		})
	}
}

// recordingTB captures Fatalf so the harness's fail-fast path can be asserted
// without failing the real test. Methods the harness does not reach on that
// path are left to the embedded (nil) TB.
type recordingTB struct {
	testing.TB
	fatals []string
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
	runtime.Goexit()
}

func runRecorded(fn func(tb testing.TB)) *recordingTB {
	rec := &recordingTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(rec)
	}()
	<-done
	return rec
}

// An unknown module ID used to log a warning; with every ID stale the case
// ran zero modules and passed. It is now fatal, before any request is sent
// (the infra here has no client, so reaching the network would panic).
func TestRunActiveTestCase_UnknownModuleIsFatal(t *testing.T) {
	tc := TestCase{ID: "stale", Endpoint: "/x", Modules: []string{"no-such-module"}, Assertion: "strict", MinFindings: 1}
	rec := runRecorded(func(tb testing.TB) {
		RunActiveTestCase(tb, tc, "http://127.0.0.1:1", &TestInfra{})
	})
	if assert.Len(t, rec.fatals, 1) {
		assert.Contains(t, rec.fatals[0], "no-such-module")
	}
}

func TestRunPassiveTestCase_UnknownModuleIsFatal(t *testing.T) {
	tc := TestCase{ID: "stale", Endpoint: "/x", Modules: []string{"no-such-passive"}, Assertion: "strict", MinFindings: 1}
	rec := runRecorded(func(tb testing.TB) {
		RunPassiveTestCase(tb, tc, "http://127.0.0.1:1", &TestInfra{})
	})
	if assert.Len(t, rec.fatals, 1) {
		assert.Contains(t, rec.fatals[0], "no-such-passive")
	}
}
