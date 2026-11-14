package network

import (
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// MISS-29b: a slow response-body fetch runs on the worker pool, so the event
// goroutine (onLoadingFinished) returns at once and later responses are not
// held behind it; every entry is still written by Close.
func TestBodyFetchOffEventLoop(t *testing.T) {
	mock := &mockWriter{}
	release := make(chan struct{})
	const sess = proto.TargetSessionID("worker-1")
	c := &Capture{
		writer:              mock,
		browser:             rod.New(),
		logged:              make(map[string]struct{}),
		seenHashes:          make(map[string]bool),
		shapeVariants:       make(map[string]int),
		maxParamVariants:    3,
		noColor:             true,
		silent:              true,
		includeResponseBody: true,
		workerSessions:      map[proto.TargetSessionID]struct{}{sess: {}},
		pending:             make(map[proto.NetworkRequestID]*pendingEntry),
	}
	c.bodyFetcher = func(proto.TargetSessionID, proto.NetworkRequestID) ([]byte, error) {
		<-release
		return []byte("body"), nil
	}
	c.startBodyWorkers()

	for i, u := range []string{"https://app.test/a", "https://app.test/b"} {
		id := proto.NetworkRequestID(rune('a' + i))
		e := createTestEntry(u)
		e.Response = &ResponseData{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}}
		c.pending[id] = &pendingEntry{entry: e, sessionID: sess, startTime: time.Now()}
		start := time.Now()
		c.onLoadingFinished(&proto.NetworkLoadingFinished{RequestID: id}, sess)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Fatalf("onLoadingFinished blocked %v on a slow body fetch", d)
		}
	}
	if n := mock.getWriteCount(); n != 0 {
		t.Fatalf("written before the bodies arrived: %d", n)
	}
	close(release)
	c.stopBodyWorkers()
	if n := mock.getWriteCount(); n != 2 {
		t.Errorf("written = %d, want 2 after the pool drained", n)
	}
}
