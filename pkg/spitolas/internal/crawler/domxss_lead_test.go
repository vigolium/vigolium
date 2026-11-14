package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// With reflected-parameter candidates in the graph, the crawl stops
// scheduling early enough to leave the DOM-XSS probe min(45s, MaxDuration/10);
// without candidates it runs to the drain grace as before.
func TestShouldTerminateLeavesDOMXSSLead(t *testing.T) {
	c := newTestCrawler(t, 100*time.Second) // lead = 10s
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c.shouldTerminate(ctx) {
		t.Fatal("no candidates: 5s left must keep crawling")
	}

	c.graph.AddState(state.New("http://example.com/search?q=hello", "<p>hello</p>", "<p>hello</p>", 1))
	c.domXssCheckedAt.Store(0) // let the prefilter run again now
	if !c.shouldTerminate(ctx) {
		t.Error("with a reflected candidate, 5s left (< 10s lead) must stop scheduling")
	}

	far, cancelFar := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelFar()
	if c.shouldTerminate(far) {
		t.Error("60s left is outside the lead")
	}
}
