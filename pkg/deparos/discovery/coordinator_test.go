package discovery

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/testutil"
	"github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
)

// createMockCallbacks creates callbacks with mock HTTP client and analyzer
func createMockCallbacks() *Callbacks {
	reqCache, _ := reqcache.NewHMapCache(&reqcache.Config{Cleanup: true})
	return &Callbacks{
		HTTPClient:   testutil.NewMockHTTPClient(),
		Analyzer:     http.NewAnalyzer(nil), // Use real analyzer with nil comparator
		RequestCache: reqCache,
	}
}

func TestPayloadCoordinator_IdleState(t *testing.T) {
	queue := queue.New()
	coordinator := NewPayloadCoordinator(queue, 2, createMockCallbacks())

	// Initially idle
	if !coordinator.IsIdle() {
		t.Error("expected coordinator to be idle initially")
	}

	if coordinator.CurrentTask() != nil {
		t.Error("expected no current task initially")
	}
}
