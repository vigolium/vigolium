package discovery

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MISS-8a: a non-trailing-slash redirect is recorded under the SOURCE URL with
// its own 3xx response, and the Location is queued as a referenced task to be
// fetched (and recorded) with its own response.
func TestHandleRedirect_RecordsSourceAndQueuesLocation(t *testing.T) {
	coord, engine, cb := newRedirectConfirmHarness(t)
	defer engine.Stop()

	var resultURLs []string
	cb.OnResult = func(r *Result) { resultURLs = append(resultURLs, r.URL.String()) }
	var queued []string
	cb.QueueReferencedURL = func(u string, _ uint16) { queued = append(queued, u) }

	driveRedirect(t, coord, cb, "http://example.test/old", "/new/page", http.StatusFound)

	require.Len(t, resultURLs, 1)
	assert.Equal(t, "http://example.test/old", resultURLs[0], "the 3xx belongs to the source URL")
	assert.Equal(t, []string{"http://example.test/new/page"}, queued)

	// A self-bounce queues nothing.
	queued = nil
	driveRedirect(t, coord, cb, "http://example.test/x", "http://example.test/x", http.StatusFound)
	assert.Empty(t, queued)
}

func TestQueueReferencedURLBuildsSpiderTask(t *testing.T) {
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	defer engine.Stop()

	before := engine.taskQueue.Size()
	engine.queueReferencedURL("http://example.test/new/page?a=1", 1)
	assert.Equal(t, before+1, engine.taskQueue.Size())
	engine.queueReferencedURL("::not a url", 1)
	assert.Equal(t, before+1, engine.taskQueue.Size(), "an unparseable Location is not queued")
}
