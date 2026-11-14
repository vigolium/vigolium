package network

import (
	"sync"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// Response-body fetch pool. Network.getResponseBody used to run
// inline on the browser's single event goroutine, so one slow body held every
// later event — the requests behind it waited, and a burst of bodies could
// age out of the browser's buffer before their turn.
const (
	bodyWorkers = 4
	bodyQueue   = 256
	// bodyDrainTimeout bounds how long Close waits for queued body fetches.
	bodyDrainTimeout = 15 * time.Second
)

// bodyJob is one response whose body is to be fetched and stored.
type bodyJob struct {
	pending        *pendingEntry
	requestID      proto.NetworkRequestID
	includeBody    bool
	includeHeaders bool
}

// bodyPoolState groups the body-pool fields embedded in Capture.
type bodyPoolState struct {
	bodyJobs   chan bodyJob // guarded by Capture.mu
	bodyClosed bool         // guarded by Capture.mu
	bodyWG     sync.WaitGroup

	// bodyFetcher replaces the CDP call in tests.
	bodyFetcher func(proto.TargetSessionID, proto.NetworkRequestID) ([]byte, error)
}

// startBodyWorkers starts the body-fetch pool (idempotent).
func (c *Capture) startBodyWorkers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bodyJobs != nil || c.bodyClosed {
		return
	}
	c.bodyJobs = make(chan bodyJob, bodyQueue)
	for range bodyWorkers {
		c.bodyWG.Add(1)
		go func(jobs <-chan bodyJob) {
			defer c.bodyWG.Done()
			for job := range jobs {
				c.runBodyJob(job)
			}
		}(c.bodyJobs)
	}
}

// enqueueBody hands job to the pool; false when the pool is not running or
// full, in which case the caller fetches inline (nothing is ever dropped).
func (c *Capture) enqueueBody(job bodyJob) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bodyJobs == nil || c.bodyClosed {
		return false
	}
	select {
	case c.bodyJobs <- job:
		return true
	default:
		return false
	}
}

// stopBodyWorkers closes the pool and waits (bounded) for queued fetches.
func (c *Capture) stopBodyWorkers() {
	c.mu.Lock()
	if c.bodyJobs != nil && !c.bodyClosed {
		close(c.bodyJobs)
	}
	c.bodyClosed = true
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		c.bodyWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(bodyDrainTimeout):
		zap.L().Warn("Response body workers did not drain in time; their entries are dropped",
			zap.Duration("waited", bodyDrainTimeout))
	}
}

// responseBody fetches a response body (the test seam, else CDP).
func (c *Capture) responseBody(sessionID proto.TargetSessionID, requestID proto.NetworkRequestID) ([]byte, error) {
	if c.bodyFetcher != nil {
		return c.bodyFetcher(sessionID, requestID)
	}
	return c.fetchResponseBody(sessionID, requestID)
}
