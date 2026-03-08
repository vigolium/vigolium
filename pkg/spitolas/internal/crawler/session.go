package crawler

import (
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// CrawlSession holds all crawl paths from a crawl session.
// CRAWLJAX PARITY: Matches Java Crawljax CrawlSession which stores all CrawlPaths.
type CrawlSession struct {
	mu sync.RWMutex

	// All crawl paths from this session
	CrawlPaths []*state.CrawlPath

	// Session metadata
	StartTime time.Time
	EndTime   time.Time
	Config    *config.Config

	// CRAWLJAX PARITY: Initial state (index)
	InitialState *state.State

	// Statistics (computed on demand)
	statsCache *SessionStats
	statsDirty bool
}

// SessionStats holds session-level statistics.
type SessionStats struct {
	TotalPaths           int
	SuccessfulBacktracks int
	FailedBacktracks     int
	NearDuplicateReaches int
	TotalEvents          int
	AveragePathLength    float64
	TotalDuration        time.Duration
}

// NewCrawlSession creates a new crawl session.
func NewCrawlSession(cfg *config.Config, initialState *state.State) *CrawlSession {
	return &CrawlSession{
		CrawlPaths:   make([]*state.CrawlPath, 0),
		StartTime:    time.Now(),
		Config:       cfg,
		InitialState: initialState,
		statsDirty:   true,
	}
}

// AddCrawlPath adds a completed crawl path to the session.
// CRAWLJAX PARITY: Called by Crawler.reset() before creating new StateMachine.
func (cs *CrawlSession) AddCrawlPath(path *state.CrawlPath) {
	if path == nil {
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Close the path if not already closed
	path.Close()

	cs.CrawlPaths = append(cs.CrawlPaths, path)
	cs.statsDirty = true
}

// GetCrawlPaths returns all crawl paths.
func (cs *CrawlSession) GetCrawlPaths() []*state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	// Return a copy of the slice
	paths := make([]*state.CrawlPath, len(cs.CrawlPaths))
	copy(paths, cs.CrawlPaths)
	return paths
}

// GetLastPath returns the most recent crawl path.
func (cs *CrawlSession) GetLastPath() *state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if len(cs.CrawlPaths) == 0 {
		return nil
	}
	return cs.CrawlPaths[len(cs.CrawlPaths)-1]
}

// PathCount returns the number of crawl paths.
func (cs *CrawlSession) PathCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.CrawlPaths)
}

// GetStats returns session statistics.
// Statistics are cached and only recomputed when paths are added.
func (cs *CrawlSession) GetStats() SessionStats {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if !cs.statsDirty && cs.statsCache != nil {
		return *cs.statsCache
	}

	stats := SessionStats{}
	totalEvents := 0
	totalPathLength := 0

	for _, path := range cs.CrawlPaths {
		stats.TotalPaths++
		pathLen := path.Len()
		totalPathLength += pathLen
		totalEvents += pathLen

		if path.BacktrackSuccess {
			stats.SuccessfulBacktracks++
		} else {
			stats.FailedBacktracks++
		}

		if path.ReachedNearDup != "" {
			stats.NearDuplicateReaches++
		}
	}

	stats.TotalEvents = totalEvents
	if stats.TotalPaths > 0 {
		stats.AveragePathLength = float64(totalPathLength) / float64(stats.TotalPaths)
	}

	if !cs.EndTime.IsZero() {
		stats.TotalDuration = cs.EndTime.Sub(cs.StartTime)
	} else {
		stats.TotalDuration = time.Since(cs.StartTime)
	}

	cs.statsCache = &stats
	cs.statsDirty = false

	return stats
}

// MarkEnd marks the session as ended.
func (cs *CrawlSession) MarkEnd() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.EndTime.IsZero() {
		cs.EndTime = time.Now()
		cs.statsDirty = true
	}
}

// Duration returns the total session duration.
func (cs *CrawlSession) Duration() time.Duration {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.EndTime.IsZero() {
		return time.Since(cs.StartTime)
	}
	return cs.EndTime.Sub(cs.StartTime)
}

// GetInitialState returns the initial state.
func (cs *CrawlSession) GetInitialState() *state.State {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.InitialState
}

// GetConfig returns the session config.
func (cs *CrawlSession) GetConfig() *config.Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.Config
}

// GetSuccessfulPaths returns only the successful backtrack paths.
func (cs *CrawlSession) GetSuccessfulPaths() []*state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var successful []*state.CrawlPath
	for _, path := range cs.CrawlPaths {
		if path.BacktrackSuccess {
			successful = append(successful, path)
		}
	}
	return successful
}

// GetFailedPaths returns only the failed backtrack paths.
func (cs *CrawlSession) GetFailedPaths() []*state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var failed []*state.CrawlPath
	for _, path := range cs.CrawlPaths {
		if !path.BacktrackSuccess {
			failed = append(failed, path)
		}
	}
	return failed
}

// GetNearDuplicatePaths returns paths that reached a near-duplicate state.
func (cs *CrawlSession) GetNearDuplicatePaths() []*state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var nearDup []*state.CrawlPath
	for _, path := range cs.CrawlPaths {
		if path.ReachedNearDup != "" {
			nearDup = append(nearDup, path)
		}
	}
	return nearDup
}

// GetPathsToTarget returns all paths that targeted a specific state.
func (cs *CrawlSession) GetPathsToTarget(targetStateID string) []*state.CrawlPath {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var paths []*state.CrawlPath
	for _, path := range cs.CrawlPaths {
		if path.BacktrackTarget == targetStateID {
			paths = append(paths, path)
		}
	}
	return paths
}

// IsActive returns true if the session is still active.
func (cs *CrawlSession) IsActive() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.EndTime.IsZero()
}
