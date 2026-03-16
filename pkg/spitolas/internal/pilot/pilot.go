package pilot

import (
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	sconfig "github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// PilotCrawler provides a fully LLM-controlled crawl mode.
// It reuses Crawler's low-level infrastructure (browser, state graph, form handler,
// network capture) but NEVER calls Crawler's crawl loop methods.
//
// The ACP agent controls ALL flow decisions: what to click, when to navigate,
// when to backtrack, when to move on. The Go code is purely an executor.
type PilotCrawler struct {
	// Infrastructure — same sub-components the standard Crawler uses
	browserPool *browser.Pool
	graph       *state.Graph
	formHandler *form.Handler
	extractor   *action.CandidateElementExtractor
	capture     *network.Capture
	config      *sconfig.Config

	// Pilot-specific
	agentDef    config.AgentDef        // ACP agent definition from vigolium config
	checkpoints *CheckpointTracker     // checkpoint-based feature tracking with replay
	entities    *EntityTracker         // created entities for create-then-delete
	trace       *SessionTrace          // session trace for debugging and prompt analysis
	blacklist   *Blacklist             // elements that must not be clicked
	pilotConfig *PilotConfig           // pilot mode configuration
	credentials *Credentials           // stored auth credentials

	// Current state tracking
	currentPage  *browser.Page
	currentState *state.State
	crawlPhase   CrawlPhase // breadth or depth

	// Stall detection — reset on every MCP tool call
	stallMu    sync.Mutex
	stallTimer *stallTimer

	// Consecutive failure tracking — auto-abandon checkpoint after threshold
	consecutiveFailures int

	// Terminate signal — set by toolTerminateCrawl
	terminated atomic.Bool
}

// reportProgress resets the stall timer, signaling that the agent is alive.
// Called from the MCP server on every tool call.
func (bc *PilotCrawler) reportProgress() {
	bc.stallMu.Lock()
	st := bc.stallTimer
	bc.stallMu.Unlock()
	if st != nil {
		st.Reset()
	}
}

// setStallTimer arms the stall timer for the current ACP attempt.
func (bc *PilotCrawler) setStallTimer(st *stallTimer) {
	bc.stallMu.Lock()
	bc.stallTimer = st
	bc.stallMu.Unlock()
}

// stopStallTimer disarms the stall timer and returns whether it had fired.
func (bc *PilotCrawler) stopStallTimer() bool {
	bc.stallMu.Lock()
	defer bc.stallMu.Unlock()
	if bc.stallTimer == nil {
		return false
	}
	fired := bc.stallTimer.Stop()
	bc.stallTimer = nil
	return fired
}

// NewPilotCrawler creates a new PilotCrawler with the given infrastructure.
// It does NOT start crawling — call Run() for that.
func NewPilotCrawler(
	cfg *sconfig.Config,
	pilotCfg *PilotConfig,
	agentDef config.AgentDef,
	pool *browser.Pool,
	graph *state.Graph,
	formHandler *form.Handler,
	extractor *action.CandidateElementExtractor,
	capture *network.Capture,
	trace *SessionTrace,
	checkpointPersistPath string,
) *PilotCrawler {
	return &PilotCrawler{
		config:      cfg,
		pilotConfig: pilotCfg,
		agentDef:    agentDef,
		browserPool: pool,
		graph:       graph,
		formHandler: formHandler,
		extractor:   extractor,
		capture:     capture,
		checkpoints: NewCheckpointTracker(checkpointPersistPath),
		entities:    NewEntityTracker(),
		trace:       trace,
		blacklist:   NewBlacklist(),
		crawlPhase:  PhaseBreadth,
	}
}
