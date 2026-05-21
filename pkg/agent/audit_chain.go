package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"go.uber.org/zap"
)

// AuditRunner is the common surface the audit dispatchers (CLI
// driverPlan, REST driverResult, single-driver runner) consume. Both the
// single-subprocess *AuditAgenticScanner and the multi-mode
// *PioliumChainScanner satisfy it, so a piolium mode chain is a drop-in
// for a single piolium run.
type AuditRunner interface {
	Start(ctx context.Context) error
	Wait() error
	Done() <-chan struct{}
	Cancel()
	Status() *AuditAgentStatus
	FindingStats() FindingStats
	CostSummary() ScanCost
	AgenticScanUUID() string
}

var (
	_ AuditRunner = (*AuditAgenticScanner)(nil)
	_ AuditRunner = (*PioliumChainScanner)(nil)
)

// NewAuditRunner returns the right runner for cfg. audit owns its own
// chaining natively (`--modes` is rendered in buildAuditAgentCommand, one
// subprocess, one row), so only a multi-mode piolium run needs the Go
// loop. Everything else stays a plain single-subprocess scanner.
func NewAuditRunner(cfg AuditAgentConfig, repo *database.Repository) AuditRunner {
	if cfg.Platform == PlatformPi && len(cfg.EffectiveModes()) > 1 {
		return NewPioliumChainScanner(cfg, repo)
	}
	return NewAuditAgenticScanner(cfg, repo)
}

// PioliumChainScanner runs a piolium mode chain (e.g. deep,confirm) as a
// sequence of `pi` subprocesses against the same source dir, collapsing
// them into a single aggregated AgenticScan row. The chain stops at the
// first mode that does not complete cleanly — matching audit's native
// `--modes` semantics.
//
// Why the per-mode aggregation rules differ: piolium's picost windows
// each cost summary to that subprocess's own run, so per-mode costs are
// disjoint and summed. Findings, by contrast, are NOT summed — piolium's
// findings/ dir is cumulative across chained modes in the same source
// tree, so the last completed mode's snapshot already reflects (and may
// have pruned) the whole chain; summing would double-count.
type PioliumChainScanner struct {
	baseCfg    AuditAgentConfig
	repo       *database.Repository
	modes      []string
	chainLabel string // JoinModes(modes), precomputed (poll-path hot)

	agenticScanUUID string
	startedAt       time.Time

	done chan struct{}

	mu        sync.Mutex
	err       error
	cancelled bool
	current   *AuditAgenticScanner

	aggStats   FindingStats
	aggCost    ScanCost
	lastStatus *AuditAgentStatus
	ranModes   []string
}

// NewPioliumChainScanner builds a chain runner. The mode chain is read
// from cfg.EffectiveModes() and filtered to the modes piolium supports
// (callers normally pre-filter via ValidateAuditDriverModes; this is a
// defensive second pass so an unsupported mode in the chain is skipped
// rather than failing the whole driver).
func NewPioliumChainScanner(cfg AuditAgentConfig, repo *database.Repository) *PioliumChainScanner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = DefaultAuditSyncInterval
	}
	if cfg.Harness.Name == "" {
		cfg.Harness = piolium.DefaultHarness()
	}

	var modes []string
	for _, m := range cfg.EffectiveModes() {
		if piolium.IsValidMode(m) {
			modes = append(modes, m)
			continue
		}
		zap.L().Info("piolium chain: skipping unsupported mode",
			zap.String("mode", m),
			zap.String("chain", JoinModes(cfg.EffectiveModes())))
	}
	if len(modes) == 0 {
		// Nothing piolium can run — fall back to its single-mode default
		// so the run still produces a (likely empty) result rather than
		// silently doing nothing.
		modes = []string{cfg.EffectiveModes()[0]}
	}

	scanUUID := deriveAuditScanUUID(cfg)

	return &PioliumChainScanner{
		baseCfg:         cfg,
		repo:            repo,
		modes:           modes,
		chainLabel:      JoinModes(modes),
		agenticScanUUID: scanUUID,
		done:            make(chan struct{}),
	}
}

func (p *PioliumChainScanner) AgenticScanUUID() string { return p.agenticScanUUID }

func (p *PioliumChainScanner) Done() <-chan struct{} { return p.done }

func (p *PioliumChainScanner) Wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *PioliumChainScanner) Cancel() {
	p.mu.Lock()
	p.cancelled = true
	cur := p.current
	p.mu.Unlock()
	if cur != nil {
		cur.Cancel()
	}
}

// Start creates the single aggregated child row and launches the chain
// loop in the background. It returns once the first mode's subprocess has
// started (or immediately with the error if it could not).
func (p *PioliumChainScanner) Start(ctx context.Context) error {
	p.startedAt = time.Now()
	p.createAggregateRow(ctx)

	startErr := make(chan error, 1)
	go p.run(ctx, startErr)
	return <-startErr
}

func (p *PioliumChainScanner) run(ctx context.Context, startErr chan<- error) {
	defer close(p.done)

	startReported := false
	report := func(err error) {
		if !startReported {
			startReported = true
			startErr <- err
		}
	}

	var chainErr error

	for i, mode := range p.modes {
		select {
		case <-ctx.Done():
			chainErr = ctx.Err()
		default:
		}
		if chainErr != nil {
			break
		}

		cfg := p.baseCfg
		cfg.Mode = mode
		cfg.Modes = nil // each inner runner is single-mode
		cfg.SuppressAgenticScanRow = true
		cfg.ForceAgenticScanUUID = p.agenticScanUUID
		cfg.KeepSourceOutputDir = i < len(p.modes)-1

		inner := NewAuditAgenticScanner(cfg, p.repo)

		p.mu.Lock()
		p.current = inner
		cancelled := p.cancelled
		p.mu.Unlock()
		if cancelled {
			chainErr = context.Canceled
			break
		}

		if err := inner.Start(ctx); err != nil {
			startErrW := fmt.Errorf("start piolium mode %q: %w", mode, err)
			// Only the very first mode's launch failure is fatal to
			// Start()'s caller; a later launch failure is just a chain
			// stop (Start() already returned nil after the first mode
			// began running).
			if i == 0 {
				report(startErrW)
			}
			chainErr = startErrW
			break
		}
		report(nil) // a subprocess is running — Start() can return

		// A Cancel() that landed in the window between setting p.current
		// and inner.Start() returning would have no-op'd on the
		// not-yet-launched subprocess (AuditAgenticScanner.Cancel exits
		// early when cmd==nil). Re-fire it now that the process is live.
		p.mu.Lock()
		cancelled = p.cancelled
		p.mu.Unlock()
		if cancelled {
			inner.Cancel()
		}

		runErr := inner.Wait()
		p.recordRan(mode, inner)

		// Stop the chain on cancellation — don't roll into the next mode.
		p.mu.Lock()
		cancelled = p.cancelled
		p.mu.Unlock()
		if cancelled {
			chainErr = context.Canceled
			break
		}

		st := inner.Status()
		complete := runErr == nil && (st == nil || st.Status == "" || st.Status == "complete")
		if runErr != nil {
			chainErr = fmt.Errorf("piolium mode %q: %w", mode, runErr)
		}
		if !complete {
			if chainErr == nil {
				chainErr = fmt.Errorf("piolium mode %q did not complete (status=%q); stopping chain", mode, statusStr(st))
			}
			zap.L().Warn("piolium chain stopped: mode did not complete",
				zap.String("mode", mode),
				zap.String("status", statusStr(st)),
				zap.String("agentic_scan_uuid", p.agenticScanUUID))
			break
		}
	}

	// Release Start()'s caller for any path that never hit report() (e.g.
	// ctx cancelled before the first launch).
	report(chainErr)

	p.mu.Lock()
	p.err = chainErr
	p.current = nil
	p.mu.Unlock()

	p.finalizeAggregateRow(chainErr)
}

// recordRan folds one completed inner runner's outcome into the chain
// aggregate. Cost is additive (disjoint picost windows). Findings stats
// are the LAST completed mode's, not the max: piolium's findings/ dir is
// cumulative in the shared source tree, so the final mode's snapshot is
// the authoritative count even when a later mode (e.g. confirm) prunes
// and reports fewer than an earlier one.
func (p *PioliumChainScanner) recordRan(mode string, inner *AuditAgenticScanner) {
	stats := inner.FindingStats()
	cost := inner.CostSummary()
	st := inner.Status()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.ranModes = append(p.ranModes, mode)
	p.aggStats = stats
	if !cost.IsZero() {
		if p.aggCost.IsZero() {
			p.aggCost = cost
		} else {
			p.aggCost.InputTokens += cost.InputTokens
			p.aggCost.OutputTokens += cost.OutputTokens
			p.aggCost.CostUSD += cost.CostUSD
			p.aggCost.Model = cost.Model
		}
	}
	if st != nil {
		p.lastStatus = st
	}
}

func (p *PioliumChainScanner) FindingStats() FindingStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.aggStats
	if stats.BySeverity != nil {
		cp := make(map[string]int, len(stats.BySeverity))
		for k, v := range stats.BySeverity {
			cp[k] = v
		}
		stats.BySeverity = cp
	}
	if stats.ReportedBySeverity != nil {
		cp := make(map[string]int, len(stats.ReportedBySeverity))
		for k, v := range stats.ReportedBySeverity {
			cp[k] = v
		}
		stats.ReportedBySeverity = cp
	}
	return stats
}

func (p *PioliumChainScanner) CostSummary() ScanCost {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.aggCost
	if !c.IsZero() {
		c.Note = fmt.Sprintf("(model %s, chain: %s)", displayModelName(c.Model), JoinModes(p.ranModes))
	}
	return c
}

// Status reports the live phase progress of the mode currently running;
// once the chain is done it returns the last mode's snapshot with the
// full chain string as the mode label.
func (p *PioliumChainScanner) Status() *AuditAgentStatus {
	p.mu.Lock()
	cur := p.current
	last := p.lastStatus
	p.mu.Unlock()

	if cur != nil {
		st := cur.Status()
		if st != nil {
			st.Mode = p.chainLabel
		}
		return st
	}
	if last != nil {
		s := *last
		s.Mode = p.chainLabel
		s.Running = p.isRunning()
		return &s
	}
	return &AuditAgentStatus{Running: p.isRunning(), Mode: p.chainLabel, Phase: "initializing"}
}

func (p *PioliumChainScanner) isRunning() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// createAggregateRow writes the single child AgenticScan row the chain
// owns. Per-mode inner runners run with SuppressAgenticScanRow so they do
// not create their own.
func (p *PioliumChainScanner) createAggregateRow(ctx context.Context) {
	if p.repo == nil {
		return
	}
	run := newAuditAgenticScanRow(p.baseCfg, p.baseCfg.Harness, p.agenticScanUUID, p.startedAt)
	if err := p.repo.CreateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("piolium chain: failed to create aggregate AgenticScan", zap.Error(err))
	}
}

func (p *PioliumChainScanner) finalizeAggregateRow(chainErr error) {
	if p.repo == nil {
		return
	}
	ctx := context.Background()
	run, err := p.repo.GetAgenticScan(ctx, p.agenticScanUUID)
	if err != nil {
		return
	}

	now := time.Now()
	run.CompletedAt = now
	run.DurationMs = now.Sub(p.startedAt).Milliseconds()

	p.mu.Lock()
	cancelled := p.cancelled
	stats := p.aggStats
	cost := p.aggCost
	last := p.lastStatus
	p.mu.Unlock()

	applyAuditTerminalStatus(run, chainErr, cancelled)
	if last != nil {
		run.CurrentPhase = ""
		run.PhasesRun = nil
	}
	run.FindingCount = stats.Parsed
	run.SavedCount = stats.Saved
	applyScanCost(run, cost)

	if uErr := p.repo.UpdateAgenticScan(ctx, run); uErr != nil {
		zap.L().Debug("piolium chain: failed to finalize aggregate AgenticScan", zap.Error(uErr))
	}
}

// deriveAuditScanUUID is the single source of truth for an audit run's
// AgenticScan UUID, shared by NewAuditAgenticScanner and the chain
// scanner: an explicit ForceAgenticScanUUID wins (the chain pins every
// inner runner to its aggregate row); otherwise a standalone run reuses
// {sessions_dir}/{uuid}/ via filepath.Base(SessionDir) so `vigolium log`
// resolves runtime.log; a nested/no-session run gets a fresh UUID.
func deriveAuditScanUUID(cfg AuditAgentConfig) string {
	if cfg.ForceAgenticScanUUID != "" {
		return cfg.ForceAgenticScanUUID
	}
	if cfg.SessionDir != "" && cfg.ParentAgenticScanUUID == "" {
		return filepath.Base(cfg.SessionDir)
	}
	return uuid.New().String()
}

func statusStr(s *AuditAgentStatus) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(s.Status)
}
