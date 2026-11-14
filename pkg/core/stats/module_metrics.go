package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// ModuleStats tracks per-module performance metrics using atomic counters
// for lock-free concurrent access from multiple worker goroutines.
type ModuleStats struct {
	Invocations atomic.Int64
	Findings    atomic.Int64
	Errors      atomic.Int64
	TotalTimeNs atomic.Int64 // nanoseconds spent in module scan functions
	// Requests counts wire attempts sent by the module's calls (Requester
	// WithSendCounter); request-cache hits and redirect hops are not counted.
	Requests atomic.Int64
	// Inconclusive counts calls that completed with no finding while the host
	// throttled them (429/503): their negatives are not real negatives.
	Inconclusive atomic.Int64
	// latency is the completed-call duration histogram (adaptive timeout).
	latency latencyBuckets
}

// ModuleMetrics tracks metrics for all modules in a scan.
type ModuleMetrics struct {
	metrics    sync.Map // key: module ID → *ModuleStats
	considered sync.Map // key: module ID → struct{} (modules whose CanProcess was evaluated, fired or not)
}

// statsFor returns moduleID's stats, creating them on first use. Load first:
// LoadOrStore would heap-allocate a &ModuleStats{} on every call only to
// discard it on the common (already-present) path.
func (mm *ModuleMetrics) statsFor(moduleID string) *ModuleStats {
	val, ok := mm.metrics.Load(moduleID)
	if !ok {
		val, _ = mm.metrics.LoadOrStore(moduleID, &ModuleStats{})
	}
	return val.(*ModuleStats)
}

// For returns moduleID's live stats and marks the module considered, so a
// caller recording several things about one module call looks it up once.
// Returns nil on a nil receiver; every ModuleStats recording method is
// nil-safe.
func (mm *ModuleMetrics) For(moduleID string) *ModuleStats {
	if mm == nil {
		return nil
	}
	mm.considered.LoadOrStore(moduleID, struct{}{})
	return mm.statsFor(moduleID)
}

// Record records a single module invocation with its duration, finding count, and error.
// Safe to call on nil receiver. Implies MarkConsidered — a module that ran was
// necessarily considered.
func (mm *ModuleMetrics) Record(moduleID string, duration time.Duration, findings int, err error) {
	mm.For(moduleID).Record(duration, findings, err)
}

// Record records one invocation of the module. Safe on a nil receiver.
func (ms *ModuleStats) Record(duration time.Duration, findings int, err error) {
	if ms == nil {
		return
	}
	ms.Invocations.Add(1)
	ms.TotalTimeNs.Add(int64(duration))
	if findings > 0 {
		ms.Findings.Add(int64(findings))
	}
	if err != nil {
		ms.Errors.Add(1)
	}
}

// RecordInconclusive counts one module call whose result is inconclusive
// (completed while throttled, nothing found). Safe on a nil receiver.
func (mm *ModuleMetrics) RecordInconclusive(moduleID string) {
	if mm == nil {
		return
	}
	mm.statsFor(moduleID).Inconclusive.Add(1)
}

// MarkConsidered records that a module was evaluated against a record — i.e.,
// CanProcess was called — regardless of whether the module actually ran. Used
// by the status counter so it can reach parity with the total module count
// even when some modules' CanProcess always rejects the input shape (e.g.,
// POST-only modules in a GET-only scan).
func (mm *ModuleMetrics) MarkConsidered(moduleID string) {
	if mm == nil {
		return
	}
	mm.considered.LoadOrStore(moduleID, struct{}{})
}

// AddRequests adds n wire requests to the module's tally. Called once per
// module call when its work has unwound (so requests sent after a timeout
// still count). Safe on a nil receiver; n <= 0 is a no-op.
func (ms *ModuleStats) AddRequests(n int64) {
	if ms != nil && n > 0 {
		ms.Requests.Add(n)
	}
}

// ConsideredCount returns the number of distinct modules whose CanProcess has
// been evaluated at least once. Reaches the total enabled-module count once
// every module has been seen, regardless of whether any of them actually ran.
func (mm *ModuleMetrics) ConsideredCount() int64 {
	if mm == nil {
		return 0
	}
	var count int64
	mm.considered.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// ModuleStatsSnapshot is a point-in-time snapshot of a module's metrics.
type ModuleStatsSnapshot struct {
	Invocations int64
	Findings    int64
	Errors      int64
	TotalTime   time.Duration
	Requests    int64
	// Inconclusive: calls that completed while throttled with nothing found.
	Inconclusive int64
}

// Add returns the field-wise sum of s and o (merging one module's snapshots
// from several executors).
func (s ModuleStatsSnapshot) Add(o ModuleStatsSnapshot) ModuleStatsSnapshot {
	s.Invocations += o.Invocations
	s.Findings += o.Findings
	s.Errors += o.Errors
	s.TotalTime += o.TotalTime
	s.Requests += o.Requests
	s.Inconclusive += o.Inconclusive
	return s
}

// DistinctCount returns the number of distinct modules that have been invoked at least once.
func (mm *ModuleMetrics) DistinctCount() int64 {
	if mm == nil {
		return 0
	}
	var count int64
	mm.metrics.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// TotalInvocations returns the sum of all module invocations across all modules.
func (mm *ModuleMetrics) TotalInvocations() int64 {
	if mm == nil {
		return 0
	}
	var total int64
	mm.metrics.Range(func(_, value any) bool {
		total += value.(*ModuleStats).Invocations.Load()
		return true
	})
	return total
}

// Snapshot returns a point-in-time snapshot of all module metrics.
// Safe to call on nil receiver.
func (mm *ModuleMetrics) Snapshot() map[string]ModuleStatsSnapshot {
	if mm == nil {
		return nil
	}
	result := make(map[string]ModuleStatsSnapshot)
	mm.metrics.Range(func(key, value any) bool {
		ms := value.(*ModuleStats)
		result[key.(string)] = ModuleStatsSnapshot{
			Invocations:  ms.Invocations.Load(),
			Findings:     ms.Findings.Load(),
			Errors:       ms.Errors.Load(),
			TotalTime:    time.Duration(ms.TotalTimeNs.Load()),
			Requests:     ms.Requests.Load(),
			Inconclusive: ms.Inconclusive.Load(),
		}
		return true
	})
	return result
}
