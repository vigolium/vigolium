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
}

// ModuleMetrics tracks metrics for all modules in a scan.
type ModuleMetrics struct {
	metrics sync.Map // key: module ID → *ModuleStats
}

// Record records a single module invocation with its duration, finding count, and error.
// Safe to call on nil receiver.
func (mm *ModuleMetrics) Record(moduleID string, duration time.Duration, findings int, err error) {
	if mm == nil {
		return
	}
	val, _ := mm.metrics.LoadOrStore(moduleID, &ModuleStats{})
	ms := val.(*ModuleStats)
	ms.Invocations.Add(1)
	ms.TotalTimeNs.Add(int64(duration))
	if findings > 0 {
		ms.Findings.Add(int64(findings))
	}
	if err != nil {
		ms.Errors.Add(1)
	}
}

// ModuleStatsSnapshot is a point-in-time snapshot of a module's metrics.
type ModuleStatsSnapshot struct {
	Invocations int64
	Findings    int64
	Errors      int64
	TotalTime   time.Duration
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
			Invocations: ms.Invocations.Load(),
			Findings:    ms.Findings.Load(),
			Errors:      ms.Errors.Load(),
			TotalTime:   time.Duration(ms.TotalTimeNs.Load()),
		}
		return true
	})
	return result
}
