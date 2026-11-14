package network

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/utils/env"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/projectdiscovery/utils/memguardian"
	"go.uber.org/zap"
)

var (
	MaxBytesBufferAllocOnLowMemory = env.GetEnvOrDefault("MEMGUARDIAN_ALLOC", 200)

	// memMu guards the guardian's lifecycle handles. They are package globals
	// written by Start and read by Stop, while the goroutine Start launched is
	// still running — so two overlapping scan lifecycles in one process (a server
	// starting a second scan as the first tears down) raced on them, and a Start
	// arriving before the previous goroutine noticed its cancellation left that
	// goroutine on a ticker nothing would ever stop.
	memMu      sync.Mutex
	memTimer   *time.Ticker
	cancelFunc context.CancelFunc

	// activeGuardian is the monitor StartActiveMemGuardian runs. A fresh one
	// per Start: MemGuardian.Run closes its ticker and context when its ctx
	// ends, so the package default cannot be run twice in one process (a
	// server running scan after scan). nil when none is running.
	activeGuardian atomic.Pointer[memguardian.MemGuardian]

	// lowMemoryOverride lets tests force IsLowOnMemory (0 = off, 1 = low,
	// 2 = not low).
	lowMemoryOverride atomic.Int32
)

// newGuardian builds a monitor with the package default's thresholds
// (MEMGUARDIAN_INTERVAL, MEMGUARDIAN_MAX_RAM_RATIO, MEMGUARDIAN_MAX_RAM).
func newGuardian() (*memguardian.MemGuardian, error) {
	opts := []memguardian.MemGuardianOption{
		memguardian.WitInterval(memguardian.DefaultInterval),
		memguardian.WithMaxRamRatioWarning(memguardian.DefaultMaxUsedRamRatio),
	}
	if maxRam := env.GetEnvOrDefault(memguardian.MemGuardianMaxUsedMemoryENV, ""); maxRam != "" {
		opts = append(opts, memguardian.WithMaxRamAmountWarning(maxRam))
	}
	return memguardian.New(opts...)
}

func StartActiveMemGuardian(ctx context.Context) {
	if memguardian.DefaultMemGuardian == nil {
		zap.L().Warn("memguardian not found, skipping")
		return
	}

	memMu.Lock()
	defer memMu.Unlock()
	// Already running: a second Start would orphan the first goroutine.
	if cancelFunc != nil {
		return
	}

	timer := time.NewTicker(time.Second * 15) // default 30s
	ctx, cancel := context.WithCancel(ctx)
	memTimer, cancelFunc = timer, cancel

	// The ticker and context are CAPTURED rather than read from the globals: a
	// later Stop/Start pair reassigns those while this goroutine still runs.
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if IsLowOnMemory() {
					_ = GlobalGuardBytesBufferAlloc()
				} else {
					GlobalRestoreBytesBufferAlloc()
				}
			}
		}
	}()

	// The monitor that sets the low-memory flag. network.Init started the
	// buffer-pool loop above, but no one ever ran a guardian's Run, so
	// IsLowOnMemory was always false and nothing backed off. Started after the
	// loop (its goroutine is a named function, not a closure) so goleak
	// allow-lists stay stable.
	if mg, err := newGuardian(); err == nil {
		activeGuardian.Store(mg)
		go runGuardian(ctx, mg)
	} else {
		zap.L().Debug("memguardian unavailable", zap.Error(err))
	}
}

// runGuardian runs a memory monitor until ctx ends.
func runGuardian(ctx context.Context, mg *memguardian.MemGuardian) {
	if err := mg.Run(ctx); err != nil {
		zap.L().Debug("memguardian stopped", zap.Error(err))
	}
}

func StopActiveMemGuardian() {
	if memguardian.DefaultMemGuardian == nil {
		return
	}

	memMu.Lock()
	timer, cancel := memTimer, cancelFunc
	memTimer, cancelFunc = nil, nil
	activeGuardian.Store(nil)
	memMu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	if cancel != nil {
		cancel()
	}
}

// IsLowOnMemory reports whether the running memory monitor is in its warning
// state (used RAM over MEMGUARDIAN_MAX_RAM_RATIO, default 75%, or over
// MEMGUARDIAN_MAX_RAM). Admission control reads it to back off: the executor's
// active-task scheduler halves its global concurrency while it is true.
func IsLowOnMemory() bool {
	switch lowMemoryOverride.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	if mg := activeGuardian.Load(); mg != nil {
		return mg.Warning.Load()
	}
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}
	return false
}

// SetLowMemoryForTest forces IsLowOnMemory's answer; reset restores it. For
// tests of components that back off under memory pressure.
func SetLowMemoryForTest(low bool) (reset func()) {
	if low {
		lowMemoryOverride.Store(1)
	} else {
		lowMemoryOverride.Store(2)
	}
	return func() { lowMemoryOverride.Store(0) }
}

// activeMemGuardianRunning reports whether a monitor is running (tests).
func activeMemGuardianRunning() bool { return activeGuardian.Load() != nil }

var muGlobalChange sync.Mutex

// GlobalGuardBytesBufferAlloc reduces buffer pool size when memory is low
func GlobalGuardBytesBufferAlloc() error {
	if !muGlobalChange.TryLock() {
		return nil
	}
	defer muGlobalChange.Unlock()

	// if current capacity was not reduced decrease it
	if MaxBytesBufferAllocOnLowMemory > 0 && httputil.DefaultBufferSize == httputil.GetPoolSize() {
		zap.L().Info("reducing bytes.buffer pool size", zap.Int("new_size", MaxBytesBufferAllocOnLowMemory))
		delta := httputil.GetPoolSize() - int64(MaxBytesBufferAllocOnLowMemory)
		return httputil.ChangePoolSize(-delta)
	}

	return nil
}

// GlobalRestoreBytesBufferAlloc restores buffer pool size when memory is normal
func GlobalRestoreBytesBufferAlloc() {
	if !muGlobalChange.TryLock() {
		return
	}
	defer muGlobalChange.Unlock()

	if httputil.DefaultBufferSize != httputil.GetPoolSize() {
		delta := httputil.DefaultBufferSize - httputil.GetPoolSize()
		zap.L().Info("restoring bytes.buffer pool size", zap.Int64("new_size", httputil.DefaultBufferSize))
		_ = httputil.ChangePoolSize(delta)
	}
}
