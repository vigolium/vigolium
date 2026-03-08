package network

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/env"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/projectdiscovery/utils/memguardian"
	"go.uber.org/zap"
)

var (
	MaxThreadsOnLowMemory          = env.GetEnvOrDefault("MEMGUARDIAN_THREADS", 30)
	MaxBytesBufferAllocOnLowMemory = env.GetEnvOrDefault("MEMGUARDIAN_ALLOC", 200)
	memTimer                       *time.Ticker
	cancelFunc                     context.CancelFunc
)

func StartActiveMemGuardian(ctx context.Context) {
	if memguardian.DefaultMemGuardian == nil {
		zap.L().Warn("memguardian not found, skipping")
		return
	}

	memTimer = time.NewTicker(time.Second * 15) // default 30s
	ctx, cancelFunc = context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-memTimer.C:
				if IsLowOnMemory() {
					_ = GlobalGuardBytesBufferAlloc()
				} else {
					GlobalRestoreBytesBufferAlloc()
				}
			}
		}
	}()
}

func StopActiveMemGuardian() {
	if memguardian.DefaultMemGuardian == nil {
		return
	}

	if memTimer != nil {
		memTimer.Stop()
		cancelFunc()
	}
}

func IsLowOnMemory() bool {
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}
	return false
}

// GuardThreadsOrDefault returns reduced thread count when memory is low
func GuardThreadsOrDefault(current int) int {
	if MaxThreadsOnLowMemory > 0 {
		return MaxThreadsOnLowMemory
	}

	fraction := int(current / 5)
	if fraction > 0 {
		return fraction
	}

	return 1
}

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
