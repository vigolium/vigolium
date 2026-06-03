package xss_stored

import (
	"context"
	"sync"
	"sync/atomic"
)

// Each confirmation spawns a real browser process, far costlier than an HTTP
// request, so escalation is bounded per-host and per-scan.
const (
	defaultPerHostBrowsers = 1
	defaultMaxScanProbes   = 100
)

// Budget bounds how often the module escalates to a real browser probe.
type Budget struct {
	maxPerScan int32

	mu             sync.Mutex
	hostSemaphores map[string]chan struct{}
	perHost        int

	remaining atomic.Int32
}

// NewBudget returns a fresh budget. Pass <= 0 to use defaults.
func NewBudget(perHost, totalPerScan int) *Budget {
	if perHost <= 0 {
		perHost = defaultPerHostBrowsers
	}
	if totalPerScan <= 0 {
		totalPerScan = defaultMaxScanProbes
	}
	b := &Budget{
		maxPerScan:     int32(totalPerScan),
		perHost:        perHost,
		hostSemaphores: make(map[string]chan struct{}),
	}
	b.remaining.Store(int32(totalPerScan))
	return b
}

// Reserve consumes one probe slot for host. The returned release must be called
// once the probe is done. ok=false means the global cap is exhausted or ctx was
// cancelled while waiting on the per-host semaphore.
func (b *Budget) Reserve(ctx context.Context, host string) (release func(), ok bool) {
	if b == nil {
		return func() {}, true
	}

	if b.remaining.Add(-1) < 0 {
		b.remaining.Add(1)
		return nil, false
	}

	sem := b.hostSem(host)
	select {
	case sem <- struct{}{}:
		return func() {
			<-sem
			b.remaining.Add(1)
		}, true
	case <-ctx.Done():
		b.remaining.Add(1)
		return nil, false
	}
}

func (b *Budget) hostSem(host string) chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	sem, ok := b.hostSemaphores[host]
	if !ok {
		sem = make(chan struct{}, b.perHost)
		b.hostSemaphores[host] = sem
	}
	return sem
}
