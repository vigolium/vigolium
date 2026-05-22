package dedup

import "sync"

// Lazy provides thread-safe lazy initialization of a dedup helper for a given
// dedup Manager.
//
// The cached value is keyed by the Manager it was built for. This matters
// because scanner module instances are shared singletons across scans (see the
// modules registry): each scan runs with its own per-runner Manager, so if Lazy
// cached the first Manager unconditionally it would hand every later scan the
// first scan's helper — which points at a Manager that was closed when the
// first scan's runner shut down, silently disabling dedup (and the modules that
// gate on it) for every subsequent scan. Re-resolving when the Manager changes
// keeps each scan isolated while still computing the value once per scan.
type Lazy[T any] struct {
	mu       sync.Mutex
	manager  *Manager
	value    *T
	initFunc func(*Manager) *T
}

// NewLazy creates a Lazy initializer with the given init function.
func NewLazy[T any](initFunc func(*Manager) *T) Lazy[T] {
	return Lazy[T]{initFunc: initFunc}
}

// Get returns the value for the given manager, or nil if manager is nil. The
// value is cached per Manager: repeated calls within the same scan reuse it,
// and a call with a different Manager (a new scan) re-resolves.
func (l *Lazy[T]) Get(manager *Manager) *T {
	if manager == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-resolve only when the Manager changes (a new scan). The condition keys
	// solely on the Manager — not on value == nil — so a helper that resolves to
	// nil (e.g. GetDiskSet returning nil after a DiskSet creation failure) is
	// cached once per Manager rather than re-attempting initFunc (and its
	// temp-dir/LevelDB creation) on every request for the rest of the scan.
	if l.manager != manager {
		l.value = l.initFunc(manager)
		l.manager = manager
	}
	return l.value
}

// LazyDefaultRHM creates a lazy RequestHashManager with DefaultOption.
func LazyDefaultRHM(key string) Lazy[RequestHashManager] {
	return NewLazy(func(m *Manager) *RequestHashManager {
		return m.GetDefaultRequestHashManager(key)
	})
}

// LazyRHM creates a lazy RequestHashManager with custom Option.
func LazyRHM(key string, opt Option) Lazy[RequestHashManager] {
	return NewLazy(func(m *Manager) *RequestHashManager {
		return m.GetRequestHashManager(key, opt)
	})
}

// LazyDiskSet creates a lazy DiskSet.
func LazyDiskSet(key string) Lazy[DiskSet] {
	return NewLazy(func(m *Manager) *DiskSet {
		return m.GetDiskSet(key)
	})
}
