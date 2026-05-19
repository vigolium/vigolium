package dedup

import "sync"

// Lazy provides thread-safe lazy initialization for any dedup type.
type Lazy[T any] struct {
	once     sync.Once
	value    *T
	initFunc func(*Manager) *T
}

// NewLazy creates a Lazy initializer with the given init function.
func NewLazy[T any](initFunc func(*Manager) *T) Lazy[T] {
	return Lazy[T]{initFunc: initFunc}
}

// Get returns the lazily-initialized value, or nil if manager is nil.
func (l *Lazy[T]) Get(manager *Manager) *T {
	if manager == nil {
		return nil
	}
	l.once.Do(func() {
		l.value = l.initFunc(manager)
	})
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
