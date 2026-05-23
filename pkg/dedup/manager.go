package dedup

import (
	"sync"

	"go.uber.org/zap"
)

// Manager manages DiskSet and RequestHashManager instances.
type Manager struct {
	mux                    sync.Mutex
	diskSets               map[string]*DiskSet
	requestHashManagerData map[string]*RequestHashManager
}

// NewManager creates a new Manager.
func NewManager() *Manager {
	return &Manager{
		diskSets:               make(map[string]*DiskSet),
		requestHashManagerData: make(map[string]*RequestHashManager),
	}
}

// GetDiskSet returns or creates a DiskSet for the given module ID.
func (m *Manager) GetDiskSet(key string) *DiskSet {
	m.mux.Lock()
	defer m.mux.Unlock()
	if ds, ok := m.diskSets[key]; ok {
		return ds
	}
	ds, err := NewDiskSet(DefaultDiskSetOptions)
	if err != nil {
		// Returning nil degrades gracefully — the caller (see Lazy.Get) treats a
		// nil helper as "dedup disabled for this scan". But a silent disable hides
		// real problems (disk full, bad temp dir), so surface it once per key.
		zap.L().Warn("dedup disabled: failed to create DiskSet; deduplication is off for this key",
			zap.String("key", key), zap.Error(err))
		return nil
	}
	m.diskSets[key] = ds
	return ds
}

// GetDefaultRequestHashManager returns a RequestHashManager with DefaultOption.
func (m *Manager) GetDefaultRequestHashManager(key string) *RequestHashManager {
	return m.GetRequestHashManager(key, DefaultOption)
}

// GetRequestHashManager returns or creates a RequestHashManager for the given module ID.
func (m *Manager) GetRequestHashManager(key string, option Option) *RequestHashManager {
	m.mux.Lock()
	defer m.mux.Unlock()
	if md, ok := m.requestHashManagerData[key]; ok {
		return md
	}
	md, err := newRequestHashManager(option)
	if err != nil {
		// As with GetDiskSet, nil means "dedup disabled for this scan"; log so the
		// silent degradation is visible rather than swallowed.
		zap.L().Warn("dedup disabled: failed to create RequestHashManager; request dedup is off for this key",
			zap.String("key", key), zap.Error(err))
		return nil
	}
	m.requestHashManagerData[key] = md
	return md
}

// Close releases all resources.
func (m *Manager) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()

	for _, ds := range m.diskSets {
		_ = ds.Close()
	}

	for _, md := range m.requestHashManagerData {
		md.Close()
	}
}
