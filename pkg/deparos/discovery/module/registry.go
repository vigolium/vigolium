package module

import (
	"sort"
	"sync"
)

// Registry manages module registration and lookup.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
	order   []string // Maintains registration order
}

// NewRegistry creates a new module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry.
// Returns false if module with same name already exists.
func (r *Registry) Register(m Module) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := m.Name()
	if _, exists := r.modules[name]; exists {
		return false
	}

	r.modules[name] = m
	r.order = append(r.order, name)
	return true
}

// Unregister removes a module from the registry.
// Returns false if module doesn't exist.
func (r *Registry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.modules[name]; !exists {
		return false
	}

	delete(r.modules, name)

	// Remove from order slice
	for i, n := range r.order {
		if n == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}

	return true
}

// Get returns a module by name.
func (r *Registry) Get(name string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[name]
	return m, ok
}

// All returns all registered modules sorted by priority.
func (r *Registry) All() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		modules = append(modules, m)
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Priority() < modules[j].Priority()
	})

	return modules
}

// Enabled returns all enabled modules sorted by priority.
func (r *Registry) Enabled() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var modules []Module
	for _, m := range r.modules {
		if m.Enabled() {
			modules = append(modules, m)
		}
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Priority() < modules[j].Priority()
	})

	return modules
}

// MatchDirectory returns enabled modules matching the directory path.
func (r *Registry) MatchDirectory(path string) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matching []Module
	for _, m := range r.modules {
		if !m.Enabled() {
			continue
		}

		matcher := NewPatternMatcher(m.Patterns())
		if matcher.MatchesDirectory(path) {
			matching = append(matching, m)
		}
	}

	sort.Slice(matching, func(i, j int) bool {
		return matching[i].Priority() < matching[j].Priority()
	})

	return matching
}

// MatchFile returns enabled modules matching the file path.
func (r *Registry) MatchFile(path string) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matching []Module
	for _, m := range r.modules {
		if !m.Enabled() {
			continue
		}

		matcher := NewPatternMatcher(m.Patterns())
		if matcher.MatchesFile(path) {
			matching = append(matching, m)
		}
	}

	sort.Slice(matching, func(i, j int) bool {
		return matching[i].Priority() < matching[j].Priority()
	})

	return matching
}

// Names returns all registered module names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.order))
	copy(names, r.order)
	return names
}

// Count returns the number of registered modules.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.modules)
}

// Enable enables a module by name.
func (r *Registry) Enable(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, ok := r.modules[name]
	if !ok {
		return false
	}

	if base, ok := m.(*BaseModule); ok {
		base.SetEnabled(true)
		return true
	}

	// For modules embedding BaseModule
	// This requires type assertion which won't work for all types
	// Modules should implement their own Enable method if needed

	return false
}

// Disable disables a module by name.
func (r *Registry) Disable(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	m, ok := r.modules[name]
	if !ok {
		return false
	}

	if base, ok := m.(*BaseModule); ok {
		base.SetEnabled(false)
		return true
	}

	return false
}

// EnableOnly enables only the specified modules, disabling all others.
func (r *Registry) EnableOnly(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	nameSet := make(map[string]struct{}, len(names))
	for _, n := range names {
		nameSet[n] = struct{}{}
	}

	for name, m := range r.modules {
		if base, ok := m.(*BaseModule); ok {
			_, shouldEnable := nameSet[name]
			base.SetEnabled(shouldEnable)
		}
	}
}

// DisableAll disables all modules.
func (r *Registry) DisableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, m := range r.modules {
		if base, ok := m.(*BaseModule); ok {
			base.SetEnabled(false)
		}
	}
}

// EnableAll enables all modules.
func (r *Registry) EnableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, m := range r.modules {
		if base, ok := m.(*BaseModule); ok {
			base.SetEnabled(true)
		}
	}
}
