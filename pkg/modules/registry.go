package modules

import (
	"fmt"
	"strings"
	"sync"
)

// Registry manages all scanner modules.
// Thread-safe for concurrent access.
type Registry struct {
	mu             sync.RWMutex
	activeModules  []ActiveModule
	passiveModules []PassiveModule
	activeIDs      map[string]struct{}
	passiveIDs     map[string]struct{}
}

// NewRegistry creates a new registry.
func NewRegistry() *Registry {
	return &Registry{
		activeIDs:  make(map[string]struct{}),
		passiveIDs: make(map[string]struct{}),
	}
}

// RegisterActive adds an active module to the registry.
// Panics if a module with the same ID is already registered or if the ID is not lowercase.
// Returns the registry to support fluent API.
func (r *Registry) RegisterActive(m ActiveModule) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := m.ID()
	if id != strings.ToLower(id) {
		panic(fmt.Sprintf("module ID %q must be lowercase", id))
	}
	if _, exists := r.activeIDs[id]; exists {
		panic(fmt.Sprintf("duplicate active module ID: %q", id))
	}

	r.activeIDs[id] = struct{}{}
	r.activeModules = append(r.activeModules, m)
	return r
}

// RegisterPassive adds a passive module to the registry.
// Panics if a module with the same ID is already registered or if the ID is not lowercase.
// Returns the registry to support fluent API.
func (r *Registry) RegisterPassive(m PassiveModule) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := m.ID()
	if id != strings.ToLower(id) {
		panic(fmt.Sprintf("module ID %q must be lowercase", id))
	}
	if _, exists := r.passiveIDs[id]; exists {
		panic(fmt.Sprintf("duplicate passive module ID: %q", id))
	}

	r.passiveIDs[id] = struct{}{}
	r.passiveModules = append(r.passiveModules, m)
	return r
}

// GetActiveModules returns all active modules.
func (r *Registry) GetActiveModules() []ActiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ActiveModule, len(r.activeModules))
	copy(result, r.activeModules)
	return result
}

// GetPassiveModules returns all passive modules.
func (r *Registry) GetPassiveModules() []PassiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]PassiveModule, len(r.passiveModules))
	copy(result, r.passiveModules)
	return result
}

// GetActiveModulesByIDs filters active modules by IDs.
// Input IDs are lowercased for user-input normalization; registered module IDs
// are guaranteed lowercase by RegisterActive.
func (r *Registry) GetActiveModulesByIDs(ids []string) []ActiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[strings.ToLower(id)] = struct{}{}
	}

	var result []ActiveModule
	for _, m := range r.activeModules {
		if _, ok := idSet[m.ID()]; ok {
			result = append(result, m)
		}
	}
	return result
}

// GetPassiveModulesByIDs filters passive modules by IDs.
// Input IDs are lowercased for user-input normalization; registered module IDs
// are guaranteed lowercase by RegisterPassive.
func (r *Registry) GetPassiveModulesByIDs(ids []string) []PassiveModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[strings.ToLower(id)] = struct{}{}
	}

	var result []PassiveModule
	for _, m := range r.passiveModules {
		if _, ok := idSet[m.ID()]; ok {
			result = append(result, m)
		}
	}
	return result
}

// GetActiveModulesID returns IDs of all active modules.
func (r *Registry) GetActiveModulesID() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, len(r.activeModules))
	for i, m := range r.activeModules {
		ids[i] = m.ID()
	}
	return ids
}

// GetPassiveModulesID returns IDs of all passive modules.
func (r *Registry) GetPassiveModulesID() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, len(r.passiveModules))
	for i, m := range r.passiveModules {
		ids[i] = m.ID()
	}
	return ids
}

// ResolveModuleTags returns deduplicated module IDs for all modules that have
// at least one of the given tags (OR condition). Tags are matched case-insensitively.
func (r *Registry) ResolveModuleTags(tags []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tagSet := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = struct{}{}
	}

	seen := make(map[string]struct{})
	var result []string

	addIfTagged := func(id string, moduleTags []string) {
		if _, ok := seen[id]; ok {
			return
		}
		for _, mt := range moduleTags {
			if _, ok := tagSet[strings.ToLower(mt)]; ok {
				seen[id] = struct{}{}
				result = append(result, id)
				return
			}
		}
	}

	for _, m := range r.activeModules {
		addIfTagged(m.ID(), m.Tags())
	}
	for _, m := range r.passiveModules {
		addIfTagged(m.ID(), m.Tags())
	}

	return result
}

// ResolveModulePatterns resolves user-provided patterns into exact module IDs
// using fuzzy matching. Each pattern is matched (case-insensitive) against:
//   - Exact module ID match
//   - Substring match on module ID
//   - Substring match on module name
//
// Returns deduplicated list of matched module IDs (both active and passive).
// Patterns that match nothing are silently ignored.
func (r *Registry) ResolveModulePatterns(patterns []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{})
	var result []string

	addModule := func(id string) {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			result = append(result, id)
		}
	}

	for _, pattern := range patterns {
		p := strings.ToLower(pattern)
		if p == "all" {
			return []string{"all"}
		}

		// Pass 1: exact ID match
		exactMatch := false
		for _, m := range r.activeModules {
			if m.ID() == p {
				addModule(m.ID())
				exactMatch = true
			}
		}
		for _, m := range r.passiveModules {
			if m.ID() == p {
				addModule(m.ID())
				exactMatch = true
			}
		}
		if exactMatch {
			continue
		}

		// Pass 2: substring match on ID, then name
		for _, m := range r.activeModules {
			if strings.Contains(m.ID(), p) || strings.Contains(strings.ToLower(m.Name()), p) {
				addModule(m.ID())
			}
		}
		for _, m := range r.passiveModules {
			if strings.Contains(m.ID(), p) || strings.Contains(strings.ToLower(m.Name()), p) {
				addModule(m.ID())
			}
		}
	}

	return result
}

// ActiveModuleCount returns the number of active modules.
func (r *Registry) ActiveModuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.activeModules)
}

// PassiveModuleCount returns the number of passive modules.
func (r *Registry) PassiveModuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.passiveModules)
}
