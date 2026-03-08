// Package builtin provides built-in discovery modules.
package builtin

import (
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
)

// BuiltInModules maps module names to their constructors.
// Only wildcard is built-in. Other modules (backup, js, static) are now
// configured via YAML in examples/main-modules.yaml.
var BuiltInModules = map[string]func() module.Module{
	"wildcard": func() module.Module { return NewWildcardModule() },
}

// RegisterBuiltins registers enabled built-in modules to the registry.
func RegisterBuiltins(registry *module.Registry, cfg *config.ModuleConfig) {
	if cfg == nil || !cfg.Enabled {
		return
	}

	for name, constructor := range BuiltInModules {
		if cfg.IsBuiltInEnabled(name) {
			m := constructor()
			registry.Register(m)
		}
	}
}

// RegisterAll registers all built-in modules regardless of config.
func RegisterAll(registry *module.Registry) {
	for _, constructor := range BuiltInModules {
		registry.Register(constructor())
	}
}

// AvailableModules returns list of available built-in module names.
func AvailableModules() []string {
	names := make([]string, 0, len(BuiltInModules))
	for name := range BuiltInModules {
		names = append(names, name)
	}
	return names
}

// NewRegistry creates a new registry with built-in modules based on config.
func NewRegistry(cfg *config.ModuleConfig) *module.Registry {
	registry := module.NewRegistry()

	if cfg != nil && cfg.Enabled {
		// Register built-in modules
		RegisterBuiltins(registry, cfg)

		// Register custom modules from config
		for _, customCfg := range cfg.Custom {
			if m, err := module.NewConfiguredModule(customCfg); err == nil {
				registry.Register(m)
			}
		}
	}

	return registry
}

// NewDefaultRegistry creates a registry with all built-in modules enabled.
func NewDefaultRegistry() *module.Registry {
	cfg := config.DefaultModuleConfig()
	return NewRegistry(&cfg)
}
