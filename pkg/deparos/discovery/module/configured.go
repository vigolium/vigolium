package module

import (
	"context"
	"regexp"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
)

// ConfiguredModule wraps a CustomModuleConfig to implement Module interface.
type ConfiguredModule struct {
	*BaseModule
	cfg            config.CustomModuleConfig
	blockPatterns  []*regexp.Regexp
	patternMatcher *PatternMatcher
}

// NewConfiguredModule creates a Module from a CustomModuleConfig.
func NewConfiguredModule(cfg config.CustomModuleConfig) (*ConfiguredModule, error) {
	// Convert config patterns to module patterns
	patterns := make([]Pattern, len(cfg.Patterns))
	for i, p := range cfg.Patterns {
		patternType, err := ParsePatternType(p.Type)
		if err != nil {
			return nil, err
		}
		patterns[i] = Pattern{
			Type:       patternType,
			Value:      p.Value,
			Negated:    p.Negated,
			MatchFiles: p.MatchFiles,
		}
		if err := patterns[i].Compile(); err != nil {
			return nil, err
		}
	}

	// Pre-compile block patterns
	var blockPatterns []*regexp.Regexp
	for _, bp := range cfg.Actions.BlockTaskPatterns {
		re, err := regexp.Compile(bp)
		if err != nil {
			continue // Skip invalid patterns
		}
		blockPatterns = append(blockPatterns, re)
	}

	base := NewBaseModule(cfg.Name, cfg.Description, cfg.Priority, patterns)
	base.SetEnabled(cfg.Enabled)

	return &ConfiguredModule{
		BaseModule:     base,
		cfg:            cfg,
		blockPatterns:  blockPatterns,
		patternMatcher: NewPatternMatcher(patterns),
	}, nil
}

// OnDirectoryMatch implements Module interface.
func (m *ConfiguredModule) OnDirectoryMatch(ctx context.Context, event *DirectoryEvent) (*ModuleResult, error) {
	if !m.patternMatcher.MatchesDirectory(event.Path) {
		return nil, nil
	}

	result := &ModuleResult{
		StopRecursion:     m.cfg.Actions.StopRecursion,
		SkipDefaultLogic:  m.cfg.Actions.SkipDefaultLogic,
		BlockTaskPatterns: m.cfg.Actions.BlockTaskPatterns,
	}

	// Build task specs from config (one TaskSpec per extension)
	for _, tc := range m.cfg.Actions.Tasks {
		priority := uint8(6) // default
		if tc.Priority != nil {
			priority = *tc.Priority
		}

		// If no extensions specified, create one task with empty extension
		if len(tc.Extensions) == 0 {
			result.Tasks = append(result.Tasks, TaskSpec{
				WordlistSource: tc.Wordlist,
				Extension:      "",
				Priority:       priority,
				CustomFile:     tc.File,
				CustomInline:   tc.Inline,
			})
		} else {
			// Create one task per extension
			for _, ext := range tc.Extensions {
				result.Tasks = append(result.Tasks, TaskSpec{
					WordlistSource: tc.Wordlist,
					Extension:      NormalizeExtension(ext),
					Priority:       priority,
					CustomFile:     tc.File,
					CustomInline:   tc.Inline,
				})
			}
		}
	}

	return result, nil
}

// OnFileMatch implements Module interface.
func (m *ConfiguredModule) OnFileMatch(ctx context.Context, event *FileEvent) (*ModuleResult, error) {
	if !m.patternMatcher.MatchesFile(event.Path) {
		return nil, nil
	}

	result := &ModuleResult{
		SkipDefaultLogic: m.cfg.Actions.SkipDefaultLogic,
	}

	return result, nil
}

// ShouldAddTask implements Module interface.
func (m *ConfiguredModule) ShouldAddTask(task queue.TaskInfo) bool {
	if len(m.blockPatterns) == 0 {
		return true
	}

	baseURL := string(task.FullURL())
	for _, re := range m.blockPatterns {
		if re.MatchString(baseURL) {
			return false
		}
	}

	return true
}

// LoadConfiguredModules creates modules from configuration.
func LoadConfiguredModules(configs []config.CustomModuleConfig) ([]Module, error) {
	var modules []Module
	for _, cfg := range configs {
		m, err := NewConfiguredModule(cfg)
		if err != nil {
			return nil, err
		}
		modules = append(modules, m)
	}
	return modules, nil
}
