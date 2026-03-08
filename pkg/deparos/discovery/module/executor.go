package module

import (
	"context"

	"go.uber.org/zap"
)

// Executor executes matching modules and merges their results.
type Executor struct {
	registry *Registry
	filter   *TaskFilter
	logger   *zap.Logger
}

// NewExecutor creates a new module executor.
func NewExecutor(registry *Registry, filter *TaskFilter, logger *zap.Logger) *Executor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Executor{
		registry: registry,
		filter:   filter,
		logger:   logger,
	}
}

// ExecuteDirectory executes all matching modules for a discovered directory.
// Returns merged result from all modules.
func (e *Executor) ExecuteDirectory(ctx context.Context, event *DirectoryEvent) (*ModuleResult, error) {
	if e.registry == nil {
		return nil, nil
	}

	// Find all matching modules
	matching := e.registry.MatchDirectory(event.Path)
	if len(matching) == 0 {
		return nil, nil
	}

	e.logger.Debug("Executing directory modules",
		zap.String("path", event.Path),
		zap.Int("matchingModules", len(matching)))

	// Execute each module and merge results
	merged := &ModuleResult{}
	for _, m := range matching {
		result, err := m.OnDirectoryMatch(ctx, event)
		if err != nil {
			e.logger.Warn("Module directory error",
				zap.String("module", m.Name()),
				zap.String("path", event.Path),
				zap.Error(err))
			continue
		}

		if result != nil {
			e.logger.Debug("Module returned result",
				zap.String("module", m.Name()),
				zap.String("path", event.Path),
				zap.Bool("stopRecursion", result.StopRecursion),
				zap.Bool("skipDefault", result.SkipDefaultLogic))

			merged.MergeResult(result)

			// Register block patterns with filter
			if e.filter != nil {
				for _, pattern := range result.BlockTaskPatterns {
					if err := e.filter.AddBlockPattern(pattern); err != nil {
						e.logger.Warn("Failed to add block pattern",
							zap.String("pattern", pattern),
							zap.Error(err))
					}
				}
			}

			// Stop processing if module requests it
			if result.StopProcessing {
				e.logger.Debug("Module requested stop processing",
					zap.String("module", m.Name()))
				break
			}
		}
	}

	return merged, nil
}

// ExecuteFile executes all matching modules for a discovered file.
// Returns merged result from all modules.
func (e *Executor) ExecuteFile(ctx context.Context, event *FileEvent) (*ModuleResult, error) {
	if e.registry == nil {
		return nil, nil
	}

	// Find all matching modules
	matching := e.registry.MatchFile(event.Path)
	if len(matching) == 0 {
		return nil, nil
	}

	e.logger.Debug("Executing file modules",
		zap.String("path", event.Path),
		zap.Int("matchingModules", len(matching)))

	// Execute each module and merge results
	merged := &ModuleResult{}
	for _, m := range matching {
		result, err := m.OnFileMatch(ctx, event)
		if err != nil {
			e.logger.Warn("Module file error",
				zap.String("module", m.Name()),
				zap.String("path", event.Path),
				zap.Error(err))
			continue
		}

		if result != nil {
			e.logger.Debug("Module returned result",
				zap.String("module", m.Name()),
				zap.String("path", event.Path))

			merged.MergeResult(result)

			// Register block patterns with filter
			if e.filter != nil {
				for _, pattern := range result.BlockTaskPatterns {
					if err := e.filter.AddBlockPattern(pattern); err != nil {
						e.logger.Warn("Failed to add block pattern",
							zap.String("pattern", pattern),
							zap.Error(err))
					}
				}
			}

			// Stop processing if module requests it
			if result.StopProcessing {
				e.logger.Debug("Module requested stop processing",
					zap.String("module", m.Name()))
				break
			}
		}
	}

	return merged, nil
}

// Registry returns the module registry.
func (e *Executor) Registry() *Registry {
	return e.registry
}

// Filter returns the task filter.
func (e *Executor) Filter() *TaskFilter {
	return e.filter
}

// HasModules returns true if any modules are registered.
func (e *Executor) HasModules() bool {
	return e.registry != nil && e.registry.Count() > 0
}

// HasEnabledModules returns true if any enabled modules exist.
func (e *Executor) HasEnabledModules() bool {
	return e.registry != nil && len(e.registry.Enabled()) > 0
}
