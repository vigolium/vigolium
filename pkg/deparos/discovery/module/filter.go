package module

import (
	"regexp"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"go.uber.org/zap"
)

// TaskFilter intercepts Engine.AddTask() to filter/modify tasks.
// This is the key mechanism for blocking recursive tasks without changing core logic.
type TaskFilter struct {
	registry      *Registry
	blockPatterns sync.Map // map[string]*regexp.Regexp - compiled patterns to block
	logger        *zap.Logger
}

// NewTaskFilter creates a new task filter.
func NewTaskFilter(registry *Registry, logger *zap.Logger) *TaskFilter {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TaskFilter{
		registry: registry,
		logger:   logger,
	}
}

// ShouldAdd is called from engine.AddTask() BEFORE task enters queue.
func (f *TaskFilter) ShouldAdd(task queue.TaskInfo) bool {
	// Spider tasks bypass all module filtering - only dedupe applies
	if task.IsFromSpider() {
		return true
	}

	baseURL := string(task.FullURL())

	// Check if any module wants to block this task
	if f.registry != nil {
		for _, module := range f.registry.Enabled() {
			if !module.ShouldAddTask(task) {
				f.logger.Debug("Task blocked by module",
					zap.String("module", module.Name()),
					zap.String("baseURL", baseURL),
					zap.String("description", task.Description()))
				return false
			}
		}
	}

	// Check block patterns set by modules
	blocked := false
	f.blockPatterns.Range(func(key, value interface{}) bool {
		pattern, ok := key.(string)
		if !ok {
			return true
		}
		re, ok := value.(*regexp.Regexp)
		if !ok {
			return true
		}
		if re.MatchString(baseURL) {
			f.logger.Debug("Task blocked by pattern",
				zap.String("pattern", pattern),
				zap.String("baseURL", baseURL))
			blocked = true
			return false // Stop iteration
		}
		return true
	})

	return !blocked
}

// AddBlockPattern adds a pattern to block.
// Called by modules to register block patterns.
func (f *TaskFilter) AddBlockPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		f.logger.Warn("Invalid block pattern",
			zap.String("pattern", pattern),
			zap.Error(err))
		return err
	}

	f.blockPatterns.Store(pattern, re)
	f.logger.Debug("Added block pattern", zap.String("pattern", pattern))
	return nil
}

// RemoveBlockPattern removes a block pattern.
func (f *TaskFilter) RemoveBlockPattern(pattern string) {
	f.blockPatterns.Delete(pattern)
	f.logger.Debug("Removed block pattern", zap.String("pattern", pattern))
}

// ClearBlockPatterns removes all block patterns.
func (f *TaskFilter) ClearBlockPatterns() {
	f.blockPatterns.Range(func(key, value interface{}) bool {
		f.blockPatterns.Delete(key)
		return true
	})
	f.logger.Debug("Cleared all block patterns")
}

// HasBlockPattern checks if a pattern is registered.
func (f *TaskFilter) HasBlockPattern(pattern string) bool {
	_, ok := f.blockPatterns.Load(pattern)
	return ok
}

// BlockPatternCount returns the number of block patterns.
func (f *TaskFilter) BlockPatternCount() int {
	count := 0
	f.blockPatterns.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetBlockPatterns returns all registered block patterns.
func (f *TaskFilter) GetBlockPatterns() []string {
	var patterns []string
	f.blockPatterns.Range(func(key, _ interface{}) bool {
		if pattern, ok := key.(string); ok {
			patterns = append(patterns, pattern)
		}
		return true
	})
	return patterns
}

// IsBlocked checks if a path would be blocked by current patterns.
func (f *TaskFilter) IsBlocked(path string) bool {
	blocked := false
	f.blockPatterns.Range(func(_, value interface{}) bool {
		re, ok := value.(*regexp.Regexp)
		if !ok {
			return true
		}
		if re.MatchString(path) {
			blocked = true
			return false
		}
		return true
	})
	return blocked
}
