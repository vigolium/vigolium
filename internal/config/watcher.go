package config

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// ConfigWatcher watches the config file for changes and hot-reloads
// reloadable sections into the shared Settings pointer.
type ConfigWatcher struct {
	configPath string
	dirPath    string
	fileName   string
	settings   *Settings
	watcher    *fsnotify.Watcher
	selfWrite  atomic.Bool
	stopCh     chan struct{}
	once       sync.Once

	onReloadMu sync.RWMutex
	onReload   []func(changed []string)
}

// reloadableSections lists config sections that can be hot-reloaded at runtime.
// server and database require a restart.
var reloadableSections = map[string]bool{
	"scope":              true,
	"notify":             true,
	"dynamic-assessment": true,
	"mutation_strategy":  true,
	"scanning_strategy":  true,
	"scanning_pace":      true,
	"storage":            true,
}

// NewConfigWatcher creates a watcher for the given config file.
// It watches the parent directory (not the file directly) to handle
// editors that save via rename+create (vim, emacs, etc.).
func NewConfigWatcher(configPath string, settings *Settings) (*ConfigWatcher, error) {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dirPath := filepath.Dir(absPath)
	if err := w.Add(dirPath); err != nil {
		_ = w.Close()
		return nil, err
	}

	return &ConfigWatcher{
		configPath: absPath,
		dirPath:    dirPath,
		fileName:   filepath.Base(absPath),
		settings:   settings,
		watcher:    w,
		stopCh:     make(chan struct{}),
	}, nil
}

// MarkSelfWrite sets the self-write flag so the next file event is skipped.
// Call this before writing config to disk from the API.
func (cw *ConfigWatcher) MarkSelfWrite() {
	cw.selfWrite.Store(true)
}

// Start begins watching for config file changes in a background goroutine.
func (cw *ConfigWatcher) Start() {
	go cw.loop()
	zap.L().Info("Config watcher started",
		zap.String("file", cw.configPath))
}

// Close stops the watcher and releases resources.
func (cw *ConfigWatcher) Close() error {
	cw.once.Do(func() {
		close(cw.stopCh)
	})
	return cw.watcher.Close()
}

// OnReload registers a callback that is invoked after config sections are hot-reloaded.
// The callback receives the list of section names that changed.
func (cw *ConfigWatcher) OnReload(fn func(changed []string)) {
	cw.onReloadMu.Lock()
	cw.onReload = append(cw.onReload, fn)
	cw.onReloadMu.Unlock()
}

func (cw *ConfigWatcher) loop() {
	var debounce *time.Timer

	for {
		select {
		case <-cw.stopCh:
			if debounce != nil {
				debounce.Stop()
			}
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Only react to our config file
			if filepath.Base(event.Name) != cw.fileName {
				continue
			}

			// Only care about writes and creates (editors do rename+create)
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			// Debounce: reset timer on each event, fire after 500ms of quiet
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(500*time.Millisecond, cw.reload)

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			zap.L().Error("Config watcher error", zap.Error(err))
		}
	}
}

func (cw *ConfigWatcher) reload() {
	// Check and clear self-write flag
	if cw.selfWrite.CompareAndSwap(true, false) {
		zap.L().Debug("Config watcher: skipping self-write event")
		return
	}

	newSettings, err := LoadSettings(cw.configPath)
	if err != nil {
		zap.L().Error("Config watcher: failed to load config", zap.Error(err))
		return
	}

	// Detect which sections changed
	oldFlat := sectionMap(FlattenSettings(cw.settings))
	newFlat := sectionMap(FlattenSettings(newSettings))

	var changed []string
	var nonReloadable []string

	allSections := mergeSectionKeys(oldFlat, newFlat)
	for _, section := range allSections {
		if oldFlat[section] != newFlat[section] {
			if reloadableSections[section] {
				changed = append(changed, section)
			} else {
				nonReloadable = append(nonReloadable, section)
			}
		}
	}

	if len(changed) == 0 && len(nonReloadable) == 0 {
		zap.L().Debug("Config watcher: no changes detected")
		return
	}

	// Warn about non-reloadable sections
	for _, section := range nonReloadable {
		zap.L().Warn("Config section changed but requires restart to take effect",
			zap.String("section", section))
	}

	if len(changed) == 0 {
		return
	}

	// Apply reloadable sections
	for _, section := range changed {
		switch section {
		case "scope":
			cw.settings.Scope = newSettings.Scope
		case "notify":
			cw.settings.Notify = newSettings.Notify
		case "dynamic-assessment":
			cw.settings.DynamicAssessment = newSettings.DynamicAssessment
		case "mutation_strategy":
			cw.settings.MutationStrategy = newSettings.MutationStrategy
		case "scanning_strategy":
			cw.settings.ScanningStrategy = newSettings.ScanningStrategy
		case "scanning_pace":
			cw.settings.ScanningPace = newSettings.ScanningPace
		case "storage":
			cw.settings.Storage = newSettings.Storage
		}
	}

	zap.L().Info("Hot-reloaded config sections",
		zap.Strings("sections", changed))

	// Fire registered callbacks
	cw.onReloadMu.RLock()
	callbacks := cw.onReload
	cw.onReloadMu.RUnlock()
	for _, fn := range callbacks {
		fn(changed)
	}
}

// sectionMap groups flattened config entries by their top-level section
// and produces a string representation for comparison.
func sectionMap(entries []ConfigEntry) map[string]string {
	grouped := make(map[string][]string)
	for _, e := range entries {
		section := e.Key
		if idx := strings.IndexByte(e.Key, '.'); idx > 0 {
			section = e.Key[:idx]
		}
		grouped[section] = append(grouped[section], e.Key+"="+e.Value)
	}

	result := make(map[string]string, len(grouped))
	for section, kvs := range grouped {
		sort.Strings(kvs)
		result[section] = strings.Join(kvs, "\n")
	}
	return result
}

// mergeSectionKeys returns a sorted, deduplicated list of section names from both maps.
func mergeSectionKeys(a, b map[string]string) []string {
	seen := make(map[string]struct{})
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
