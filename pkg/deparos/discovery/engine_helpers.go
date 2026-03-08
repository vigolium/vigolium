package discovery

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/deparos/wordlist"
	"go.uber.org/zap"
)

// State represents the discovery engine lifecycle state.
type State int

const (
	// StateIdle indicates engine hasn't started
	StateIdle State = iota
	// StateRunning indicates active discovery
	StateRunning
	// StatePaused indicates user-paused discovery
	StatePaused
	// StateStopped indicates terminated session (terminal state)
	StateStopped
)

// String returns human-readable state name.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateRunning:
		return "RUNNING"
	case StatePaused:
		return "PAUSED"
	case StateStopped:
		return "STOPPED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// collectDirectoryURLs walks directories and returns their URLs.
func collectDirectoryURLs(s storage.Storage) []string {
	urls := make([]string, 0, 1000)
	_ = s.WalkDirectories(func(node *storage.DiscoveredNode) error {
		urls = append(urls, node.URL().String())
		return nil
	})
	return urls
}

// extractFilenamesFromSitemap extracts filenames and extensions from existing sitemap URLs.
func extractFilenamesFromSitemap(e *Engine) error {
	return e.storage.WalkFiles(func(node *storage.DiscoveredNode) error {
		name, ext := ExtractFilename(node.URL().Path)
		if name != "" {
			e.AddObservedNameTrusted(name)
		}
		if ext != "" {
			e.addObservedExtensionIfNew(ext)
		}

		// Store full filename for literal file testing (preserves hashes like app.b5ca88ec.js)
		rawFilename, rawExt := ExtractRawFilename(node.URL().Path)
		if rawFilename != "" && rawExt != "" {
			if _, ok := config.AllowedObservedExtensions[rawExt]; ok {
				e.AddObservedFileTrusted(rawFilename)
			}
		}

		// Extract paths and segments
		if e.config.Filenames.UseObservedPaths {
			// Store raw full path
			fullPath := ExtractPathForFuzzing(node.URL().Path)
			if fullPath != "" {
				e.AddObservedPathTrusted(fullPath)
			}

			// Extract name/extension from each segment to avoid adding full filenames like "app.js"
			segments := ExtractPathSegments(node.URL().Path)
			for _, segment := range segments {
				name, ext := ExtractFilename("/" + segment)
				if name != "" {
					e.AddObservedNameTrusted(name)
				}
				if ext != "" {
					e.addObservedExtensionIfNew(ext)
				}
			}
		}
		return nil
	})
}

// extractWordsFromResponses extracts words from stored response bodies.
// Returns count of words extracted.
func extractWordsFromResponses(e *Engine) int {
	count := 0
	_ = e.storage.WalkFiles(func(node *storage.DiscoveredNode) error {
		resp := node.Response()
		if resp == nil || len(resp.Body) == 0 {
			return nil
		}

		contentType := resp.MIMEType

		err := e.wordlistExtractor.ExtractBytes(
			e.ctx,
			resp.Body,
			contentType,
			func(token *wordlist.Token) {
				e.AddObservedName(token.Value)
				count++
			},
		)

		if err != nil {
			logger.Debug("Word extraction failed for stored response",
				zap.String("url", node.URL().String()),
				zap.Error(err))
		}

		return nil
	})
	return count
}

// addTasks adds multiple tasks and returns count of successfully added tasks.
// Deduplication happens in AddTask().
func (e *Engine) addTasks(tasks []Task) int {
	added := 0
	for _, task := range tasks {
		if e.AddTask(task) {
			added++
		}
	}
	return added
}

// incrementTasksBlocked atomically increments the TasksBlocked metric.
func (e *Engine) incrementTasksBlocked() {
	e.metricsMu.Lock()
	e.metrics.TasksBlocked++
	e.metricsMu.Unlock()
}

// incrementTasksDeduped atomically increments the TasksDeduped metric and returns new count.
func (e *Engine) incrementTasksDeduped() uint64 {
	e.metricsMu.Lock()
	e.metrics.TasksDeduped++
	count := e.metrics.TasksDeduped
	e.metricsMu.Unlock()
	return count
}

// incrementTasksGenerated atomically increments the TasksGenerated metric and returns new count.
func (e *Engine) incrementTasksGenerated() uint64 {
	e.metricsMu.Lock()
	e.metrics.TasksGenerated++
	count := e.metrics.TasksGenerated
	e.metricsMu.Unlock()
	return count
}

// handleNewExtension processes a newly discovered extension.
// Adds to observed collections and generates dynamic tasks if configured.
func (e *Engine) handleNewExtension(ext string, depth uint16) {
	wasNew := e.addObservedExtensionIfNew(ext)
	if wasNew && e.config.Extensions.TestObserved {
		logger.Info("New extension discovered, generating dynamic tasks",
			zap.String("extension", ext))
		e.generateObservedExtensionTasks(ext, depth)
	}
}

// getObservedExtensionsSnapshot returns a snapshot of all seen extensions.
func (e *Engine) getObservedExtensionsSnapshot() []string {
	return e.observedExtensions.GetAllItems()
}
