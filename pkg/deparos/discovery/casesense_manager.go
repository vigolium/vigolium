package discovery

import (
	"context"
	"net/url"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/casesense"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"go.uber.org/zap"
)

// CaseSensitivityManager tracks detection state and results.
// Thread-safe: detection can be triggered from multiple workers.
type CaseSensitivityManager struct {
	mu           sync.RWMutex
	detector     *casesense.Detector
	fileDetected bool
	dirDetected  bool
	fileMode     config.CaseSensitivityMode
	dirMode      config.CaseSensitivityMode
	enabled      bool // false if user specified explicit mode (not auto_detect)
}

// NewCaseSensitivityManager creates a manager for lazy case sensitivity detection.
// If initialMode is not CaseAutoDetect, detection is disabled and the explicit mode is used.
func NewCaseSensitivityManager(detector *casesense.Detector, initialMode config.CaseSensitivityMode) *CaseSensitivityManager {
	m := &CaseSensitivityManager{
		detector: detector,
		enabled:  initialMode == config.CaseAutoDetect,
	}

	// If explicit mode specified, use it for both file and dir
	if initialMode != config.CaseAutoDetect {
		m.fileMode = initialMode
		m.dirMode = initialMode
		m.fileDetected = true
		m.dirDetected = true
	}

	return m
}

// OnValidDiscovery is called when a valid resource is discovered.
// Triggers detection if not already done for this resource type.
// This method is thread-safe and idempotent.
func (m *CaseSensitivityManager) OnValidDiscovery(
	ctx context.Context,
	discoveredURL *url.URL,
	sample *fingerprint.Sample,
	isDirectory bool,
) {
	if !m.enabled {
		return
	}

	// Quick check without lock
	if isDirectory {
		m.mu.RLock()
		detected := m.dirDetected
		m.mu.RUnlock()
		if detected {
			return
		}
	} else {
		m.mu.RLock()
		detected := m.fileDetected
		m.mu.RUnlock()
		if detected {
			return
		}
	}

	// Need to detect - acquire write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring lock (another goroutine may have detected)
	if isDirectory && m.dirDetected {
		return
	}
	if !isDirectory && m.fileDetected {
		return
	}

	// Skip if path has no alpha chars
	if !casesense.HasAlphaChars(discoveredURL.Path) {
		logger.Debug("Skipping case detection - path has no alpha chars",
			zap.String("path", discoveredURL.Path),
			zap.Bool("isDirectory", isDirectory))
		return
	}

	var resourceType casesense.DetectionType
	if isDirectory {
		resourceType = casesense.DetectionDir
	} else {
		resourceType = casesense.DetectionFile
	}

	mode, err := m.detector.DetectFromValid(ctx, discoveredURL, sample, resourceType)
	if err != nil {
		logger.Warn("Case sensitivity detection failed, defaulting to insensitive",
			zap.Error(err),
			zap.String("type", resourceType.String()))
		mode = config.CaseInsensitive
	}

	if isDirectory {
		m.dirMode = mode
		m.dirDetected = true
		logger.Info("Case sensitivity detected for directories",
			zap.String("mode", string(mode)))
	} else {
		m.fileMode = mode
		m.fileDetected = true
		logger.Info("Case sensitivity detected for files",
			zap.String("mode", string(mode)))
	}
}

// FileMode returns the detected case sensitivity mode for files.
// Returns CaseAutoDetect if not yet detected.
func (m *CaseSensitivityManager) FileMode() config.CaseSensitivityMode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.fileDetected {
		return config.CaseAutoDetect
	}
	return m.fileMode
}

// DirMode returns the detected case sensitivity mode for directories.
// Returns CaseAutoDetect if not yet detected.
func (m *CaseSensitivityManager) DirMode() config.CaseSensitivityMode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.dirDetected {
		return config.CaseAutoDetect
	}
	return m.dirMode
}

// IsFileCaseSensitive returns true if files should be treated as case-sensitive.
// Returns false (case-insensitive) if not yet detected (safe default).
func (m *CaseSensitivityManager) IsFileCaseSensitive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.fileMode == config.CaseSensitive
}

// IsDirCaseSensitive returns true if directories should be treated as case-sensitive.
// Returns false (case-insensitive) if not yet detected (safe default).
func (m *CaseSensitivityManager) IsDirCaseSensitive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.dirMode == config.CaseSensitive
}

// FileDetected returns true if file case sensitivity has been detected.
func (m *CaseSensitivityManager) FileDetected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fileDetected
}

// DirDetected returns true if directory case sensitivity has been detected.
func (m *CaseSensitivityManager) DirDetected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dirDetected
}

// IsEnabled returns true if auto-detection is enabled.
func (m *CaseSensitivityManager) IsEnabled() bool {
	return m.enabled
}
