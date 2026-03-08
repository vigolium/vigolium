package database

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// ScanLogger provides a convenient interface for writing scan log entries.
// It is safe to use with a nil Repository (all methods become no-ops).
type ScanLogger struct {
	repo     *Repository
	scanUUID string
}

// NewScanLogger creates a ScanLogger for the given scan. If repo is nil, all
// logging methods are no-ops so callers don't need nil checks.
func NewScanLogger(repo *Repository, scanUUID string) *ScanLogger {
	return &ScanLogger{repo: repo, scanUUID: scanUUID}
}

// Info logs an informational message.
func (l *ScanLogger) Info(phase, message string) {
	l.log("info", phase, message, nil)
}

// Warn logs a warning message.
func (l *ScanLogger) Warn(phase, message string) {
	l.log("warn", phase, message, nil)
}

// Error logs an error message.
func (l *ScanLogger) Error(phase, message string) {
	l.log("error", phase, message, nil)
}

// InfoWithMeta logs an informational message with structured metadata.
func (l *ScanLogger) InfoWithMeta(phase, message string, meta map[string]interface{}) {
	l.log("info", phase, message, meta)
}

func (l *ScanLogger) log(level, phase, message string, meta map[string]interface{}) {
	if l == nil || l.repo == nil || l.scanUUID == "" {
		return
	}

	entry := &ScanLog{
		ScanUUID:  l.scanUUID,
		Level:     level,
		Phase:     phase,
		Message:   message,
		CreatedAt: time.Now(),
	}

	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			entry.Metadata = string(b)
		}
	}

	if err := l.repo.CreateScanLog(context.Background(), entry); err != nil {
		zap.L().Debug("Failed to write scan log", zap.Error(err))
	}
}
