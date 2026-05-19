package database

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ScanLogger provides a convenient interface for writing scan log entries.
// It is safe to use with a nil Repository (all methods become no-ops).
type ScanLogger struct {
	repo     *Repository
	scanUUID string

	// Batch buffering for trace-level entries (raw console output).
	mu            sync.Mutex
	buf           []*ScanLog
	flushInterval time.Duration
	stopCh        chan struct{}
	stopped       bool
}

// NewScanLogger creates a ScanLogger for the given scan. If repo is nil, all
// logging methods are no-ops so callers don't need nil checks.
func NewScanLogger(repo *Repository, scanUUID string) *ScanLogger {
	return &ScanLogger{
		repo:          repo,
		scanUUID:      scanUUID,
		flushInterval: 2 * time.Second,
	}
}

// StartBatcher launches a background goroutine that periodically flushes
// buffered trace entries to the database. Call Close() to stop and flush.
func (l *ScanLogger) StartBatcher() {
	if l == nil || l.repo == nil || l.scanUUID == "" {
		return
	}
	l.stopCh = make(chan struct{})
	go l.batchLoop()
}

func (l *ScanLogger) batchLoop() {
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.Flush()
		case <-l.stopCh:
			return
		}
	}
}

// Flush writes all buffered trace entries to the database.
func (l *ScanLogger) Flush() {
	if l == nil || l.repo == nil {
		return
	}
	l.mu.Lock()
	entries := l.buf
	l.buf = nil
	l.mu.Unlock()

	if len(entries) == 0 {
		return
	}
	if err := l.repo.CreateScanLogBatch(context.Background(), entries); err != nil {
		zap.L().Debug("Failed to flush scan log batch", zap.Int("count", len(entries)), zap.Error(err))
	}
}

// Close stops the batcher goroutine and flushes any remaining entries.
func (l *ScanLogger) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.stopCh != nil && !l.stopped {
		l.stopped = true
		close(l.stopCh)
	}
	l.mu.Unlock()
	l.Flush()
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

// Trace logs a trace-level message (raw console output). These entries are
// buffered and flushed in batches to avoid per-line DB inserts.
func (l *ScanLogger) Trace(phase, message string) {
	if l == nil || l.repo == nil || l.scanUUID == "" {
		return
	}
	entry := &ScanLog{
		ScanUUID:  l.scanUUID,
		Level:     "trace",
		Phase:     phase,
		Message:   message,
		CreatedAt: time.Now(),
	}
	l.mu.Lock()
	l.buf = append(l.buf, entry)
	l.mu.Unlock()
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
