package notify

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

const (
	defaultQueueSize       = 1000
	defaultShutdownTimeout = 30 * time.Second
)

// Config configures the notification Manager.
type Config struct {
	// Backends to send notifications to
	Backends []Backend

	// AllowedSeverities filters which severities to notify.
	// Use "all" to notify all severities.
	AllowedSeverities []string

	// QueueSize is the notification queue buffer size.
	// Default: 1000
	QueueSize int

	// ShutdownTimeout is how long to wait for pending notifications on Close.
	// Default: 30s
	ShutdownTimeout time.Duration
}

// notification represents a queued notification item.
type notification struct {
	result *output.ResultEvent // nil if raw message
	raw    string              // raw message text
}

// Manager manages async notification queue and multiple backends.
type Manager struct {
	backends          []Backend
	allowedSeverities []string
	notifyAll         bool

	queue  chan *notification
	ctx    context.Context
	cancel context.CancelFunc
	wg     conc.WaitGroup
	closed atomic.Bool

	shutdownTimeout time.Duration
}

// New creates a new notification Manager.
func New(cfg Config) *Manager {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		backends:          cfg.Backends,
		allowedSeverities: cfg.AllowedSeverities,
		notifyAll:         containsIgnoreCase(cfg.AllowedSeverities, "all"),
		queue:             make(chan *notification, cfg.QueueSize),
		ctx:               ctx,
		cancel:            cancel,
		shutdownTimeout:   cfg.ShutdownTimeout,
	}

	// Start worker
	m.wg.Go(func() {
		m.worker()
	})

	zap.L().Info("[Notify] Manager started",
		zap.Int("backends", len(cfg.Backends)),
		zap.Int("queue_size", cfg.QueueSize))

	return m
}

// Send queues a scan result notification (non-blocking).
// Returns immediately after queueing.
func (m *Manager) Send(result *output.ResultEvent) error {
	if m.closed.Load() {
		return nil
	}

	// Check severity filter
	if !m.shouldNotify(result.Info.Severity.String()) {
		return nil
	}

	select {
	case m.queue <- &notification{result: result}:
		return nil
	default:
		zap.L().Warn("[Notify] Queue full, dropping notification",
			zap.String("module", result.Info.Name),
			zap.String("url", result.URL))
		return nil
	}
}

// SendRaw queues a raw text message (non-blocking).
func (m *Manager) SendRaw(msg string) error {
	if m.closed.Load() {
		return nil
	}

	select {
	case m.queue <- &notification{raw: msg}:
		return nil
	default:
		zap.L().Warn("[Notify] Queue full, dropping raw message")
		return nil
	}
}

// Close waits for all pending notifications to be sent, then closes all backends.
func (m *Manager) Close() {
	if !m.closed.CompareAndSwap(false, true) {
		return
	}

	pending := len(m.queue)
	if pending > 0 {
		zap.L().Info("[Notify] Waiting for pending notifications",
			zap.Int("pending", pending))
	}

	// Signal worker to stop after draining queue
	m.cancel()

	// Wait for worker with timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("[Notify] panic in worker", zap.Any("panic", r))
			}
		}()
		m.wg.Wait()
	}()

	select {
	case <-done:
		zap.L().Info("[Notify] All notifications sent")
	case <-time.After(m.shutdownTimeout):
		zap.L().Warn("[Notify] Shutdown timeout, some notifications may be lost",
			zap.Int("remaining", len(m.queue)))
	}

	// Close all backends
	for _, b := range m.backends {
		b.Close()
	}
}

// worker processes notifications from the queue.
func (m *Manager) worker() {
	for {
		select {
		case n := <-m.queue:
			if n == nil {
				continue
			}
			m.dispatch(n)
		case <-m.ctx.Done():
			// Drain remaining queue
			for {
				select {
				case n := <-m.queue:
					if n != nil {
						m.dispatch(n)
					}
				default:
					return
				}
			}
		}
	}
}

// dispatch sends notification to all backends.
func (m *Manager) dispatch(n *notification) {
	for _, backend := range m.backends {
		var err error
		if n.result != nil {
			err = backend.Send(n.result)
		} else {
			err = backend.SendRaw(n.raw)
		}
		if err != nil {
			zap.L().Warn("[Notify] Backend send failed", zap.Error(err))
		}
	}
}

// shouldNotify checks if the severity should trigger a notification.
func (m *Manager) shouldNotify(severity string) bool {
	if m.notifyAll {
		return true
	}
	return containsIgnoreCase(m.allowedSeverities, severity)
}

// containsIgnoreCase checks if slice contains item (case-insensitive).
func containsIgnoreCase(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
