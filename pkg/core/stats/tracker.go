package stats

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/terminal"
)

const printInterval = 5 * time.Second

// Tracker tracks scan statistics and prints progress periodically.
type Tracker struct {
	processed atomic.Int64
	findings  atomic.Int64
	blocked   atomic.Int64
	total     int64 // 0 = unknown
	startTime time.Time
	cancel    context.CancelFunc
	done      chan struct{}

	// For speed calculation
	lastCount int64
	lastTime  time.Time
}

// New creates a new stats Tracker. Returns nil if silent is true.
// If total is 0, it means the total count is unknown.
func New(total int64, silent bool) *Tracker {
	if silent {
		return nil
	}
	return &Tracker{
		total: total,
		done:  make(chan struct{}),
	}
}

// Increment adds 1 to the processed count (thread-safe).
func (t *Tracker) Increment() {
	t.processed.Add(1)
}

// Processed returns the current processed count (thread-safe).
func (t *Tracker) Processed() int64 {
	return t.processed.Load()
}

// Total returns the known total count (0 = unknown).
func (t *Tracker) Total() int64 {
	return t.total
}

// IncrementFindings adds 1 to the findings count (thread-safe).
func (t *Tracker) IncrementFindings() {
	t.findings.Add(1)
}

// Findings returns the current findings count (thread-safe).
func (t *Tracker) Findings() int64 {
	return t.findings.Load()
}

// IncrementBlocked adds 1 to the blocked count (thread-safe).
func (t *Tracker) IncrementBlocked() {
	t.blocked.Add(1)
}

// Blocked returns the current blocked count (thread-safe).
func (t *Tracker) Blocked() int64 {
	return t.blocked.Load()
}

// Start begins printing statistics every 5 seconds.
// Should be called once. Blocks until ctx is done or Stop is called.
func (t *Tracker) Start(ctx context.Context) {
	t.startTime = time.Now()
	t.lastTime = t.startTime
	t.lastCount = 0

	ctx, t.cancel = context.WithCancel(ctx)
	go t.run(ctx)
}

// Stop stops the tracker goroutine and waits for it to finish.
func (t *Tracker) Stop() {
	if t.cancel != nil {
		t.cancel()
		<-t.done
	}
}

func (t *Tracker) run(ctx context.Context) {
	defer close(t.done)

	ticker := time.NewTicker(printInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.printStats()
		}
	}
}

func (t *Tracker) printStats() {
	now := time.Now()
	currentCount := t.processed.Load()

	// Calculate speed (tasks per second)
	elapsed := now.Sub(t.lastTime).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(currentCount-t.lastCount) / elapsed
	}

	// Update last values for next interval
	t.lastCount = currentCount
	t.lastTime = now

	// Calculate runtime
	runtime := now.Sub(t.startTime)

	// Format output with colors and symbols
	findings := t.findings.Load()
	var msg string
	if t.total > 0 {
		msg = fmt.Sprintf("%s %s Processed: %s | Speed: %s | Findings: %s | Runtime: %s",
			terminal.InfoSymbol(),
			terminal.BoldCyan("Stats"),
			terminal.Cyan(fmt.Sprintf("%d/%d", currentCount, t.total)),
			terminal.Green(fmt.Sprintf("%.1f/s", speed)),
			terminal.Orange(fmt.Sprintf("%d", findings)),
			terminal.Gray(formatDuration(runtime)))
	} else {
		msg = fmt.Sprintf("%s %s Processed: %s | Speed: %s | Findings: %s | Runtime: %s",
			terminal.InfoSymbol(),
			terminal.BoldCyan("Stats"),
			terminal.Cyan(fmt.Sprintf("%d", currentCount)),
			terminal.Green(fmt.Sprintf("%.1f/s", speed)),
			terminal.Orange(fmt.Sprintf("%d", findings)),
			terminal.Gray(formatDuration(runtime)))
	}

	fmt.Fprintln(os.Stderr, msg)
}

// formatDuration formats a duration into human-readable string like "2m30s"
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)

	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
