package state

import (
	"fmt"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"strings"
	"sync"
	"time"
)

// CrawlPath represents the path a Crawler has taken, or is about to backtrack on.
// CRAWLJAX PARITY: Matches Java CrawlPath extends ForwardingList<Eventable> exactly.
type CrawlPath struct {
	mu sync.RWMutex

	// Sequence of Eventables executed in this path
	// CRAWLJAX PARITY: Matches Java List<Eventable> eventablePath
	eventablePath []*action.Eventable

	// CRAWLJAX PARITY: Backtrack target state ID (index in Java)
	BacktrackTarget string

	// CRAWLJAX PARITY: Backtrack result
	BacktrackSuccess bool

	// CRAWLJAX PARITY: If backtrack reached a near-duplicate instead of exact target
	// Empty string if exact match or no near-duplicate reached (-1 in Java)
	ReachedNearDup string

	// Timing (Go-specific, not in Java)
	StartTime time.Time
	EndTime   time.Time
}

// NewCrawlPath creates a new crawl path for a backtrack target.
// CRAWLJAX PARITY: Matches Java new CrawlPath(int backtrackTarget)
func NewCrawlPath(backtrackTarget string) *CrawlPath {
	return &CrawlPath{
		eventablePath:    make([]*action.Eventable, 0),
		BacktrackTarget:  backtrackTarget,
		BacktrackSuccess: false,
		ReachedNearDup:   "",
		StartTime:        time.Now(),
	}
}

// NewCrawlPathFromList creates a CrawlPath from an existing list of Eventables.
// CRAWLJAX PARITY: Matches Java new CrawlPath(List<Eventable> delegate, int backtrackTarget)
func NewCrawlPathFromList(eventables []*action.Eventable, backtrackTarget string) *CrawlPath {
	path := make([]*action.Eventable, len(eventables))
	copy(path, eventables)
	return &CrawlPath{
		eventablePath:    path,
		BacktrackTarget:  backtrackTarget,
		BacktrackSuccess: false,
		ReachedNearDup:   "",
		StartTime:        time.Now(),
	}
}

// CopyOf creates a new CrawlPath as a copy of the given eventables.
// CRAWLJAX PARITY: Matches Java CrawlPath.copyOf(List<Eventable>, int)
func CopyOf(eventables []*action.Eventable, backtrackTarget string) *CrawlPath {
	return NewCrawlPathFromList(eventables, backtrackTarget)
}

// Add appends an Eventable to the path.
// CRAWLJAX PARITY: Matches Java List.add(Eventable)
func (cp *CrawlPath) Add(eventable *action.Eventable) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.eventablePath = append(cp.eventablePath, eventable)
}

// Get returns the Eventable at the given index.
// CRAWLJAX PARITY: Matches Java List.get(int)
func (cp *CrawlPath) Get(index int) *action.Eventable {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	if index < 0 || index >= len(cp.eventablePath) {
		return nil
	}
	return cp.eventablePath[index]
}

// Last returns the last Eventable in the path.
// CRAWLJAX PARITY: Matches Java CrawlPath.last()
func (cp *CrawlPath) Last() *action.Eventable {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	if len(cp.eventablePath) == 0 {
		return nil
	}
	return cp.eventablePath[len(cp.eventablePath)-1]
}

// Size returns the number of Eventables.
// CRAWLJAX PARITY: Matches Java List.size()
func (cp *CrawlPath) Size() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.eventablePath)
}

// Len is an alias for Size (Go-style).
func (cp *CrawlPath) Len() int {
	return cp.Size()
}

// IsEmpty returns true if the path has no Eventables.
// CRAWLJAX PARITY: Matches Java List.isEmpty()
func (cp *CrawlPath) IsEmpty() bool {
	return cp.Size() == 0
}

// Remove removes the Eventable at the given index.
// CRAWLJAX PARITY: Matches Java List.remove(int)
func (cp *CrawlPath) Remove(index int) *action.Eventable {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if index < 0 || index >= len(cp.eventablePath) {
		return nil
	}

	removed := cp.eventablePath[index]
	cp.eventablePath = append(cp.eventablePath[:index], cp.eventablePath[index+1:]...)
	return removed
}

// RemoveLast removes and returns the last Eventable.
// CRAWLJAX PARITY: Convenience method for remove(size()-1)
func (cp *CrawlPath) RemoveLast() *action.Eventable {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if len(cp.eventablePath) == 0 {
		return nil
	}

	last := cp.eventablePath[len(cp.eventablePath)-1]
	cp.eventablePath = cp.eventablePath[:len(cp.eventablePath)-1]
	return last
}

// GetBacktrackTarget returns the backtrack target.
// CRAWLJAX PARITY: Matches Java getBacktrackTarget()
func (cp *CrawlPath) GetBacktrackTarget() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.BacktrackTarget
}

// SetBacktrackTarget sets the backtrack target.
// CRAWLJAX PARITY: Matches Java setBacktrackTarget(int)
func (cp *CrawlPath) SetBacktrackTarget(target string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.BacktrackTarget = target
}

// IsBacktrackSuccess returns the backtrack success status.
// CRAWLJAX PARITY: Matches Java isBacktrackSuccess()
func (cp *CrawlPath) IsBacktrackSuccess() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.BacktrackSuccess
}

// SetBacktrackSuccess sets the backtrack success status.
// CRAWLJAX PARITY: Matches Java setBacktrackSuccess(boolean)
func (cp *CrawlPath) SetBacktrackSuccess(success bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.BacktrackSuccess = success
}

// IsReachedNearDup returns the near-duplicate state ID reached (empty if none).
// CRAWLJAX PARITY: Matches Java isReachedNearDup() - returns -1 in Java for none
func (cp *CrawlPath) IsReachedNearDup() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.ReachedNearDup
}

// SetReachedNearDup sets the near-duplicate state ID reached.
// CRAWLJAX PARITY: Matches Java setReachedNearDup(int)
func (cp *CrawlPath) SetReachedNearDup(nearDupStateID string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.ReachedNearDup = nearDupStateID
}

// MarkSuccess marks the backtrack as successful.
// Convenience method combining SetBacktrackSuccess and clearing ReachedNearDup.
func (cp *CrawlPath) MarkSuccess() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.BacktrackSuccess = true
	cp.ReachedNearDup = ""
}

// MarkFailed marks the backtrack as failed.
// Convenience method for SetBacktrackSuccess(false).
func (cp *CrawlPath) MarkFailed() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.BacktrackSuccess = false
}

// MarkNearDuplicate marks that a near-duplicate was reached.
func (cp *CrawlPath) MarkNearDuplicate(nearDupStateID string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.BacktrackSuccess = false
	cp.ReachedNearDup = nearDupStateID
}

// ImmutableCopy creates an immutable copy of the current CrawlPath.
// CRAWLJAX PARITY: Matches Java immutableCopy()
func (cp *CrawlPath) ImmutableCopy() *CrawlPath {
	return cp.immutableCopyInternal(false)
}

// ImmutableCopyWithoutLast creates an immutable copy without the last Eventable.
// CRAWLJAX PARITY: Matches Java immutableCopyWithoutLast()
func (cp *CrawlPath) ImmutableCopyWithoutLast() *CrawlPath {
	return cp.immutableCopyInternal(true)
}

func (cp *CrawlPath) immutableCopyInternal(removeLast bool) *CrawlPath {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	if len(cp.eventablePath) == 0 {
		return NewCrawlPath(cp.BacktrackTarget)
	}

	// Build copy
	pathLen := len(cp.eventablePath)
	if removeLast {
		pathLen--
	}

	path := make([]*action.Eventable, pathLen)
	for i := 0; i < pathLen; i++ {
		// Deep copy each Eventable
		path[i] = cp.eventablePath[i].Clone()
	}

	copied := &CrawlPath{
		eventablePath:    path,
		BacktrackTarget:  cp.BacktrackTarget,
		BacktrackSuccess: cp.BacktrackSuccess,
		ReachedNearDup:   cp.ReachedNearDup,
		StartTime:        cp.StartTime,
		EndTime:          cp.EndTime,
	}

	return copied
}

// GetEventables returns a copy of the eventables slice.
// CRAWLJAX PARITY: Provides access to internal list
func (cp *CrawlPath) GetEventables() []*action.Eventable {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	eventables := make([]*action.Eventable, len(cp.eventablePath))
	copy(eventables, cp.eventablePath)
	return eventables
}

// AsStackTrace builds a stack trace for this path.
// CRAWLJAX PARITY: Matches Java asStackTrace()
func (cp *CrawlPath) AsStackTrace() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	size := len(cp.eventablePath)
	trace := make([]string, size)

	for i, e := range cp.eventablePath {
		elemStr := ""
		if e.Element != nil {
			elemStr = e.Element.String()
		}
		identStr := ""
		if e.Identification != nil {
			identStr = e.Identification.String()
		}

		// Java format: StackTraceElement(eventType, identification, element, lineNumber)
		trace[size-1-i] = fmt.Sprintf("%s.%s(%s:%d)",
			e.EventType,
			identStr,
			elemStr,
			i+1)
	}

	return trace
}

// String returns a string representation.
// Format for debugging purposes.
func (cp *CrawlPath) String() string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	var sb strings.Builder

	// Header: BT-state<target>:<success/failed>:<nearDup>
	fmt.Fprintf(&sb, "BT-state%s:", cp.BacktrackTarget)
	if cp.BacktrackSuccess {
		sb.WriteString("success:")
	} else {
		sb.WriteString("failed:")
	}
	if cp.ReachedNearDup != "" {
		sb.WriteString(cp.ReachedNearDup)
	} else {
		sb.WriteString("-1")
	}

	// Path events
	for _, e := range cp.eventablePath {
		sb.WriteString("_")
		sb.WriteString(e.SourceStateID)
		sb.WriteString("_")
		fmt.Fprintf(&sb, "%d", e.ID)
		sb.WriteString("_")
		sb.WriteString(e.TargetStateID)
	}

	return sb.String()
}

// Duration returns the duration of this crawl path.
func (cp *CrawlPath) Duration() time.Duration {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	if cp.EndTime.IsZero() {
		return time.Since(cp.StartTime)
	}
	return cp.EndTime.Sub(cp.StartTime)
}

// Close marks the path as ended.
func (cp *CrawlPath) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.EndTime.IsZero() {
		cp.EndTime = time.Now()
	}
}

// GetSourceStates returns all unique source states in the path.
func (cp *CrawlPath) GetSourceStates() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	seen := make(map[string]bool)
	var states []string

	for _, e := range cp.eventablePath {
		if e.SourceStateID != "" && !seen[e.SourceStateID] {
			seen[e.SourceStateID] = true
			states = append(states, e.SourceStateID)
		}
	}

	return states
}

// GetTargetStates returns all unique target states in the path.
func (cp *CrawlPath) GetTargetStates() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	seen := make(map[string]bool)
	var states []string

	for _, e := range cp.eventablePath {
		if e.TargetStateID != "" && !seen[e.TargetStateID] {
			seen[e.TargetStateID] = true
			states = append(states, e.TargetStateID)
		}
	}

	return states
}
