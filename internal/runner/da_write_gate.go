package runner

import "github.com/vigolium/vigolium/pkg/database"

// noteWriteTemplatesSkipped records the stored write templates (a
// state-changing method, first stored without a response) a dynamic-assessment
// pass held back because the run does not allow writes: a phase note, so the
// scan's caveats carry templates_skipped_unsafe_method with the count, and
// --allow-writes is the remedy.
//
// A phase runs several passes over overlapping windows (feedback rounds, tier
// passes of one round), each counting the templates in its own window, so the
// phase keeps the largest count rather than the sum: the same template must not
// be counted once per pass.
func (t *phaseTracker) noteWriteTemplatesSkipped(n int64) {
	if t == nil || n <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.notes, database.LimitTemplatesSkippedUnsafeMethod)
	if t.counts == nil {
		t.counts = make(map[string]int64)
	}
	if n > t.counts[database.LimitTemplatesSkippedUnsafeMethod] {
		t.counts[database.LimitTemplatesSkippedUnsafeMethod] = n
	}
}
