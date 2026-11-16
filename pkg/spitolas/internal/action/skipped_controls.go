package action

import (
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// skippedControlLedger is the bounded, deduplicated sample of skipped
// controls (scanevents.AppendSkippedControls), shared by an extractor and its
// ForTab copies. The count beyond the sample stays exact (SkippedDestructive).
type skippedControlLedger struct {
	mu     sync.Mutex
	sample []scanevents.SkippedControl
}

func (l *skippedControlLedger) full() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sample) >= scanevents.MaxSkippedControlSample
}

func (l *skippedControlLedger) add(c scanevents.SkippedControl) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sample = scanevents.AppendSkippedControls(l.sample, c)
}

func (l *skippedControlLedger) snapshot() []scanevents.SkippedControl {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]scanevents.SkippedControl(nil), l.sample...)
}

// controlLabel is what a person would read the control as: its text, else
// its aria-label/title/value, else its href.
func controlLabel(c *CandidateElement) string {
	label := strings.TrimSpace(c.Text)
	if label == "" {
		for _, v := range denyAttrValues(c.Attributes) {
			if v = strings.TrimSpace(v); v != "" {
				label = v
				break
			}
		}
	}
	if label == "" {
		label = c.Href
	}
	return textutil.TruncateRunesEllipsis(label, 120, "…")
}
