package scanevents

import "slices"

// MaxSkippedControlSample bounds the skipped controls a crawl, a phase and a
// scan name; the count beyond it stays exact.
const MaxSkippedControlSample = 20

// SkippedControls is the skipped_controls object of scan.finished and of the
// scan -j document: Count is exact, Sample names at most
// MaxSkippedControlSample.
type SkippedControls struct {
	Count  int64            `json:"count"`
	Sample []SkippedControl `json:"sample,omitempty"`
}

// SkippedControl is one click candidate the browser crawl's destructive-click
// guard refused: what it read as (Label), how to find it (Selector: the XPath
// or shadow locator the crawl identifies it by), the page it was on (URL),
// which rule refused it (Reason: "deny_click" for
// spidering.interaction.deny_click_pattern and its built-in default,
// "deny_click_extra" for spidering.deny_click_extra, "logout" for the
// authenticated-crawl logout guard) and the text that matched.
//
// It is the one shape from the crawler (pkg/spitolas) through the phase
// outcome (database.PhaseOutcome) to scan.finished and the -j document; this
// package owns it because every one of them can import it.
type SkippedControl struct {
	Label    string `json:"label"`
	Selector string `json:"selector,omitempty"`
	URL      string `json:"url,omitempty"`
	Reason   string `json:"reason"`
	Match    string `json:"match,omitempty"`
}

// AppendSkippedControls appends each of add that sample does not already hold,
// until sample reaches MaxSkippedControlSample. The bounded, deduplicated
// sample every layer keeps.
func AppendSkippedControls(sample []SkippedControl, add ...SkippedControl) []SkippedControl {
	for _, c := range add {
		if len(sample) >= MaxSkippedControlSample {
			break
		}
		if !slices.Contains(sample, c) {
			sample = append(sample, c)
		}
	}
	return sample
}
