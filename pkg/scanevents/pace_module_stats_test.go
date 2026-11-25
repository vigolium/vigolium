package scanevents

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

// scan.started carries pace_ignored and scan.finished carries module_stats,
// each on the wire with its documented keys and valid against the schema.
func TestPaceIgnoredAndModuleStatsOnTheWire(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "11111111-2222-3333-4444-555555555555")
	e.Emit(Event{Type: TypeScanStarted, Pace: &Pace{RateLimit: 50, Concurrency: 10, MaxPerHost: 40}, Budgets: &Budgets{},
		PaceIgnored: []PaceIgnored{{Phase: "spidering", Dial: "rate_limit", Source: PaceSourceConfig}}})
	e.Finish(Event{Status: StatusCompleted, ModuleStats: map[string]ModuleStat{
		"xss":  {Invocations: 4, Requests: 9, Findings: 1, Skips: map[string]int64{"tech_filter": 2}},
		"sqli": {Errors: 3},
	}})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("emitted %d lines, want 2:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		contracttest.ValidateEvent(t, line)
	}

	var started struct {
		PaceIgnored []map[string]string `json:"pace_ignored"`
	}
	if err := json.Unmarshal(lines[0], &started); err != nil {
		t.Fatal(err)
	}
	if len(started.PaceIgnored) != 1 || started.PaceIgnored[0]["phase"] != "spidering" ||
		started.PaceIgnored[0]["dial"] != "rate_limit" || started.PaceIgnored[0]["source"] != "config" {
		t.Errorf("pace_ignored = %v", started.PaceIgnored)
	}

	var finished struct {
		ModuleStats map[string]struct {
			Invocations int64            `json:"invocations"`
			Requests    int64            `json:"requests"`
			Errors      int64            `json:"errors"`
			Skips       map[string]int64 `json:"skips"`
		} `json:"module_stats"`
	}
	if err := json.Unmarshal(lines[1], &finished); err != nil {
		t.Fatal(err)
	}
	xss := finished.ModuleStats["xss"]
	if xss.Invocations != 4 || xss.Requests != 9 || xss.Skips["tech_filter"] != 2 {
		t.Errorf("module_stats.xss = %+v", xss)
	}
	if finished.ModuleStats["sqli"].Errors != 3 {
		t.Errorf("module_stats.sqli = %+v", finished.ModuleStats["sqli"])
	}
}
