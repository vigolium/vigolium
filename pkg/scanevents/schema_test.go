package scanevents

import (
	"bytes"
	"sort"
	"testing"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

// TestEventFieldTableCoversEveryType: every type in Types has a row, no row
// names a type outside it, and every row builds (no key Event lacks).
func TestEventFieldTableCoversEveryType(t *testing.T) {
	inTypes := map[string]bool{}
	for _, typ := range Types {
		inTypes[typ] = true
		if _, ok := eventFields[typ]; !ok {
			t.Errorf("event type %q has no row in eventFields (schema.go)", typ)
		}
		if _, err := contract.EventSchema(typ); err != nil {
			t.Errorf("schema for %q: %v", typ, err)
		}
	}
	for typ := range eventFields {
		if !inTypes[typ] {
			t.Errorf("eventFields has a row for %q, which is not in Types", typ)
		}
	}
	if got := contract.EventTypes(); len(got) != len(Types) {
		t.Errorf("contract registry holds %d event types, Types has %d", len(got), len(Types))
	}
}

// TestEveryEventKeyBelongsToAType: a key added to Event must be claimed by the
// row of every type that emits it, or `vigolium schema event` rejects lines
// that carry it.
func TestEveryEventKeyBelongsToAType(t *testing.T) {
	claimed := map[string]bool{}
	for _, k := range eventSpine {
		claimed[k] = true
	}
	for _, f := range eventFields {
		for _, k := range append(append([]string{}, f.Required...), f.Optional...) {
			claimed[k] = true
		}
	}
	var orphans []string
	for _, k := range contract.JSONFieldNames(Event{}) {
		if !claimed[k] {
			orphans = append(orphans, k)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("Event keys no type claims (add them to eventFields in schema.go): %v", orphans)
	}
}

// TestEmittedEventsMatchSchema runs representative lines through the real
// emitter, so the stamped spine (v, ts, seq, scan_uuid) is validated too.
func TestEmittedEventsMatchSchema(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "11111111-2222-3333-4444-555555555555")
	yes := true
	e.Emit(Event{Type: TypeScanStarted, Target: "https://app.test", Targets: 1, Strategy: "balanced",
		Phases: []string{"ingestion", "dynamic-assessment"}, Pace: &Pace{RateLimit: 50, Concurrency: 10, MaxPerHost: 40},
		Budgets: &Budgets{}, Egress: &Egress{Gated: []string{"scanner"}, Exempt: []EgressExemption{{Path: "oast", Reason: "out-of-band"}}},
		TargetsAdmitted: Int(1), TargetsRejected: Int(0)})
	e.Emit(Event{Type: TypePhaseStarted, Phase: "dynamic-assessment"})
	e.Emit(Event{Type: TypePhaseProgress, Phase: "dynamic-assessment", RequestsSent: Int64(0), Findings: Int64(0),
		Done: Int64(3), Total: Int64(10), Unit: "records"})
	e.Emit(Event{Type: TypeFindingNew, Severity: "high", Confidence: "firm", ModuleID: "xss", URL: "https://app.test/?q=1", Host: "app.test"})
	e.Emit(Event{Type: TypeWAFBlock, Host: "app.test", Vendor: "cloudflare", BlockKind: "challenge", Transport: "spider", StatusCode: 200, Detail: "edge"})
	e.Emit(Event{Type: TypeHostQuarantined, Host: "app.test:443", Phase: "dynamic-assessment", Detail: "timeout"})
	e.Emit(Event{Type: TypeAuthRelogin, Session: "admin", Gen: 2, OK: &yes, Count: Int64(1)})
	e.Emit(Event{Type: TypeError, Phase: "spidering", Message: "boom", ErrorKind: "wait_timeout"})
	e.Emit(Event{Type: TypePhaseFinished, Phase: "dynamic-assessment", Status: StatusCurtailed, DurationMS: 12,
		RequestsSent: Int64(4), Findings: Int64(1), Reasons: []string{"phase_deadline"}})
	e.Finish(Event{Status: StatusCompleted, DurationMS: 20, FindingsBySeverity: map[string]int{"high": 1},
		RecordsWritten: Int64(4), StopReason: ""})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 10 {
		t.Fatalf("emitted %d lines, want 10:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		contracttest.ValidateEvent(t, line)
	}

	// A key the type does not own is a contract violation.
	err := contracttest.Check(mustEventSchema(t, TypePhaseStarted),
		[]byte(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","seq":1,"scan_uuid":"u","type":"phase.started","phase":"x","severity":"high"}`))
	if err == nil {
		t.Error("phase.started carrying severity validated; the schema must be closed")
	}
}

func mustEventSchema(t *testing.T, typ string) *contract.Schema {
	t.Helper()
	s, err := contract.EventSchema(typ)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
