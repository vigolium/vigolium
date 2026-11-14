package scanevents

import "github.com/vigolium/vigolium/pkg/contract"

// Event is one struct for every type, so the struct alone cannot say which
// keys a given type's line carries. eventFields is that table, and the source
// of `vigolium schema event`: per type, the keys a line always carries
// (required) and the keys it may carry (optional), on top of the spine every
// line has.
//
// Keep it in step with the emit sites. schema_test.go fails when a type in
// Types has no row, when a row names a key Event does not have, or when an
// Event key belongs to no type.
var eventSpine = []string{"v", "ts", "seq", "scan_uuid", "type"}

var eventFields = map[string]contract.EventFields{
	TypeScanStarted: {
		Description: "First line of every stream: what the scan will run, against what, at what pace and budget.",
		Required:    []string{"pace", "budgets"},
		Optional: []string{"target", "targets", "strategy", "phases", "db_path", "project_uuid", "phase_pace",
			"egress", "request_cap_enforcement", "targets_admitted", "targets_rejected"},
	},
	TypeScanInterrupting: {
		Description: "A shutdown signal arrived and the graceful stop began. Nonterminal: scan.finished still follows.",
		Optional:    []string{"message"},
	},
	TypeScanFinished: {
		Description: "The terminal line, on every reachable exit path. status: completed, curtailed, interrupted or failed.",
		Required:    []string{"status"},
		Optional: []string{"duration_ms", "message", "stop_reason", "reasons", "limits",
			"requests_sent", "findings", "records_written", "records_basis", "findings_by_severity",
			"targets_admitted", "targets_rejected", "targets_reached", "targets_unreachable",
			"budget_exhausted_hosts", "exports", "module_errors", "extensions_failed", "findings_capped", "caveats"},
	},
	TypePhaseStarted: {
		Description: "A phase began.",
		Required:    []string{"phase"},
	},
	TypePhaseProgress: {
		Description: "Heartbeat while a phase runs. total is a non-decreasing upper bound, absent until known.",
		Required:    []string{"phase"},
		Optional:    []string{"requests_sent", "requests_in_scope", "findings", "done", "total", "unit"},
	},
	TypePhaseFinished: {
		Description: "A phase ended. status: completed, curtailed or failed; reasons are defects, limits configured bounds reached.",
		Required:    []string{"phase", "status"},
		Optional: []string{"duration_ms", "requests_sent", "requests_in_scope", "findings", "reasons", "limits",
			"message", "done", "total", "unit", "findings_capped"},
	},
	TypeWAFBlock: {
		Description: "The edge started filtering scan traffic for a host.",
		Required:    []string{"host"},
		Optional:    []string{"vendor", "status_code", "detail"},
	},
	TypeWAFPacing: {
		Description: "Proactive pacing armed for a host behind a CDN/WAF edge.",
		Required:    []string{"host"},
		Optional:    []string{"vendor", "concurrency_from", "concurrency_to", "detail"},
	},
	TypeFindingNew: {
		Description: "A finding was reported. Metadata only: the evidence is in the database.",
		Optional:    []string{"severity", "confidence", "module_id", "url", "host"},
	},
	TypeImportSummary: {
		Description: "What a bridge import is about to write: total will cross, matched is what the source holds.",
		Optional:    []string{"source", "matched", "total"},
	},
	TypeError: {
		Description: "A NON-fatal error. A failure that ends the run is scan.finished{status:failed}.",
		Required:    []string{"message"},
		Optional:    []string{"phase", "error_kind"},
	},
	TypeScanPlan: {
		Description: "The resolved scan plan, second on every stream (the same object `scan --dry-run` prints).",
		Required:    []string{"plan"},
	},
	TypeScanSetup: {
		Description: "A lazy first-run install inside the phase that needs it, before that phase's clock starts: component chrome|nuclei (the `doctor --fix --only` id), state started|finished|failed. bytes is the download size when known; duration_ms and message (failed) ride on the terminal line.",
		Required:    []string{"component", "state"},
		Optional:    []string{"phase", "bytes", "duration_ms", "message"},
	},
	TypeOASTUnavailable: {
		Description: "OAST registration failed or timed out: out-of-band checks do not run (scan partial, oast_unavailable).",
		Optional:    []string{"phase", "message", "detail"},
	},
	TypeHostQuarantined: {
		Description: "A host's breaker opened after consecutive errors; it is re-probed after a cooldown.",
		Required:    []string{"host"},
		Optional:    []string{"phase", "detail", "message"},
	},
	TypeHostRecovered: {
		Description: "A quarantined host answered its probe and is back in rotation.",
		Required:    []string{"host"},
		Optional:    []string{"phase", "detail", "message"},
	},
	TypeHostDead: {
		Description: "A host failed every probe: no further requests go to it this scan.",
		Required:    []string{"host"},
		Optional:    []string{"phase", "detail", "message"},
	},
	TypeAuthSessionSuspect: {
		Description: "Responses for a session look logged out; gen is the suspected credential generation.",
		Required:    []string{"session"},
		Optional:    []string{"phase", "gen", "detail"},
	},
	TypeAuthRelogin: {
		Description: "How a re-login cycle ended: ok, the new generation when it worked, count of logins tried.",
		Required:    []string{"session", "ok"},
		Optional:    []string{"phase", "gen", "count", "message"},
	},
	TypeModuleError: {
		Description: "A module call failed (error_kind exception, timeout or panic). Rate-limited per module: the first 3, then every 100th; count is the module's running error total for the scan.",
		Optional:    []string{"module_id", "phase", "url", "error_kind", "message", "count"},
	},
	TypeExtensionFailed: {
		Description: "An extension failed to load: stage is the load step that failed; explicit says it was named with --ext (the scan then stops, exit 2 extension_load_failed, unless --ext-allow-failures).",
		Required:    []string{"path", "stage", "explicit", "message"},
		Optional:    []string{"module_id"},
	},
}

func init() {
	contract.SetEventPayload(Event{}, SchemaVersion, eventSpine)
	for _, typ := range Types {
		contract.RegisterEvent(typ, eventFields[typ])
	}
}
