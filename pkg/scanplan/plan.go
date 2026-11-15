// Package scanplan is the resolved plan of a native scan: which phases run and
// why the others do not, the budgets and pace each phase runs under, the
// modules, scope, auth sessions and targets it will use, and a rough estimate
// of how many requests it will send.
//
// It is types only, so both the event stream (pkg/scanevents, the scan.plan
// event) and the resolver (internal/runner.ResolvePlan) can import it without
// a cycle. The same value is printed by `scan --dry-run`, emitted as the
// second event of every `--events` stream, persisted on the scan row
// (scans.plan) and embedded verbatim in the `scan -j` document.
//
// The JSON shape is a contract: fields are only ever added. Bump SchemaVersion
// on any breaking change.
package scanplan

import (
	"encoding/json"
	"fmt"
)

// SchemaVersion is the plan schema version, carried as schema_version.
const SchemaVersion = 1

// Plan is one scan's resolved plan.
type Plan struct {
	SchemaVersion int `json:"schema_version"`
	// ScanUUID is empty under --dry-run (no scan UUID is minted) unless
	// --scan-uuid pinned one.
	ScanUUID string `json:"scan_uuid,omitempty"`
	// DryRun marks a plan that was resolved without running the scan.
	DryRun     bool   `json:"dry_run,omitempty"`
	Strategy   string `json:"strategy"`
	Intensity  string `json:"intensity,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Heuristics string `json:"heuristics_check"`
	// Phases is every phase in execution order, enabled AND disabled.
	Phases  []Phase       `json:"phases"`
	Budgets Budgets       `json:"budgets"`
	Modules Modules       `json:"modules"`
	Scope   Scope         `json:"scope"`
	Auth    []AuthSession `json:"auth"`
	Targets Targets       `json:"targets"`
	// Phase-specific shaping, present when the phase is enabled.
	Discovery   *Discovery   `json:"discovery,omitempty"`
	Harvest     *Harvest     `json:"harvest,omitempty"`
	ParamMining *ParamMining `json:"param_mining,omitempty"`
	// Egress lists which outbound paths share the scan's rate and host limits.
	Egress *Egress `json:"egress,omitempty"`
	// Proxy is the proxy target traffic goes through and where it came from;
	// absent when every request connects directly.
	Proxy    *Proxy    `json:"proxy,omitempty"`
	Estimate Estimate  `json:"estimate"`
	Warnings []Warning `json:"warnings"`
}

// Proxy is the effective proxy configuration: --proxy for every request, or
// the environment's proxies by scheme minus NO_PROXY.
type Proxy struct {
	Routes []ProxyRoute `json:"routes"`
	// NoProxy and NoProxySource are the NO_PROXY value in effect and the
	// variable it came from (absent under --proxy, which ignores it).
	NoProxy       string `json:"no_proxy,omitempty"`
	NoProxySource string `json:"no_proxy_source,omitempty"`
	// Targets lists, per admitted target, the proxy it goes through ("direct"
	// when it connects directly).
	Targets map[string]string `json:"targets,omitempty"`
}

// ProxyRoute is one proxy: the request scheme it serves ("*" for all), its
// URL (password masked) and its source ("--proxy" or the variable name).
type ProxyRoute struct {
	Scheme string `json:"scheme"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// Phase is one row of the plan.
type Phase struct {
	// ID is the canonical phase id (the vocabulary --only/--skip accept).
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	// DisabledBy says what turned a disabled phase off: strategy, only, skip,
	// heuristics, intensity, module_selection, default (opt-in phase not asked
	// for), gate (a runtime precondition is not met) or scope.
	DisabledBy string `json:"disabled_by,omitempty"`
	// SendsTarget reports whether the phase sends requests to the target.
	SendsTarget bool         `json:"sends_target_traffic"`
	Budget      *PhaseBudget `json:"budget,omitempty"`
	// Pace carries only the fields the phase actually enforces.
	Pace *Pace `json:"pace,omitempty"`
	// RequestCap says how strictly --max-requests holds for the phase's
	// traffic (hard, soft, partial); present when a request budget is set.
	RequestCap string `json:"request_cap_enforcement,omitempty"`
}

// Budget semantics: what a phase's max-duration bounds.
const (
	// SemanticsPerTarget: each target gets the whole budget; no phase ceiling.
	SemanticsPerTarget = "per_target"
	// SemanticsPerTargetCapped: each target gets the budget, and the phase is
	// capped at budget × min(targets, cap).
	SemanticsPerTargetCapped = "per_target_capped"
	// SemanticsPhase: the budget is the whole phase's wall clock.
	SemanticsPhase = "phase"
	// SemanticsPerLeg: each leg of the phase (nuclei, secret scan) gets the
	// whole budget.
	SemanticsPerLeg = "per_leg"
	// SemanticsPerCall: each outbound call is bounded by the budget.
	SemanticsPerCall = "per_call"
)

// Budget sources: where a phase's max-duration came from.
const (
	SourceFlag    = "flag"
	SourceConfig  = "config"
	SourceFactor  = "factor"
	SourceDefault = "default"
	// SourceFloor: a factor-derived budget raised to the spidering floor.
	SourceFloor = "floor"
)

// PhaseBudget is the time budget one phase runs under.
type PhaseBudget struct {
	// PerTargetMS is the per-target budget (per_target, per_target_capped).
	PerTargetMS int64 `json:"per_target_ms,omitempty"`
	// PhaseCeilingMS bounds the whole phase (phase, per_target_capped, per_leg).
	PhaseCeilingMS int64 `json:"phase_ceiling_ms,omitempty"`
	// DurationFactor is the scanning_pace duration_factor behind a derived
	// budget; 0 when the budget was set outright.
	DurationFactor float64 `json:"duration_factor,omitempty"`
	// GraceMS is the drain window before a per-target deadline (spidering).
	GraceMS   int64  `json:"grace_ms,omitempty"`
	Semantics string `json:"semantics"`
	Source    string `json:"source"`
}

// Pace is a phase's or the scan's effective speed. Zero means unlimited.
type Pace struct {
	RateLimit   int `json:"rate_limit"`
	Concurrency int `json:"concurrency"`
	MaxPerHost  int `json:"max_per_host"`
}

// Budgets are the scan-wide limits. Zero means unlimited.
type Budgets struct {
	ScanMaxDurationMS  int64 `json:"scan_max_duration_ms"`
	MaxRequests        int64 `json:"max_requests"`
	MaxRequestsPerHost int64 `json:"max_requests_per_host"`
	RateLimit          int   `json:"rate_limit"`
	Concurrency        int   `json:"concurrency"`
	MaxPerHost         int   `json:"max_per_host"`
}

// Module scopes, the keys of Modules.ByScope.
const (
	ScopeInsertionPoint = "insertion_point"
	ScopeRequest        = "request"
	ScopeHost           = "host"
)

// Modules is the module selection the assessment runs with.
type Modules struct {
	// Active and Passive count the built-in modules that run.
	Active  int `json:"active"`
	Passive int `json:"passive"`
	// Extensions counts the JS/YAML extension modules that run (or, before
	// the extensions are loaded, the extension files that will be loaded).
	Extensions int `json:"extensions"`
	// TierCeiling is the highest module tier the intensity runs.
	TierCeiling string `json:"tier_ceiling"`
	// TierFiltered, HygieneSuppressed and RiskGated count the modules a broad
	// selection drops: above the tier ceiling, hardening advisories below deep,
	// risk:high modules without --allow-risky-payloads.
	TierFiltered      int `json:"tier_filtered"`
	HygieneSuppressed int `json:"hygiene_suppressed"`
	RiskGated         int `json:"risk_gated"`
	// RiskyPayloadsAllowed reports whether risk:high payloads and modules run.
	RiskyPayloadsAllowed bool `json:"risky_payloads_allowed"`
	// PayloadsGated lists modules that hold back some of their payloads.
	PayloadsGated []PayloadGate `json:"payloads_gated,omitempty"`
	// ByScope counts running modules per scan scope (a module with several
	// scopes counts once in each).
	ByScope map[string]int `json:"by_scope"`
	// ExtensionSelection is how the module selection narrowed the loaded
	// extensions; present once they are loaded (the runner's plan).
	ExtensionSelection *ExtensionSelection `json:"extension_selection,omitempty"`
	// IDs lists the running module ids (verbose only).
	IDs []string `json:"ids,omitempty"`
}

// PayloadGate is one module's withheld payloads.
type PayloadGate struct {
	Module string `json:"module"`
	Gated  int    `json:"gated"`
	Total  int    `json:"total"`
	Reason string `json:"reason"`
}

// ExtensionSelection summarizes how the module selection narrowed the loaded
// extension modules.
type ExtensionSelection struct {
	Active    int            `json:"active"`
	Passive   int            `json:"passive"`
	Skipped   int            `json:"skipped"`
	SkippedBy map[string]int `json:"skipped_by,omitempty"`
	Summary   string         `json:"summary"`
}

// Scope is the scope configuration the scan enforces.
type Scope struct {
	OriginMode   string   `json:"origin_mode"`
	IgnoreStatic bool     `json:"ignore_static"`
	HostInclude  []string `json:"host_include"`
	HostExclude  []string `json:"host_exclude"`
	PathInclude  []string `json:"path_include"`
	PathExclude  []string `json:"path_exclude"`
	// Rules lists every scope rule that differs from its pass-all default,
	// status code, content type and string rules included, so a rule that
	// drops records is visible before the scan runs.
	Rules []ScopeRuleView `json:"rules,omitempty"`
	// ScopeTargets are scope-only targets derived from a file input with no
	// -t: the scope-origin index is built from them, but they seed
	// nothing.
	ScopeTargets []string `json:"scope_targets,omitempty"`
	// InputHosts is the input file's per-host record census, each host with
	// whether the derived scope admits it. Sorted by records, descending.
	InputHosts []InputHost `json:"input_hosts,omitempty"`
}

// ScopeRuleView is one non-default scope rule: its class (host, path,
// status_code, request_content_type, response_content_type, request_string,
// response_string) and its patterns.
type ScopeRuleView struct {
	Class   string   `json:"class"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// InputHost is one row of Scope.InputHosts.
type InputHost struct {
	Host    string `json:"host"`
	Records int    `json:"records"`
	InScope bool   `json:"in_scope"`
}

// AuthSession names one session the scan will use. Never carries a secret.
type AuthSession struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// Kind is headers, login_flow or login_request.
	Kind    string `json:"kind"`
	Primary bool   `json:"primary"`
	// LoginHost is the host a login flow posts to.
	LoginHost string `json:"login_host,omitempty"`
	// Source is file, inline or db.
	Source string `json:"source"`
}

// Targets is what the scan will seed and what scope admits.
type Targets struct {
	// Seeded counts every target the scan seeds (CLI, -T file lines, piped
	// URL list); FromFiles is the -T share.
	Seeded    int `json:"seeded"`
	FromFiles int `json:"from_files"`
	// AllRecords: the stored records are the input (--all-records).
	AllRecords bool `json:"all_records,omitempty"`
	// DBRecordsInScope counts the stored records the assessment will read;
	// absent without a database.
	DBRecordsInScope *int64 `json:"db_records_in_scope,omitempty"`
	Admitted         int    `json:"admitted"`
	Rejected         int    `json:"rejected"`
	// RejectedSample names at most 10 refused targets.
	RejectedSample []Rejection `json:"rejected_sample,omitempty"`
}

// Rejection is one target scope refused, with the rule that refused it.
type Rejection struct {
	Target string `json:"target"`
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
}

// Discovery is the content-discovery shaping.
type Discovery struct {
	// WordlistTier is the effective discovery.wordlists.tier (never auto).
	WordlistTier string     `json:"wordlist_tier"`
	Wordlists    []Wordlist `json:"wordlists"`
	Fuzzing      bool       `json:"fuzzing"`
	// FuzzingReason says why fuzzing is on or off.
	FuzzingReason     string `json:"fuzzing_reason"`
	RecursionEnabled  bool   `json:"recursion_enabled"`
	RecursionMaxDepth int    `json:"recursion_max_depth"`
	// TargetConcurrency is how many targets are discovered at once.
	TargetConcurrency int `json:"target_concurrency"`
	// JSTangle is the JavaScript analysis service shaping.
	JSTangle *JSTangle `json:"jstangle,omitempty"`
	Sitemap  *Sitemap  `json:"sitemap,omitempty"`
}

// Wordlist is one list feeding discovery.
type Wordlist struct {
	// Slot is short_file, short_dir, long_file, long_dir or fuzz.
	Slot string `json:"slot"`
	// Source is embedded or path.
	Source string `json:"source"`
	// Name is the embedded list name or the configured path.
	Name string `json:"name"`
	// Lines is the list's word count; absent when unknown (an unreadable path).
	Lines *int64 `json:"lines,omitempty"`
}

// JSTangle is the JavaScript analysis service's worker shaping.
type JSTangle struct {
	Enabled        bool  `json:"enabled"`
	Workers        int   `json:"workers"`
	MemoryBudgetMB int64 `json:"memory_budget_mb"`
}

// Sitemap is the sitemap source's caps.
type Sitemap struct {
	Enabled  bool `json:"enabled"`
	MaxURLs  int  `json:"max_urls"`
	PerShape int  `json:"per_shape"`
}

// Harvest is the external-harvest shaping.
type Harvest struct {
	Sources    []string `json:"sources"`
	MaxURLs    int      `json:"max_urls"`
	PerShape   int      `json:"per_shape"`
	CDXMaxRows int      `json:"cdx_max_rows"`
	// Probe reports whether harvest-probe checks the harvested URLs.
	Probe bool `json:"probe"`
}

// ParamMining is the param-mining shaping.
type ParamMining struct {
	EndpointsPerHost    int `json:"endpoints_per_host"`
	RequestsPerEndpoint int `json:"requests_per_endpoint"`
	Workers             int `json:"workers"`
}

// Egress describes which outbound paths share the scan's rate and host limits.
type Egress struct {
	Gated  []string          `json:"gated"`
	Exempt []EgressExemption `json:"exempt"`
}

// EgressExemption is one outbound path that bypasses the shared gate.
type EgressExemption struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ConfidenceRough is the only estimate confidence there is today.
const ConfidenceRough = "rough"

// Estimate is a rough request-volume estimate.
type Estimate struct {
	Low  int64 `json:"low"`
	High int64 `json:"high"`
	// CeilingByPace is rate_limit × the scan's duration budget: the one hard
	// number, and the headline when present.
	CeilingByPace *int64 `json:"ceiling_by_pace,omitempty"`
	// ClampedTo is --max-requests when it lowered the estimate.
	ClampedTo *int64 `json:"clamped_to,omitempty"`
	// HitsMaxRequests names the phases expected to run into --max-requests.
	HitsMaxRequests []string                 `json:"hits_max_requests,omitempty"`
	ByPhase         map[string]PhaseEstimate `json:"by_phase"`
	Basis           string                   `json:"basis"`
	Confidence      string                   `json:"confidence"`
	// DurationMS is the rough wall-clock range the scan is expected to take.
	DurationMS *DurationEstimate `json:"duration_ms,omitempty"`
}

// DurationEstimate is a rough wall-clock range in milliseconds: requests over
// the effective rate, bounded by the phase budgets and the scan's own
// duration budget. Confidence is always "rough".
type DurationEstimate struct {
	Low        int64  `json:"low"`
	High       int64  `json:"high"`
	Basis      string `json:"basis"`
	Confidence string `json:"confidence"`
}

// PhaseEstimate is one phase's share of the estimate.
type PhaseEstimate struct {
	Low           int64  `json:"low"`
	High          int64  `json:"high"`
	CeilingByPace *int64 `json:"ceiling_by_pace,omitempty"`
	Basis         string `json:"basis"`
}

// Warning is one thing the operator should know before the scan runs. Codes
// share the reason vocabulary (no_targets_in_scope, targets_out_of_scope, …).
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Phase returns the plan row for id, or nil.
func (p *Plan) Phase(id string) *Phase {
	if p == nil {
		return nil
	}
	for i := range p.Phases {
		if p.Phases[i].ID == id {
			return &p.Phases[i]
		}
	}
	return nil
}

// EnabledPhaseIDs returns the ids of the enabled phases, in execution order.
func (p *Plan) EnabledPhaseIDs() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, ph := range p.Phases {
		if ph.Enabled {
			out = append(out, ph.ID)
		}
	}
	return out
}

// AddWarning appends a warning.
func (p *Plan) AddWarning(code, format string, args ...any) {
	p.Warnings = append(p.Warnings, Warning{Code: code, Message: fmt.Sprintf(format, args...)})
}

// Decode parses a persisted plan (scans.plan). An empty input is (nil, nil).
func Decode(raw []byte) (*Plan, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("decode scan plan: %w", err)
	}
	return &p, nil
}
