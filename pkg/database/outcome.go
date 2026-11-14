package database

import (
	"sort"
	"unicode/utf8"
)

// PersistenceOutcome is what a writer can say, after shutdown, about writes it
// accepted. Committed+Failed+Unknown == Accepted. Unknown = still queued or in
// flight when the close deadline passed: it may or may not have landed.
//
// The distinction between Failed and Unknown is the point. Before this existed,
// Close() returned nothing: a writer that drained cleanly, a writer that lost a
// batch to a failed transaction, and a writer whose deadline expired with records
// still queued were indistinguishable to the caller, so a scan reported success
// either way. Unknown is deliberately not folded into Failed — a timed-out drain
// may well have committed everything a moment later, and reporting those as lost
// would be as wrong as reporting them as stored.
type PersistenceOutcome struct {
	Writer    string `json:"writer"` // "records" | "findings" | "mixed"
	Accepted  int64  `json:"accepted"`
	Committed int64  `json:"committed"` // persisted, or deduplicated onto an existing row
	Failed    int64  `json:"failed,omitempty"`
	Unknown   int64  `json:"unknown,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
}

// PersistenceShutdowner is a writer that can be drained and asked what happened.
// Both RecordWriter and FindingWriter satisfy it, which is what lets a phase shut
// down whatever writers it owns through one call.
type PersistenceShutdowner interface {
	Shutdown() PersistenceOutcome
}

// Writer names used by the two writers and by a merged outcome.
const (
	PersistenceWriterRecords  = "records"
	PersistenceWriterFindings = "findings"
	PersistenceWriterMixed    = "mixed"
)

// Clean reports whether everything the writer accepted reached a known-good end.
// A clean outcome is the only one a caller may report as an unqualified success.
func (o PersistenceOutcome) Clean() bool { return o.Failed == 0 && o.Unknown == 0 }

// Merge folds p into o, so a phase that shuts down several writers can report one
// number. The writer label collapses to "mixed" once two different writers are
// combined; merging into a zero outcome adopts p's label.
func (o *PersistenceOutcome) Merge(p PersistenceOutcome) {
	switch {
	case o.Writer == "":
		o.Writer = p.Writer
	case p.Writer != "" && o.Writer != p.Writer:
		o.Writer = PersistenceWriterMixed
	}
	o.Accepted += p.Accepted
	o.Committed += p.Committed
	o.Failed += p.Failed
	o.Unknown += p.Unknown
	o.TimedOut = o.TimedOut || p.TimedOut
}

// PhaseState is what became of one scan phase. It is deliberately NOT the scan
// status vocabulary ("running"/"completed"/"failed"/"cancelled"): a phase can end
// having done most of its work and none of those four words says so, which is the
// whole reason a time-boxed phase used to report a clean completion.
type PhaseState string

const (
	// PhaseCompleted — the phase consumed its whole input and nothing was lost.
	PhaseCompleted PhaseState = "completed"
	// PhasePartial — the phase ran but did not cover everything it was given.
	PhasePartial PhaseState = "partial"
	// PhaseFailed — the phase reported an error. It may still have produced work.
	PhaseFailed PhaseState = "failed"
	// PhaseSkipped — the phase never ran (nothing to do, or the budget was gone).
	PhaseSkipped PhaseState = "skipped"
)

// Reason and limit codes. These are PERSISTED on the scan row and EMITTED on the
// event stream, so they are a compatibility surface: add codes, never rename or
// repurpose one. A reason says why a phase did not cover everything; a limit says
// a configured bound was reached, which is designed behaviour rather than a
// defect, and is reported separately so a consumer can tell them apart.
const (
	ReasonPhaseDeadline        = "phase_deadline"         // the phase's own max_duration / ceiling fired
	ReasonScanBudget           = "scan_budget"            // --scanning-max-duration fired
	ReasonCancelled            = "cancelled"              // Ctrl-C / caller cancellation
	ReasonError                = "error"                  // the phase returned an error
	ReasonNoModules            = "no_modules"             // nothing to execute
	ReasonDrainStalled         = "drain_stalled"          // feedback drain abandoned with workers in flight
	ReasonWorkersAbandoned     = "workers_abandoned"      // workers did not exit within the shutdown grace
	ReasonDeferredFlushSkipped = "deferred_flush_skipped" // passive flush skipped after abandoning workers
	ReasonProducerAbandoned    = "producer_abandoned"     // an input producer did not exit in time
	ReasonTargetsFailed        = "targets_failed"         // one or more targets errored
	ReasonTargetsSkipped       = "targets_skipped"        // one or more targets were never attempted
	ReasonPersistence          = "persistence_incomplete" // a writer could not account for every write
	ReasonRoundError           = "round_error"            // a dynamic-assessment feedback round failed
	ReasonCheckpointFailed     = "checkpoint_failed"      // the durable scan cursor could not be advanced
	ReasonInputIncomplete      = "input_incomplete"       // the executor stopped before its source was exhausted
	ReasonAuthUnavailable      = "auth_unavailable"       // configured authentication could not be applied
	ReasonLoginBudget          = "login_budget"           // the total login budget elapsed before every session hydrated
	ReasonTargetsOutOfScope    = "targets_out_of_scope"   // one or more CLI targets were rejected by scope
	ReasonTargetsUnreachable   = "targets_unreachable"    // one or more admitted targets got no HTTP answer
	ReasonOASTUnavailable      = "oast_unavailable"       // OAST registration failed; out-of-band checks did not run (non-stopping)
	ReasonRequestBudget        = "request_budget"         // the scan-wide request budget (--max-requests) ran out
	ReasonAuthLost             = "auth_lost"              // the session expired mid-scan and re-login did not restore it
	ReasonPhaseError           = "phase_error"            // a phase failed and the scan carried on without it
	ReasonExtensionsAllFailed  = "extensions_all_failed"  // every requested extension failed to load or run
	ReasonAbandoned            = "abandoned"              // the scan's process died without finalizing; set by `log ls --reap`
	ReasonFeedbackDropped      = "feedback_dropped"       // discovered endpoints were dropped from the feedback queue
	ReasonEdgeBlocked          = "edge_blocked"           // a WAF/edge blocked requests to one or more hosts during the phase
	ReasonBrowserUnavailable   = "browser_unavailable"    // the crawl browser failed to launch
	ReasonAuthUnverified       = "auth_unverified"        // a session's login could not be verified (no check, or the check failed)

	// Stop reasons: the scan did nothing useful and ends with exit 1.
	ReasonNoTargetsInScope   = "no_targets_in_scope"  // scope admitted zero targets
	ReasonNoTargetsReachable = "no_targets_reachable" // zero admitted targets answered

	LimitTargetBudget            = "target_budget"              // informational: a target used its whole budget
	LimitHostRequestBudget       = "host_request_budget"        // a host used its whole request budget
	LimitJSRequestCap            = "js_request_cap"             // JS analysis hit its per-target request cap
	LimitJSInputOverHardLimit    = "js_input_over_hard_limit"   // a JS file exceeded the hard size limit and was not parsed
	LimitJSTemplatePersistCap    = "js_template_persist_cap"    // JS-derived request templates hit the persist cap
	LimitCDXMaxRows              = "cdx_max_rows"               // an archive (CDX) query hit its row cap
	LimitSitemapCap              = "sitemap_cap"                // sitemap expansion hit its URL cap
	LimitResponsesWhileLoggedOut = "responses_while_logged_out" // responses observed while the session was logged out
	LimitFindingsPerModule       = "findings_per_module"        // --max-findings-per-module dropped findings (see PhaseOutcome.FindingsCapped)
	LimitThrottled               = "throttled"                  // a host throttled (429/503 Retry-After) module traffic
)

// OutcomeCodes lists every reason and limit code exactly once. It exists so a
// consumer can enumerate the vocabulary, and so a drift guard in the tests can
// assert that a newly added constant was not forgotten here.
var OutcomeCodes = []string{
	ReasonPhaseDeadline,
	ReasonScanBudget,
	ReasonCancelled,
	ReasonError,
	ReasonNoModules,
	ReasonDrainStalled,
	ReasonWorkersAbandoned,
	ReasonDeferredFlushSkipped,
	ReasonProducerAbandoned,
	ReasonTargetsFailed,
	ReasonTargetsSkipped,
	ReasonPersistence,
	ReasonRoundError,
	ReasonCheckpointFailed,
	ReasonInputIncomplete,
	ReasonAuthUnavailable,
	ReasonLoginBudget,
	ReasonTargetsOutOfScope,
	ReasonTargetsUnreachable,
	ReasonOASTUnavailable,
	ReasonRequestBudget,
	ReasonAuthLost,
	ReasonPhaseError,
	ReasonExtensionsAllFailed,
	ReasonAbandoned,
	ReasonFeedbackDropped,
	ReasonEdgeBlocked,
	ReasonBrowserUnavailable,
	ReasonAuthUnverified,
	ReasonNoTargetsInScope,
	ReasonNoTargetsReachable,
	LimitTargetBudget,
	LimitHostRequestBudget,
	LimitJSRequestCap,
	LimitJSInputOverHardLimit,
	LimitJSTemplatePersistCap,
	LimitCDXMaxRows,
	LimitSitemapCap,
	LimitResponsesWhileLoggedOut,
	LimitFindingsPerModule,
	LimitThrottled,
}

// ResolvePhaseState turns the three things a phase tracker observes into a state.
//
// Precedence is errors → skipped → reasons → completed. An error outranks
// everything because a phase that failed is not a phase that merely came up
// short; a skipped phase never ran, so its reasons describe why it was skipped
// rather than what it missed; a reason without an error is the partial case this
// vocabulary exists for. LIMITS are deliberately not an input: reaching a
// configured bound is designed behaviour and must not downgrade a phase.
func ResolvePhaseState(errs int, reasons []string, skipped bool) PhaseState {
	switch {
	case errs > 0:
		return PhaseFailed
	case skipped:
		return PhaseSkipped
	case len(reasons) > 0:
		return PhasePartial
	default:
		return PhaseCompleted
	}
}

// PhaseOutcome is one phase's result, in the terms a consumer can act on. It is
// persisted on the scan row (scans.phase_outcomes) and summarised on the event
// stream, so every field is additive-only.
type PhaseOutcome struct {
	Phase   string     `json:"phase"`
	State   PhaseState `json:"state"`
	Reasons []string   `json:"reasons,omitempty"` // sorted, unique
	Limits  []string   `json:"limits,omitempty"`  // sorted, unique
	Errors  int        `json:"errors,omitempty"`
	Message string     `json:"message,omitempty"` // first error, truncated
	// Unprocessed counts work items the executor dequeued but did not process —
	// deliberately NOT acknowledged, so a later run re-serves them.
	Unprocessed int64               `json:"unprocessed,omitempty"`
	DurationMS  int64               `json:"duration_ms"`
	Persistence *PersistenceOutcome `json:"persistence,omitempty"`
	// Targets is the CLI-target tally (scope admission, reachability); set only
	// on the "preflight" pseudo-phase. See TargetTally.
	Targets *TargetTally `json:"targets,omitempty"`
	// Counts are phase-specific tallies keyed by a stable snake_case name (the
	// harvest-probe step reports hosts_dead, kept, dropped_not_found, …). Only
	// phases whose result is a set of numbers rather than records set it.
	Counts map[string]int64 `json:"counts,omitempty"`
	// BudgetExhaustedHosts are the hosts whose --max-requests-per-host ran out
	// during the phase, sorted; set alongside the host_request_budget limit.
	BudgetExhaustedHosts []string `json:"budget_exhausted_hosts,omitempty"`
	// FindingsCapped counts, per module, the distinct findings the
	// --max-findings-per-module cap dropped during the phase; set alongside the
	// findings_per_module limit.
	FindingsCapped map[string]int64 `json:"findings_capped,omitempty"`
}

// BenignSkip reports whether this phase was skipped for having nothing to do,
// rather than because the scan ran out of time, was cancelled, or failed.
//
// It is the one rule behind "does this phase count against the scan's
// coverage", and it lives here because three places need the same answer: the
// completeness verdict, the partial banner, and the union of reasons on the
// terminal event. The third did not have it, so an already-partial scan's
// scan.finished could carry a `no_modules` that the banner and the phase line
// both — correctly — left out: one rule, three answers.
//
// The state check is part of the rule. A phase that FAILED without recording a
// reason is not a benign skip; it is the most serious thing that can happen to
// a phase, reported with no explanation.
func (o PhaseOutcome) BenignSkip() bool {
	if o.State != PhaseSkipped {
		return false
	}
	for _, reason := range o.Reasons {
		if reason != ReasonNoModules {
			return false
		}
	}
	return true
}

// phaseStateRank orders the states from "least to report" to "most". Skipped
// ranks LOWEST so a phase that ran once and was skipped once reads as having
// run; failed ranks highest because a lost phase is the headline whatever the
// other attempts managed.
var phaseStateRank = map[PhaseState]int{
	PhaseSkipped:   0,
	PhaseCompleted: 1,
	PhasePartial:   2,
	PhaseFailed:    3,
}

// Merge folds another outcome for the SAME phase into o.
//
// It exists for full-native-scan-on-receive, which runs the whole plan once per
// batch of arriving records: without coalescing, the scan row would accumulate
// one outcome per phase per iteration and grow without bound for the life of the
// run. Coalescing also gives the more useful answer — "what happened to the
// discovery phase in this scan" rather than a thousand separate verdicts — and
// for an ordinary scan, where each phase appears exactly once, it never fires.
//
// Reasons and limits union, counts sum, and the state is the worse of the two.
// The first message is kept: it is the first failure, which is normally the
// cause rather than a consequence of it.
func (o *PhaseOutcome) Merge(b PhaseOutcome) {
	o.Reasons = mergeCodes(o.Reasons, b.Reasons)
	o.Limits = mergeCodes(o.Limits, b.Limits)
	o.Errors += b.Errors
	if o.Message == "" {
		o.Message = b.Message
	}
	o.Unprocessed += b.Unprocessed
	o.DurationMS += b.DurationMS
	if phaseStateRank[b.State] > phaseStateRank[o.State] {
		o.State = b.State
	}
	switch {
	case b.Persistence == nil:
	case o.Persistence == nil:
		p := *b.Persistence
		o.Persistence = &p
	default:
		o.Persistence.Merge(*b.Persistence)
	}
	if b.Targets != nil {
		if o.Targets == nil {
			o.Targets = &TargetTally{}
		}
		o.Targets.Merge(*b.Targets)
	}
	for name, n := range b.Counts {
		if o.Counts == nil {
			o.Counts = make(map[string]int64, len(b.Counts))
		}
		o.Counts[name] += n
	}
	o.BudgetExhaustedHosts = mergeCodes(o.BudgetExhaustedHosts, b.BudgetExhaustedHosts)
	for module, n := range b.FindingsCapped {
		if o.FindingsCapped == nil {
			o.FindingsCapped = make(map[string]int64, len(b.FindingsCapped))
		}
		o.FindingsCapped[module] += n
	}
}

// SumFindingsCapped adds up the per-module capped counts across phases (nil
// when nothing was capped).
func SumFindingsCapped(phases []PhaseOutcome) map[string]int64 {
	var out map[string]int64
	for _, p := range phases {
		for module, n := range p.FindingsCapped {
			if out == nil {
				out = make(map[string]int64)
			}
			out[module] += n
		}
	}
	return out
}

// mergeCodes unions two code lists into one sorted, deduplicated list.
func mergeCodes(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, code := range a {
		set[code] = struct{}{}
	}
	for _, code := range b {
		set[code] = struct{}{}
	}
	return SortedCodes(set)
}

// SortedCodes returns the keys of a code set, sorted and deduplicated, or nil for
// an empty set — so a PhaseOutcome's Reasons/Limits are stable across runs and
// comparable between two scans of the same target.
func SortedCodes(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for code := range set {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// OutcomeMessageMax bounds the stored first-error text. A phase error can carry a
// wrapped chain with a full response body in it, and the scan row is read by
// every listing.
const OutcomeMessageMax = 512

// TruncateOutcomeMessage clips a message to OutcomeMessageMax bytes on a rune
// boundary, so a persisted outcome can never carry an unbounded error string or
// an invalid UTF-8 tail.
func TruncateOutcomeMessage(msg string) string {
	if len(msg) <= OutcomeMessageMax {
		return msg
	}
	cut := OutcomeMessageMax
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut]
}

// ScanCompletion is the scan-level roll-up of its phases: whether everything was
// covered, the single most useful explanation when it was not, and the per-phase
// detail behind that verdict.
type ScanCompletion struct {
	// Completeness is "complete", "partial", or "" (unknown — written by a caller
	// that has no outcome data, e.g. an older binary or an agent-driven scan).
	Completeness string         `json:"completeness,omitempty"`
	StopReason   string         `json:"stop_reason,omitempty"`
	Phases       []PhaseOutcome `json:"phases,omitempty"`
}

// Completeness values. Empty means unknown and must never be read as complete.
const (
	CompletenessComplete = "complete"
	CompletenessPartial  = "partial"
)
