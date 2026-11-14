package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
)

// The scan document: what `scan`, `run`, `scan-url` and `scan-request` print
// under -j.
//
// Those four commands used to answer -j in three shapes: a bare scan-url result
// object carrying nuclei-keyed findings (template-id, matched-at, info{}), an
// envelope of such objects for several targets, and — on every Runner path,
// `scan -j` included — the bulk JSONL export streamed to stdout. A driver had
// to know which path a flag combination took before it could parse the answer,
// and the findings in none of them had the shape `finding -j` gives the same
// rows.
//
// Now every path builds ONE envelope (kind "scan") through scanDocBuilder:
//
//   - AddDirect folds in a direct-path result (scan-url/scan-request with no
//     -S/-o/phase flags), read back from the store by scan_uuid when it was
//     persisted, else rendered from the in-memory results (findingViewFromEvent,
//     finding_hash as identity);
//   - AddRunner folds in a Runner pass, read from the scan row and its findings
//     while the database (a -S temp store included) is still open;
//   - AddStored folds in a finished scan read back by its row alone (what
//     `scan wait` prints), and AddStatusOnly one known only from its
//     status.json heartbeat file;
//   - Emit writes the document once per invocation and latches, so the root's
//     error envelope never follows it. A failed scan still gets its document,
//     with status "failed" and errors[]; the exit code carries the failure.
//
// The row fields come from database.ScanView (buildScanViews), the same view
// `db ls --table scans` renders, and the items from compactFindingView, the
// same view `finding -j` renders, so neither can drift from its read command.

// defaultScanDocLimit caps the findings embedded in a scan document's items.
// The rest stay one `query` away; total and counts_by_severity are exact.
const defaultScanDocLimit = 200

// scanDocLimit backs -n/--limit on the scan commands.
var scanDocLimit = defaultScanDocLimit

// registerScanDocumentFlags adds the scan document's shaping flags: the shared
// --fields/--compact/--full-body/--max-output-bytes of the read commands, and
// -n/--limit for the items cap.
func registerScanDocumentFlags(flags *pflag.FlagSet) {
	registerAgentJSONFlags(flags)
	flags.IntVarP(&scanDocLimit, "limit", "n", defaultScanDocLimit,
		"With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest")
}

// validateScanDocumentFlags checks the shaping flags before any network or
// database work, like every other command carrying them.
func validateScanDocumentFlags() error {
	if scanDocLimit < 0 {
		return usageErrorf("--limit must be >= 0 (0 = no cap), got %d", scanDocLimit)
	}
	if d := strings.TrimSpace(scanOpts.FingerprintDepth); d != "" {
		if _, ok := recon.ParseDepth(d); !ok {
			return usageErrorf("fingerprint depth %q: want light, standard or full", d)
		}
	}
	if scanDocListsHosts() {
		return hostsShaping.validate()
	}
	return validateAgentViewFlags(agentViewOptionsFromFlags(), findingViewFields)
}

// scanDocListsHosts reports whether this run's document lists host facts
// rather than findings: a fingerprint-only run (`vigolium fingerprint`, `run
// fingerprint`, `scan --only fingerprint`), whose output IS the origins it
// fingerprinted. Decided from the phase selection, not the command name, so
// every entry point to the same run gets the same document and vocabulary.
func scanDocListsHosts() bool {
	only := runner.OnlyPhaseSet(globalOnly)
	return len(only) == 1 && only[string(runner.PhaseFingerprint)]
}

// scanDocError is one entry of the document's errors[].
type scanDocError struct {
	Code    apicontract.ErrorCode `json:"code"`
	Message string                `json:"message"`
	Target  string                `json:"target,omitempty"`
}

// scanDocErrorOf classifies err the way the root's error envelope would.
func scanDocErrorOf(err error, target string) scanDocError {
	return scanDocError{Code: classifyErrorCode(err, classifyExitCode(err)), Message: err.Error(), Target: target}
}

// scanDocModules is the document's modules{}: selected is what the scan was
// handed, executed how many of those ran at least once.
type scanDocModules struct {
	Selected int `json:"selected"`
	Executed int `json:"executed"`
}

// scanDocTarget is one entry of targets[]. Reached is null when reachability
// was not checked (--skip preflight, an interrupted preflight, a target the
// input was not); Reason is "out_of_scope" (Code = the scope rule) or
// "unreachable" (Code = the transport error class), empty otherwise.
type scanDocTarget struct {
	Target         string `json:"target"`
	Method         string `json:"method,omitempty"`
	ScanUUID       string `json:"scan_uuid,omitempty"`
	Admitted       bool   `json:"admitted"`
	Reached        *bool  `json:"reached"`
	Reason         string `json:"reason,omitempty"`
	Code           string `json:"code,omitempty"`
	Detail         string `json:"detail,omitempty"`
	ResolvedTarget string `json:"resolved_target,omitempty"`
	SchemeSource   string `json:"scheme_source,omitempty"`
	Findings       *int64 `json:"findings,omitempty"`
	DurationMS     *int64 `json:"duration_ms,omitempty"`
	// Query is the follow-up for this target's own scan, set when the
	// document spans several scans (unpinned multi-target scan-url).
	Query string `json:"query,omitempty"`
}

// Per-target reasons.
const (
	scanDocReasonOutOfScope  = "out_of_scope"
	scanDocReasonUnreachable = "unreachable"
)

// scanDocScan is everything the document says about one scan row (or, with no
// store, one in-memory run).
type scanDocScan struct {
	scanUUID     string
	projectUUID  string
	status       string
	completeness string
	stopReason   string
	reasons      []string
	phases       []database.PhaseOutcome
	modules      scanDocModules
	counts       map[string]int
	total        int64
	items        []map[string]any
	candidates   int64
	observations int64
	persisted    bool
	dbPath       string
	startedAt    time.Time
	errors       []scanDocError
	targets      []scanDocTarget
	// plan is the resolved plan stored on the row (scans.plan), nil when the
	// row has none (a direct-path scan, an older binary).
	plan *scanplan.Plan
	// finishedAt and durationMS are the row's own, used when the document
	// describes a stored scan rather than this invocation's run.
	finishedAt time.Time
	durationMS int64
	// moduleErrors is the row's per-module error tally (caveats).
	moduleErrors map[string]int64
}

// scanDocBuilder accumulates one invocation's scan document. Not safe for
// concurrent use; the scan commands add their inputs one at a time.
type scanDocBuilder struct {
	command    string
	start      time.Time
	scans      []*scanDocScan
	notScanned []string
	// errors not attached to a scan: an input that failed before it had a row.
	errors  []scanDocError
	view    agentViewOptions
	limit   int
	emitted bool
	// fromRows: the document describes stored scans (AddStored/AddStatusOnly),
	// so its times are the scans' own, not this invocation's.
	fromRows bool
}

// newScanDocBuilder starts the document for command (its path without the root).
func newScanDocBuilder(command string) *scanDocBuilder {
	return &scanDocBuilder{
		command: command,
		start:   time.Now(),
		view:    agentViewOptionsFromFlags(),
		limit:   scanDocLimit,
	}
}

// scanFor returns the scan entry for uuid, creating it on first sight. A
// pinned --scan-uuid shares one row across inputs, so a later input refreshes
// the row-level fields of the same entry instead of adding a second.
func (b *scanDocBuilder) scanFor(uuid string) *scanDocScan {
	for _, s := range b.scans {
		if s.scanUUID == uuid && uuid != "" {
			return s
		}
	}
	s := &scanDocScan{scanUUID: uuid}
	b.scans = append(b.scans, s)
	return s
}

// docReadContext bounds the document's reads: they run after the scan, often
// on a detached path (an interrupt), and must not hang the exit.
func docReadContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// fillFromStore reads the scan's findings, counts and row back from the store.
// The row may be missing (it was never created); the findings are read anyway,
// by scan_uuid, which every finding of the run carries.
func (b *scanDocBuilder) fillFromStore(ctx context.Context, repo *database.Repository, s *scanDocScan, projectScope string) *database.Scan {
	filters := database.QueryFilters{ProjectUUID: projectScope, ObservedInScan: s.scanUUID, SortBy: "severity", Limit: b.limit}
	if scanDocListsHosts() {
		// The fingerprint document's items are the origins it fingerprinted,
		// the host facts `vigolium hosts` reads; findings are still counted.
		b.fillHostItems(ctx, repo, s, projectScope)
	} else if findings, total, err := repo.ListFindings(ctx, filters); err == nil {
		if !b.view.noBodies {
			hydrateFindingEvidence(ctx, repo, findings)
		}
		s.items = make([]map[string]any, 0, len(findings))
		for _, f := range findings {
			if projectScope == "" && globalStateless {
				// A -S temp store's row ids resolve to nothing once the run
				// exits; finding_hash is the identity, as for any unpersisted
				// finding.
				f.ID = 0
			}
			s.items = append(s.items, compactFindingView(f, nil, b.view))
		}
		s.total = total
	} else {
		s.errors = append(s.errors, scanDocError{Code: apicontract.CodeFailed, Message: "read findings: " + err.Error()})
	}
	s.counts = repo.ScanSeverityTally(ctx, s.scanUUID)
	s.candidates = countRecordKind(ctx, repo, projectScope, s.scanUUID, database.RecordKindCandidate)
	s.observations = countRecordKind(ctx, repo, projectScope, s.scanUUID, database.RecordKindObservation)

	row, err := repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil || row == nil {
		return nil
	}
	view := buildScanViews([]*database.Scan{row})[0]
	s.projectUUID = view.ProjectUUID
	s.completeness = view.Completeness
	s.stopReason = view.StopReason
	s.phases = view.PhaseOutcomes
	s.reasons = unionPhaseReasons(view.PhaseOutcomes)
	s.startedAt = view.StartedAt
	s.finishedAt = row.FinishedAt
	s.durationMS = row.DurationMs
	s.plan = storedScanPlan(row)
	s.moduleErrors = row.ModuleErrors
	return row
}

// fillHostItems sets s's items to the host facts the scan stored.
func (b *scanDocBuilder) fillHostItems(ctx context.Context, repo *database.Repository, s *scanDocScan, projectScope string) {
	rows, total, err := repo.ListHostObservationsWithCount(ctx, database.HostObservationQuery{
		ProjectUUID: projectScope, ScanUUID: s.scanUUID, Has: "fingerprint", Limit: b.limit})
	if err != nil {
		s.errors = append(s.errors, scanDocError{Code: apicontract.CodeFailed, Message: "read host facts: " + err.Error()})
		return
	}
	views := make([]hostView, 0, len(rows))
	for _, r := range rows {
		views = append(views, newHostView(r))
	}
	items, err := hostsShaping.applyRows(views)
	if err != nil {
		s.errors = append(s.errors, scanDocError{Code: apicontract.CodeFailed, Message: "render host facts: " + err.Error()})
		return
	}
	s.items = items
	s.total = int64(total)
}

// hydrateFindingEvidence loads the evidence columns the list query leaves out
// (request, response, additional_evidence) for the findings a scan document
// embeds — at most --limit of them, by primary key. The document carries the
// proof the scan found (response_evidence, the PoC request) the same way for a
// persisted run and for one whose store is gone with the process (-S), where
// it is the only copy; --compact skips it.
func hydrateFindingEvidence(ctx context.Context, repo *database.Repository, findings []*database.Finding) {
	byID := make(map[int64]*database.Finding, len(findings))
	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		if f != nil && f.ID != 0 {
			byID[f.ID] = f
			ids = append(ids, f.ID)
		}
	}
	for chunk := range slices.Chunk(ids, database.SQLChunkSize) {
		var loaded []*database.Finding
		if err := repo.DB().NewSelect().Model(&loaded).
			Column("id", "request", "response", "additional_evidence").
			Where("id IN (?)", bun.List(chunk)).
			Scan(ctx); err != nil {
			return
		}
		for _, row := range loaded {
			if f := byID[row.ID]; f != nil {
				f.Request, f.Response, f.AdditionalEvidence = row.Request, row.Response, row.AdditionalEvidence
			}
		}
	}
}

// countRecordKind counts a scan's candidates or observations; they appear in
// the document as counts only (`finding --scan-uuid … --record-kind …` lists
// them).
func countRecordKind(ctx context.Context, repo *database.Repository, projectScope, scanUUID, kind string) int64 {
	_, total, err := repo.ListFindings(ctx, database.QueryFilters{
		ProjectUUID: projectScope, ObservedInScan: scanUUID, RecordKinds: []string{kind}, Limit: 1,
	})
	if err != nil {
		return 0
	}
	return total
}

// runnerDocInput is one Runner pass, as AddRunner reads it.
type runnerDocInput struct {
	db     *database.DB
	opts   *types.Options
	runErr error
	// dbPath is the store a follow-up reads ("" when none can be named: a -S
	// temp store, a non-SQLite driver).
	dbPath string
	// method is the request method of a scan-url/scan-request input.
	method string
}

// AddRunner folds in a Runner pass. It must run while in.db is open and after
// the runner was closed (the row is final then): the scan commands call it from
// a defer registered right after the database opened.
func (b *scanDocBuilder) AddRunner(in runnerDocInput) {
	if b == nil || in.db == nil || in.opts == nil {
		return
	}
	ctx, cancel := docReadContext()
	defer cancel()
	repo := database.NewRepository(in.db)
	opts := in.opts

	known := slices.ContainsFunc(b.scans, func(x *scanDocScan) bool { return x.scanUUID == opts.ScanUUID })
	s := b.scanFor(opts.ScanUUID)
	row := b.fillFromStore(ctx, repo, s, exportProjectScope(opts))
	if row == nil && in.runErr != nil && s.total == 0 && !known {
		// Nothing ran far enough to leave a row: the failure is the answer, and
		// with nothing else in the document the root's error envelope says it.
		b.scans = slices.DeleteFunc(b.scans, func(x *scanDocScan) bool { return x == s })
		b.errors = append(b.errors, scanDocErrorOf(in.runErr, firstTarget(opts.Targets)))
		return
	}
	if s.projectUUID == "" {
		s.projectUUID = exportProjectScope(opts)
	}
	s.persisted = !opts.Stateless
	if s.persisted {
		s.dbPath = in.dbPath
	}

	runFailed := in.runErr != nil && !isExportFailure(in.runErr)
	s.status = scanDocStatus(activeScanSignals.Interrupted(), runFailed, s.completeness)
	if s.completeness == "" && s.status != scanevents.StatusCompleted {
		s.completeness = database.CompletenessPartial
	}
	if in.runErr != nil {
		s.errors = append(s.errors, scanDocErrorOf(in.runErr, ""))
	}
	s.modules = runnerDocModules(s.phases)

	var tally *database.TargetTally
	for _, p := range s.phases {
		if p.Phase == string(runner.PhasePreflight) && p.Targets != nil {
			tally = p.Targets
		}
	}
	s.targets = runnerDocTargets(opts.Targets, tally, s.scanUUID, in.method)
	if len(s.targets) == 1 {
		n := s.total
		s.targets[0].Findings = &n
		if row != nil && row.DurationMs > 0 {
			d := row.DurationMs
			s.targets[0].DurationMS = &d
		}
	}
}

// AddStored folds in a scan that has already ended, read back from the store by
// its row alone: what `scan wait` prints once the scan it polled is terminal.
// The document is the one the scan's own `scan -j` printed, rebuilt by the
// same reads (fillFromStore), so a driver that waited parses the same shape as
// one that ran the scan. effective is the scan status view's effective_status
// (completed, failed or cancelled); dbPath names the store for the follow-up.
func (b *scanDocBuilder) AddStored(ctx context.Context, repo *database.Repository, row *database.Scan, effective, dbPath string) {
	if b == nil || repo == nil || row == nil {
		return
	}
	b.fromRows = true
	s := b.scanFor(row.UUID)
	// Scoped by the row's own project: the findings of the scan live there,
	// and a -S read of a standalone file keeps its row ids resolvable.
	if got := b.fillFromStore(ctx, repo, s, row.ProjectUUID); got != nil {
		row = got
	}
	if s.projectUUID == "" {
		s.projectUUID = row.ProjectUUID
	}
	s.persisted = true
	s.dbPath = dbPath
	s.status = storedScanDocStatus(effective, s.completeness)
	if s.completeness == "" && s.status != scanevents.StatusCompleted {
		s.completeness = database.CompletenessPartial
	}
	if row.ErrorMessage != "" && s.status != scanevents.StatusCompleted && s.status != scanevents.StatusCurtailed {
		s.errors = append(s.errors, scanDocError{Code: apicontract.CodeFailed, Message: row.ErrorMessage})
	}
	s.modules = runnerDocModules(s.phases)

	var tally *database.TargetTally
	for _, p := range s.phases {
		if p.Phase == string(runner.PhasePreflight) && p.Targets != nil {
			tally = p.Targets
		}
	}
	s.targets = runnerDocTargets(splitStoredTargets(row.Target), tally, s.scanUUID, "")
	if len(s.targets) == 1 {
		n := s.total
		s.targets[0].Findings = &n
		if row.DurationMs > 0 {
			d := row.DurationMs
			s.targets[0].DurationMS = &d
		}
	}
}

// AddStatusOnly folds in a finished scan known only from its status.json
// heartbeat file: a -S or --db-isolate scan whose row is not in the store being
// read. The file carries counts, not findings, so items stay empty (total and
// counts_by_severity are exact; items_truncated says the rest is elsewhere) and
// the document is not "persisted" anywhere a follow-up could name.
func (b *scanDocBuilder) AddStatusOnly(v *scanStatusView) {
	if b == nil || v == nil {
		return
	}
	b.fromRows = true
	s := b.scanFor(v.ScanUUID)
	s.projectUUID = v.ProjectUUID
	s.completeness = v.Completeness
	s.stopReason = v.StopReason
	s.status = storedScanDocStatus(v.EffectiveStatus, s.completeness)
	if s.completeness == "" && s.status != scanevents.StatusCompleted {
		s.completeness = database.CompletenessPartial
	}
	s.total = int64(v.Findings)
	s.counts = map[string]int{}
	for sev, n := range v.FindingsBySeverity {
		s.counts[sev] = n
	}
	s.plan = v.Plan
	s.startedAt, s.finishedAt, s.durationMS = v.startedAt, v.finishedAt, v.DurationMS
	if v.ErrorMessage != "" && s.status == scanevents.StatusFailed {
		s.errors = append(s.errors, scanDocError{Code: apicontract.CodeFailed, Message: v.ErrorMessage})
	}
}

// storedScanDocStatus maps a finished scan's effective status (the `scan
// status` vocabulary) to the scan document's (the scan.finished one).
func storedScanDocStatus(effective, completeness string) string {
	switch effective {
	case effStatusFailed:
		return scanevents.StatusFailed
	case effStatusCancelled:
		return scanevents.StatusInterrupted
	}
	return scanDocStatus(false, false, completeness)
}

// splitStoredTargets undoes the runner's ", " join of the CLI targets on
// scans.target.
func splitStoredTargets(target string) []string {
	var out []string
	for _, t := range strings.Split(target, ", ") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// runnerDocModules reads modules{} off the dynamic-assessment phase, which
// records both counts (runner.CountModulesSelected/Executed). A run without
// that phase executed no modules.
func runnerDocModules(phases []database.PhaseOutcome) scanDocModules {
	for _, p := range phases {
		if p.Phase == string(runner.PhaseDynamicAssessment) && p.Counts != nil {
			return scanDocModules{
				Selected: int(p.Counts[runner.CountModulesSelected]),
				Executed: int(p.Counts[runner.CountModulesExecuted]),
			}
		}
	}
	return scanDocModules{}
}

// runnerDocTargets builds targets[] from the run's CLI targets and the
// preflight tally (scope admission, and reachability when it was checked).
// The tally's issue lists are capped at database.TargetIssueCap; a target past
// the cap reads as admitted with an unknown reach.
func runnerDocTargets(targets []string, tally *database.TargetTally, scanUUID, method string) []scanDocTarget {
	rejected := map[string]database.TargetIssue{}
	unreachable := map[string]database.TargetIssue{}
	checked := false
	if tally != nil {
		for _, issue := range tally.Rejected {
			rejected[issue.Target] = issue
		}
		for _, issue := range tally.Unreachable {
			unreachable[issue.Target] = issue
		}
		checked = tally.ReachabilityChecked
	}
	// A target the tally names but the list does not (it was normalized on
	// the way in) is still reported.
	all := append([]string(nil), targets...)
	for _, list := range [][]database.TargetIssue{tallyIssues(tally, true), tallyIssues(tally, false)} {
		for _, issue := range list {
			if !slices.Contains(all, issue.Target) {
				all = append(all, issue.Target)
			}
		}
	}
	out := make([]scanDocTarget, 0, len(all))
	for _, t := range all {
		entry := scanDocTarget{Target: t, Method: method, ScanUUID: scanUUID, Admitted: true}
		if issue, ok := rejected[t]; ok {
			entry.Admitted = false
			entry.Reason, entry.Code, entry.Detail = scanDocReasonOutOfScope, issue.Code, issue.Detail
		} else if checked {
			issue, dead := unreachable[t]
			reached := !dead
			entry.Reached = &reached
			if dead {
				entry.Reason, entry.Code, entry.Detail = scanDocReasonUnreachable, issue.Code, issue.Detail
			}
		}
		out = append(out, entry)
	}
	return out
}

func tallyIssues(t *database.TargetTally, rejected bool) []database.TargetIssue {
	if t == nil {
		return nil
	}
	if rejected {
		return t.Rejected
	}
	return t.Unreachable
}

// AddDirect folds in one direct-path result. A persisted result is read back
// from the store by scan_uuid, which gives the stored rows' id, status and
// http_record_uuids; an unpersisted one is rendered from its in-memory results.
// execErr is the execution's own error, if any.
func (b *scanDocBuilder) AddDirect(result *scanResult, execErr error) {
	if b == nil || result == nil {
		return
	}
	s := b.scanFor(result.ScanUUID)
	s.persisted = result.Persisted
	s.projectUUID = result.projectUUID

	var row *database.Scan
	if result.Persisted && result.repo != nil {
		ctx, cancel := docReadContext()
		row = b.fillFromStore(ctx, result.repo, s, result.projectUUID)
		cancel()
		s.dbPath = directDocDBPath()
	} else {
		b.fillFromResult(s, result)
	}

	// The input's own verdict, from the result: the row (when there is one)
	// says the same, but an unpersisted run has only this.
	failed := result.StopReason != "" || (execErr != nil && !result.Interrupted)
	if row == nil {
		s.stopReason = result.StopReason
		s.completeness = database.CompletenessComplete
		if failed || result.Interrupted {
			s.completeness = database.CompletenessPartial
		}
		if result.StopReason != "" {
			s.reasons = mergeReasonCodes(s.reasons, []string{result.StopReason})
		}
	}
	status := scanDocStatus(result.Interrupted, failed, s.completeness)
	// A pinned row shared across inputs: the first failed input does not make
	// the whole row failed when another answered; the row's own verdict wins
	// once there is more than one input in it.
	if s.status == "" || len(s.targets) == 0 {
		s.status = status
	} else {
		s.status = foldScanDocStatus([]string{s.status, status})
	}

	s.modules.Selected = max(s.modules.Selected, result.ModulesLoaded)
	s.modules.Executed = max(s.modules.Executed, result.ModulesRun)

	target := scanDocTarget{
		Target:         result.Target,
		Method:         result.Method,
		ScanUUID:       result.ScanUUID,
		Admitted:       result.StopReason != database.ReasonNoTargetsInScope,
		ResolvedTarget: result.ResolvedTarget,
		SchemeSource:   result.SchemeSource,
	}
	findings := int64(len(result.Findings))
	target.Findings = &findings
	if target.Admitted {
		duration := result.ScanDurationMs
		target.DurationMS = &duration
	}
	switch {
	case !target.Admitted:
		target.Reason = scanDocReasonOutOfScope
		if len(result.TargetsRejected) > 0 {
			target.Code = result.TargetsRejected[0].Rule
		}
		s.errors = append(s.errors, scanDocError{
			Code:    apicontract.CodeNoTargetsInScope,
			Message: fmt.Sprintf("%s rejected by scope (%s); nothing sent", result.Target, runner.DescribeRejected(result.TargetsRejected, 0)),
			Target:  result.Target,
		})
	case result.Unreachable != nil:
		reached := false
		target.Reached = &reached
		target.Reason, target.Code, target.Detail = scanDocReasonUnreachable, result.Unreachable.Code, result.Unreachable.Detail
		s.errors = append(s.errors, scanDocError{
			Code:    apicontract.CodeNoTargetsReachable,
			Message: fmt.Sprintf("%s did not answer (%s)", result.Target, result.Unreachable.Detail),
			Target:  result.Target,
		})
	case result.Reachable:
		reached := true
		target.Reached = &reached
	}
	if execErr != nil && !errors.Is(execErr, context.Canceled) {
		s.errors = append(s.errors, scanDocErrorOf(execErr, result.Target))
	}
	s.targets = append(s.targets, target)
}

// fillFromResult renders an unpersisted direct result: its findings through
// findingViewFromEvent, capped and ordered like the store read.
func (b *scanDocBuilder) fillFromResult(s *scanDocScan, result *scanResult) {
	events := append([]*output.ResultEvent(nil), result.Findings...)
	slices.SortStableFunc(events, func(x, y *output.ResultEvent) int {
		return severityRank(y.Info.Severity.String()) - severityRank(x.Info.Severity.String())
	})
	s.total += int64(len(events))
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	for _, ev := range events {
		s.counts[ev.Info.Severity.String()]++
		if b.limit > 0 && len(s.items) >= b.limit {
			continue
		}
		if v := findingViewFromEvent(ev, result.ScanUUID, result.projectUUID, b.view); v != nil {
			s.items = append(s.items, v)
		}
	}
	s.candidates += int64(len(result.Candidates))
	s.observations += int64(len(result.Observations))
}

// directDocDBPath names the store the direct path persisted into, for db_path
// and the follow-up; "" when it cannot be named on a command line.
func directDocDBPath() string {
	if driver := clicommon.OpenedDBDriver(); driver != "" && driver != "sqlite" {
		return ""
	}
	return clicommon.OpenedDBPath()
}

// AddError records an input that failed before it produced anything the
// document can describe (no row, no result).
func (b *scanDocBuilder) AddError(err error, target string) {
	if b == nil || err == nil {
		return
	}
	b.errors = append(b.errors, scanDocErrorOf(err, target))
}

// NoteNotScanned records the inputs an interrupt cut off before they started.
func (b *scanDocBuilder) NoteNotScanned(targets []string) {
	if b != nil {
		b.notScanned = append(b.notScanned, targets...)
	}
}

// scanDocStatus is one scan's status. interrupted beats failed: both say the
// run did not cover everything, and only interrupted says why (errors[] still
// carries the error). A partial verdict on an otherwise clean run is
// "curtailed", as on scan.finished.
func scanDocStatus(interrupted, failed bool, completeness string) string {
	switch {
	case interrupted:
		return scanevents.StatusInterrupted
	case failed:
		return scanevents.StatusFailed
	case completeness == database.CompletenessPartial:
		return scanevents.StatusCurtailed
	}
	return scanevents.StatusCompleted
}

// foldScanDocStatus folds several scans' statuses into the document's: failed
// only when every scan failed, interrupted when any was, curtailed when any
// fell short (a failed input among answered ones included).
func foldScanDocStatus(statuses []string) string {
	if len(statuses) == 0 {
		return scanevents.StatusCompleted
	}
	allFailed, anyShort := true, false
	for _, st := range statuses {
		if st == scanevents.StatusInterrupted {
			return st
		}
		if st != scanevents.StatusFailed {
			allFailed = false
		}
		if st != scanevents.StatusCompleted {
			anyShort = true
		}
	}
	switch {
	case allFailed:
		return scanevents.StatusFailed
	case anyShort:
		return scanevents.StatusCurtailed
	}
	return scanevents.StatusCompleted
}

// mergeReasonCodes unions reason codes, sorted.
func mergeReasonCodes(lists ...[]string) []string {
	set := map[string]struct{}{}
	for _, l := range lists {
		for _, c := range l {
			if c != "" {
				set[c] = struct{}{}
			}
		}
	}
	return database.SortedCodes(set)
}

func firstTarget(targets []string) string {
	if len(targets) == 1 {
		return targets[0]
	}
	return ""
}

// scanDocQueryArgv is the follow-up that lists a scan's findings from the
// store it persisted into — every one of them, not only the embedded items.
func scanDocQueryArgv(dbPath, projectUUID, scanUUID string) []string {
	argv := []string{"vigolium"}
	if dbPath != "" {
		argv = append(argv, "--db", absOrRaw(database.ExpandPath(dbPath)))
	}
	if cfg := strings.TrimSpace(globalConfig); cfg != "" {
		argv = append(argv, "--config", absOrRaw(cfg))
	}
	if projectUUID != "" {
		argv = append(argv, "--project-uuid", projectUUID)
	}
	return append(argv, "finding", "--scan-uuid", scanUUID, "-j")
}

// envelope assembles the document.
func (b *scanDocBuilder) envelope() *agentEnvelope {
	var (
		items        []map[string]any
		total        int64
		candidates   int64
		observations int64
		statuses     []string
		uuids        []string
		targets      = []scanDocTarget{}
		errs         = []scanDocError{}
		phases       []database.PhaseOutcome
		modules      scanDocModules
		reasonLists  [][]string
		stopReasons  = map[string]struct{}{}
		counts       = map[string]int{}
		persisted    = len(b.scans) > 0
		complete     = true
		projectUUID  string
		dbPath       string
		startedAt    = b.start
	)
	for _, sev := range severityOrder {
		counts[sev] = 0
	}
	multi := len(b.scans) > 1
	for _, s := range b.scans {
		items = append(items, s.items...)
		total += s.total
		candidates += s.candidates
		observations += s.observations
		statuses = append(statuses, s.status)
		if s.scanUUID != "" {
			uuids = append(uuids, s.scanUUID)
		}
		for sev, n := range s.counts {
			counts[sev] += n
		}
		phases = mergePhaseOutcomes(phases, s.phases)
		modules.Selected = max(modules.Selected, s.modules.Selected)
		modules.Executed = max(modules.Executed, s.modules.Executed)
		reasonLists = append(reasonLists, s.reasons)
		stopReasons[s.stopReason] = struct{}{}
		persisted = persisted && s.persisted
		complete = complete && s.completeness == database.CompletenessComplete
		if projectUUID == "" {
			projectUUID = s.projectUUID
		}
		if dbPath == "" {
			dbPath = s.dbPath
		}
		if !s.startedAt.IsZero() && s.startedAt.Before(startedAt) {
			startedAt = s.startedAt
		}
		for _, t := range s.targets {
			if multi && s.persisted && s.scanUUID != "" {
				t.Query = quoteArgv(scanDocQueryArgv(s.dbPath, s.projectUUID, s.scanUUID))
			}
			targets = append(targets, t)
		}
		errs = append(errs, s.errors...)
	}
	errs = append(errs, b.errors...)

	// Highest severity first across scans, then cap: each scan's own read was
	// already capped at the same limit, so the cut here is exact.
	slices.SortStableFunc(items, func(x, y map[string]any) int {
		return severityRank(fmt.Sprint(y["severity"])) - severityRank(fmt.Sprint(x["severity"]))
	})
	if b.limit > 0 && len(items) > b.limit {
		items = items[:b.limit]
	}
	if items == nil {
		items = []map[string]any{}
	}

	status := foldScanDocStatus(statuses)
	if len(b.scans) == 0 && len(b.notScanned) > 0 {
		status = scanevents.StatusInterrupted
	}
	if len(b.notScanned) > 0 && status == scanevents.StatusCompleted {
		status = scanevents.StatusInterrupted
	}
	completeness := database.CompletenessComplete
	if !complete || len(b.notScanned) > 0 || len(b.errors) > 0 {
		completeness = database.CompletenessPartial
	}

	// A stop reason is the document's only when every scan stopped for it. A
	// stop that hit some inputs of a batch and not others is a partial reason:
	// the plural code the runner uses for the same situation.
	stopReason := ""
	reasons := mergeReasonCodes(reasonLists...)
	if len(stopReasons) == 1 {
		for r := range stopReasons {
			stopReason = r
		}
	} else if len(b.scans) > 1 {
		reasons = partialBatchReasons(reasons)
	}

	limit := b.limit
	if limit == 0 {
		limit = len(items)
	}
	env := newAgentEnvelope(b.command, "findings", items, total, 0, limit)
	env.Kind = string(kindScan)
	env.WithProjectScope(projectUUID)
	stateless := globalStateless
	if persisted && !stateless {
		env.DBPath = dbPath
		if len(uuids) == 1 {
			argv := scanDocQueryArgv(dbPath, projectUUID, uuids[0])
			env.QueryArgv = argv
			env.Query = quoteArgv(argv)
		}
	}
	if len(uuids) == 1 {
		env.With("scan_uuid", uuids[0])
	}
	if uuids == nil {
		uuids = []string{}
	}
	notScanned := b.notScanned
	if notScanned == nil {
		notScanned = []string{}
	}
	if phases == nil {
		phases = []database.PhaseOutcome{}
	}
	moduleErrs := map[string]int64{}
	for _, s := range b.scans {
		for id, n := range s.moduleErrors {
			moduleErrs[id] += n
		}
	}
	caveats := database.CoverageCaveats(database.ScanCompletion{Phases: phases}, moduleErrs)
	if caveats == nil {
		caveats = []database.Caveat{}
	}
	if reasons == nil {
		reasons = []string{}
	}
	now := time.Now()
	finishedAt, durationMS := now, now.Sub(b.start).Milliseconds()
	if b.fromRows {
		// A stored scan's own times, not this invocation's: `scan wait` began
		// long after the scan did and ends after it.
		finishedAt, durationMS = time.Time{}, 0
		var earliest time.Time
		for _, s := range b.scans {
			if !s.startedAt.IsZero() && (earliest.IsZero() || s.startedAt.Before(earliest)) {
				earliest = s.startedAt
			}
			if s.finishedAt.After(finishedAt) {
				finishedAt = s.finishedAt
			}
			durationMS = max(durationMS, s.durationMS)
		}
		if !earliest.IsZero() {
			startedAt = earliest
		}
		if finishedAt.IsZero() {
			finishedAt = now
		}
		if durationMS == 0 && finishedAt.After(startedAt) {
			durationMS = finishedAt.Sub(startedAt).Milliseconds()
		}
	}
	// The plan is the scan's: embedded verbatim when the document describes
	// one scan whose row stored one, null otherwise (a direct-path scan, an
	// older binary, a document spanning several scans).
	var plan *scanplan.Plan
	if len(b.scans) == 1 {
		plan = b.scans[0].plan
	}
	env.With("scan_uuids", uuids).
		With("persisted", persisted && !stateless).
		With("stateless", stateless).
		With("status", status).
		With("completeness", completeness).
		With("reasons", reasons).
		With("targets", targets).
		With("targets_not_scanned", notScanned).
		With("phase_outcomes", phases).
		With("caveats", caveats).
		With("artifacts", collectedScanArtifacts()).
		With("baseline", baselineDocument()).
		With("next", scanDocNextSteps(uuids, dbPath, total, persisted && !stateless)).
		With("modules", modules).
		With("counts_by_severity", counts).
		With("candidates", candidates).
		With("observations", observations).
		With("errors", errs).
		With("items_truncated", total > int64(len(items))).
		With("plan", plan).
		With("duration_ms", durationMS).
		With("started_at", agentTimestamp(startedAt)).
		With("finished_at", agentTimestamp(finishedAt))
	if stopReason != "" {
		env.With("stop_reason", stopReason)
	}
	return env
}

// partialBatchReasons rewrites the all-inputs stop codes to their partial
// forms, for a batch in which only some inputs stopped.
func partialBatchReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case database.ReasonNoTargetsInScope:
			r = database.ReasonTargetsOutOfScope
		case database.ReasonNoTargetsReachable:
			r = database.ReasonTargetsUnreachable
		}
		out = append(out, r)
	}
	return mergeReasonCodes(out)
}

// mergePhaseOutcomes folds b's phases into a, merging same-named phases.
func mergePhaseOutcomes(a, b []database.PhaseOutcome) []database.PhaseOutcome {
	for _, p := range b {
		idx := slices.IndexFunc(a, func(x database.PhaseOutcome) bool { return x.Phase == p.Phase })
		if idx < 0 {
			a = append(a, p)
			continue
		}
		a[idx].Merge(p)
	}
	return a
}

// Emit writes the document — once per invocation, latched like every -j
// result, so the root does not append an error envelope after it. When no scan
// produced anything to describe and an input failed, nothing is written: the
// root's error envelope is then the honest answer.
func (b *scanDocBuilder) Emit() error {
	if b == nil || b.emitted || jsonResultEmitted {
		return nil
	}
	if len(b.scans) == 0 && len(b.errors) > 0 {
		return nil
	}
	b.emitted = true
	return writeAgentJSON(b.envelope())
}

// scanDocNextSteps is the document's `next`: the follow-up commands for a
// single persisted scan (empty for a batch, which names its scans instead).
func scanDocNextSteps(uuids []string, dbPath string, total int64, persisted bool) []scanNextStep {
	uuid := ""
	if len(uuids) == 1 {
		uuid = uuids[0]
	}
	return scanNextSteps(uuid, dbPath, total, persisted)
}
