package runner

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
)

// ResumeError refuses a --resume-scan before anything is built: no session
// login, OAST registration or request happens for a resume that cannot
// proceed. Code is scan_not_found (no such scan in this project) or
// resume_mismatch (Diffs names what differs; --force resumes anyway).
type ResumeError struct {
	ScanUUID string
	// Kind is the stable error code (Code).
	Kind    apicontract.ErrorCode
	Message string
	Diffs   []ResumeDiff
}

func (e *ResumeError) Error() string { return e.Message }

// Code is the stable error code the CLI reports.
func (e *ResumeError) Code() apicontract.ErrorCode { return e.Kind }

// ResumeDiff is one aspect of the stored scan that differs from the run that
// would resume it: Field is targets, scope or modules.
type ResumeDiff struct {
	Field     string `json:"field"`
	Stored    string `json:"stored"`
	Requested string `json:"requested"`
}

// checkResume validates opts.ResumeScanUUID against the stored row, before
// buildInfrastructure. A resume that reuses another scan's row, cursor and
// coverage ledger is only meaningful for the same work: the ledger's done
// bits are per record and module, so a different target set, scope or module
// selection would skip work this run never did, or mix two scans in one row.
func (r *Runner) checkResume(ctx context.Context) error {
	uuid := r.options.ResumeScanUUID
	if uuid == "" || r.repository == nil {
		return nil
	}
	scan, err := r.lookupResumeScan(ctx, uuid)
	if err != nil {
		return err
	}
	diffs := ResumeMismatch(scan, r.options, r.settings)
	if len(diffs) == 0 || r.options.ResumeForce {
		return nil
	}
	parts := make([]string, 0, len(diffs))
	for _, d := range diffs {
		parts = append(parts, fmt.Sprintf("%s (stored %s, requested %s)", d.Field, d.Stored, d.Requested))
	}
	return &ResumeError{ScanUUID: uuid, Kind: apicontract.CodeResumeMismatch, Diffs: diffs,
		Message: fmt.Sprintf("--resume-scan %s: this run differs from the stored scan in %s; pass the same targets, scope and modules, or --force to resume anyway",
			uuid, strings.Join(parts, "; "))}
}

// lookupResumeScan loads the --resume-scan row: it must exist and belong to
// this run's project (the default project when none is set). Both refusals
// are a scan_not_found ResumeError — the up-front check and the row re-open
// report the same code.
func (r *Runner) lookupResumeScan(ctx context.Context, uuid string) (*database.Scan, error) {
	scan, err := r.repository.GetScanByUUID(ctx, uuid)
	if err != nil || scan == nil {
		return nil, &ResumeError{ScanUUID: uuid, Kind: apicontract.CodeScanNotFound,
			Message: fmt.Sprintf("--resume-scan %s: no such scan in this database", uuid)}
	}
	project := cmp.Or(r.options.ProjectUUID, database.DefaultProjectUUID)
	if scan.ProjectUUID != "" && scan.ProjectUUID != project {
		return nil, &ResumeError{ScanUUID: uuid, Kind: apicontract.CodeScanNotFound,
			Message: fmt.Sprintf("--resume-scan %s: the scan belongs to another project", uuid)}
	}
	return scan, nil
}

// ResumeMismatch compares a stored scan with the run that would resume it, on
// what the coverage ledger's meaning depends on:
//
//   - targets: the row's target list against opts.Targets, as sets;
//   - scope: the stored plan's scope rules (origin mode, host/path include and
//     exclude, static-file filter, the other non-default rules) against the
//     settings' — skipped when the row has no plan;
//   - modules: the built-in modules the row's assessment ran against
//     FilterModulesForRun's selection — skipped when the row never reached the
//     assessment. Extension modules are not compared: they are known only once
//     the extension engine is built.
func ResumeMismatch(scan *database.Scan, opts *types.Options, settings *config.Settings) []ResumeDiff {
	if scan == nil || opts == nil {
		return nil
	}
	var diffs []ResumeDiff
	if stored, requested := splitTargets(scan.Target), normalizedSet(opts.Targets); !slices.Equal(stored, requested) {
		diffs = append(diffs, ResumeDiff{Field: "targets", Stored: listOrNone(stored), Requested: listOrNone(requested)})
	}
	if settings != nil && len(scan.Plan) > 0 {
		var stored scanplan.Plan
		if json.Unmarshal(scan.Plan, &stored) == nil {
			want := resumeScopeKey(stored.Scope)
			got := resumeScopeKey(planScope(settings.Scope))
			if !reflect.DeepEqual(want, got) {
				diffs = append(diffs, ResumeDiff{Field: "scope", Stored: scopeSummary(want), Requested: scopeSummary(got)})
			}
		}
	}
	if stored := builtinModuleIDs(strings.Split(scan.Modules, ",")); len(stored) > 0 {
		sel := FilterModulesForRun(opts, settings)
		ids := make([]string, 0, len(sel.Active)+len(sel.Passive))
		for _, m := range sel.Active {
			ids = append(ids, m.ID())
		}
		for _, m := range sel.Passive {
			ids = append(ids, m.ID())
		}
		if requested := builtinModuleIDs(ids); !slices.Equal(stored, requested) {
			diffs = append(diffs, ResumeDiff{Field: "modules", Stored: moduleDelta(stored, requested), Requested: moduleDelta(requested, stored)})
		}
	}
	return diffs
}

// resumeScopeKey is the part of a plan's scope a resume must match: the
// rules, not the input census (InputHosts counts records, which a resumed
// scan's own crawl changes).
func resumeScopeKey(s scanplan.Scope) scanplan.Scope {
	key := scanplan.Scope{
		OriginMode: s.OriginMode, IgnoreStatic: s.IgnoreStatic,
		HostInclude: normalizedSet(s.HostInclude), HostExclude: normalizedSet(s.HostExclude),
		PathInclude: normalizedSet(s.PathInclude), PathExclude: normalizedSet(s.PathExclude),
	}
	for _, rule := range s.Rules {
		key.Rules = append(key.Rules, scanplan.ScopeRuleView{Class: rule.Class,
			Include: normalizedSet(rule.Include), Exclude: normalizedSet(rule.Exclude)})
	}
	slices.SortFunc(key.Rules, func(a, b scanplan.ScopeRuleView) int { return strings.Compare(a.Class, b.Class) })
	return key
}

func scopeSummary(s scanplan.Scope) string {
	parts := []string{"origin_mode=" + s.OriginMode}
	add := func(name string, v []string) {
		if len(v) > 0 {
			parts = append(parts, name+"="+strings.Join(v, ","))
		}
	}
	add("host_include", s.HostInclude)
	add("host_exclude", s.HostExclude)
	add("path_include", s.PathInclude)
	add("path_exclude", s.PathExclude)
	for _, rule := range s.Rules {
		add(rule.Class+"_include", rule.Include)
		add(rule.Class+"_exclude", rule.Exclude)
	}
	return strings.Join(parts, " ")
}

// splitTargets reads a scans.target value (the runner joins its targets with
// ", ") back into a normalized set.
func splitTargets(target string) []string {
	return normalizedSet(strings.Split(target, ","))
}

// normalizedSet trims, drops empties, sorts and deduplicates; never nil, so
// two empty sets compare equal.
func normalizedSet(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// builtinModuleIDs is the normalized set of ids without extension modules.
func builtinModuleIDs(ids []string) []string {
	var keep []string
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" && !strings.HasPrefix(id, ExtensionModulePrefix) {
			keep = append(keep, id)
		}
	}
	return normalizedSet(keep)
}

// moduleDelta renders the ids in a that b lacks, bounded, for the message.
func moduleDelta(a, b []string) string {
	var only []string
	for _, id := range a {
		if !slices.Contains(b, id) {
			only = append(only, id)
		}
	}
	if len(only) == 0 {
		return fmt.Sprintf("%d modules", len(a))
	}
	shown := only
	if len(shown) > 8 {
		shown = shown[:8]
	}
	s := fmt.Sprintf("%d modules, %d not in the other: %s", len(a), len(only), strings.Join(shown, ","))
	if len(only) > len(shown) {
		s += fmt.Sprintf(", +%d more", len(only)-len(shown))
	}
	return s
}

func listOrNone(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ",")
}
