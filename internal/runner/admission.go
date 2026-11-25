package runner

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TargetAdmission and TargetVerdict are aliased from pkg/types so callers that
// already import the runner need not import types for them.
type (
	TargetAdmission = types.TargetAdmission
	TargetVerdict   = types.TargetVerdict
)

// AdmitTargets evaluates every CLI target against scope before any request is
// sent, and says which ones the scan will actually reach.
//
// The matcher is built exactly as the runner builds the one the executor
// enforces — config.NewScopeMatcher(scope, targets...) over the full target
// list — so origin mode is computed over the same index and the verdict here is
// the one sendItem will apply. Each target is checked as the requester sends
// it (config.ScopeMatcher.RejectTarget): its port (the scheme's default when
// the URL names none), the hostname without port, the request-target (path
// plus query, "/" when empty), and the address rules an IP-literal or
// instance-metadata host is judged on without resolving it.
//
// Exported so pkg/cli can call it before the runner exists. A target that does
// not parse as a URL is admitted: scope cannot evaluate it, and refusing it here
// would hide the real (input) error behind a scope one.
func AdmitTargets(scope config.ScopeConfig, targets []string) TargetAdmission {
	var adm TargetAdmission
	if len(targets) == 0 {
		return adm
	}
	matcher := config.NewScopeMatcher(scope, targets...)
	for _, target := range targets {
		host, port, path, ok := admissionHostPath(target)
		if !ok {
			adm.Admitted = append(adm.Admitted, target)
			continue
		}
		if rule, _ := matcher.RejectTarget(host, port, path); rule != "" {
			adm.Rejected = append(adm.Rejected, TargetVerdict{Target: target, Host: host, Rule: rule})
			continue
		}
		adm.Admitted = append(adm.Admitted, target)
	}
	return adm
}

// admissionHostPath splits a target into the (host, port, path) the
// requester's send-time scope check evaluates. A schemeless target gets the
// same default scheme normalizeTargetSchemes gives it, and a URL without a
// port its scheme's default port.
func admissionHostPath(target string) (host string, port int, path string, ok bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, "", false
	}
	normalized, _ := httpmsg.EnsureURLSchemeTracked(target, httpmsg.DefaultTargetScheme)
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" {
		return "", 0, "", false
	}
	port, _ = strconv.Atoi(u.Port())
	if port == 0 {
		port = config.DefaultPortForScheme(u.Scheme)
	}
	return u.Hostname(), port, u.RequestURI(), true
}

// ErrNoTargetsInScope is what RunNativeScan's error wraps when scope admitted
// none of the scan's CLI targets: nothing was sent. Match it with errors.Is;
// errors.As on *TargetsRejectedError gives the per-target verdicts.
var ErrNoTargetsInScope = errors.New("no targets in scope")

// TargetsRejectedError is the typed form of ErrNoTargetsInScope, carrying the
// admission that refused every target, so a caller can name each target and the
// rule that refused it.
type TargetsRejectedError struct {
	Admission TargetAdmission
}

func (e *TargetsRejectedError) Error() string {
	return fmt.Sprintf("%s: scope rejected all %d target(s): %s",
		ErrNoTargetsInScope, len(e.Admission.Rejected), DescribeRejected(e.Admission.Rejected, 5))
}

func (e *TargetsRejectedError) Unwrap() error { return ErrNoTargetsInScope }

// DescribeRejected renders rejected targets as "target (rule)", comma
// separated, naming at most limit of them (limit <= 0 names all).
func DescribeRejected(rejected []TargetVerdict, limit int) string {
	return describeTargets(rejected, limit, func(v TargetVerdict) (string, string) { return v.Target, v.Rule })
}

// describeTargets renders items as "target (detail)", comma separated, naming
// at most limit of them (limit <= 0 names all) and summarising the rest as
// "and N more".
func describeTargets[T any](items []T, limit int, describe func(T) (target, detail string)) string {
	parts := make([]string, 0, len(items))
	for i, v := range items {
		if limit > 0 && i == limit {
			parts = append(parts, fmt.Sprintf("and %d more", len(items)-limit))
			break
		}
		target, detail := describe(v)
		parts = append(parts, fmt.Sprintf("%s (%s)", target, detail))
	}
	return strings.Join(parts, ", ")
}

// AdmissionTally is the preflight TargetTally for an admission: requested and
// admitted counts, and each rejected target with its rule as the issue code.
// Reached is left for the reachability check to fill.
func AdmissionTally(adm TargetAdmission) database.TargetTally {
	t := database.TargetTally{Requested: adm.Requested(), Admitted: len(adm.Admitted)}
	for _, v := range adm.Rejected {
		t.AddRejected(database.TargetIssue{Target: v.Target, Code: v.Rule})
	}
	return t
}

// admissionOutcome is the "preflight" pseudo-phase outcome for an admission:
// the tally, plus targets_out_of_scope when scope refused some targets or
// no_targets_in_scope when it refused them all. Completion turns either into a
// partial scan with that reason.
func admissionOutcome(adm TargetAdmission) database.PhaseOutcome {
	tally := AdmissionTally(adm)
	o := database.PhaseOutcome{Phase: string(PhasePreflight), Targets: &tally}
	switch {
	case adm.NoneAdmitted():
		o.Reasons = []string{database.ReasonNoTargetsInScope}
	case len(adm.Rejected) > 0:
		o.Reasons = []string{database.ReasonTargetsOutOfScope}
	}
	o.State = database.ResolvePhaseState(0, o.Reasons, false)
	return o
}

// targetAdmission is the scope verdict this run enforces over its CLI targets,
// or nil when the run's input is not its target list.
//
// The runner owns the decision, so it recomputes the verdict from its own
// settings and targets instead of trusting a copy: the CLI's copy is only for
// its banner and scan.started. Admission applies when the runner was built from
// its options' targets (runner.New with no stdin or target files left) or when
// the caller marked the targets as the input (Options.TargetAdmission, set by the
// CLI for a single-request -S scan). It never applies to scan-on-receive, whose
// input arrives later and is filtered record by record; there the executor's
// scope-rejected counter reports the drop (phaseTracker.noteExecution).
func (r *Runner) targetAdmission() *TargetAdmission {
	if r.settings == nil || len(r.options.Targets) == 0 {
		return nil
	}
	if r.options.ScanOnReceive || r.options.FullNativeScanOnReceive {
		return nil
	}
	if !r.targetsAreInput && r.options.TargetAdmission == nil {
		return nil
	}
	adm := AdmitTargets(r.settings.Scope, r.options.Targets)
	return &adm
}
