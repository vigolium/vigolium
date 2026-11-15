package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Reachability on the CLI ("a dead target is loud"): a scan whose admitted
// targets never answered exits 1 with error.code no_targets_reachable, after
// its result document (or the runner's scan row) says which targets did not
// answer and why. The runner decides it for runner scans (preflight.go); the
// scan-url / scan-request direct path decides it from its executor, which
// already fetched the baseline — no extra request.

// directReach folds reachability across a scan-url / scan-request
// invocation's inputs, so the exit is 1 only when NO input answered: one dead
// target in a batch is reported on its own result, not as the batch's failure.
type directReach struct {
	reached     int
	unreachable []database.TargetIssue
	// hint is the remediation clause of the last unreachable input (the
	// scheme was inferred, ...), carried onto the coded error.
	hint string
}

// noteReached records an input that answered (or a runner-path input that
// finished without a reachability failure).
func (d *directReach) noteReached() {
	if d != nil {
		d.reached++
	}
}

// noteUnreachable records an input that got no HTTP answer.
func (d *directReach) noteUnreachable(issue database.TargetIssue, hint string) {
	if d == nil {
		return
	}
	d.unreachable = append(d.unreachable, issue)
	if hint != "" {
		d.hint = hint
	}
}

// settle turns the invocation's error into its final one: when inputs ran and
// none answered, the command fails with no_targets_reachable after every
// result was written. An earlier error is kept.
func (d *directReach) settle(err error) error {
	if d == nil || err != nil || d.reached > 0 || len(d.unreachable) == 0 {
		return err
	}
	return noTargetsReachableError(d.unreachable, d.hint)
}

// noTargetsReachableError is the command's error when no admitted target
// answered: error.code no_targets_reachable, exit 1. It wraps
// runner.ErrNoTargetsReachable so callers can still match it.
func noTargetsReachableError(issues []database.TargetIssue, hint string) error {
	if ph := runner.ProxyUnreachableHint(globalProxy, issues); ph != "" && !strings.Contains(hint, ph) {
		if hint != "" {
			hint += "; "
		}
		hint += ph
	}
	return clicommon.NewCodedError(apicontract.CodeNoTargetsReachable,
		&runner.TargetsUnreachableError{Unreachable: issues, Hint: hint})
}

// noteRunnerReach classifies a runner-path input's outcome for directReach:
// the runner's own no_targets_reachable is recorded (and, while other inputs
// may still answer, warned about instead of failing the batch); anything else
// that is not a scope refusal counts as reached. Returns the error the input
// should report.
func (d *directReach) noteRunnerReach(err error, batch bool) error {
	var unreachable *runner.TargetsUnreachableError
	switch {
	case errors.As(err, &unreachable):
		for _, issue := range unreachable.Unreachable {
			d.noteUnreachable(issue, unreachable.Hint)
		}
		if batch {
			if !globalSilent {
				fmt.Fprintf(os.Stderr, "%s %v\n", terminal.WarnPrefix(), err)
			}
			return nil
		}
		return err
	case err == nil:
		d.noteReached()
	}
	return err
}

// resolvedTargetOf is the scheme://host:port the request was actually sent to.
func resolvedTargetOf(rr *httpmsg.HttpRequestResponse) string {
	if rr == nil || rr.Service() == nil {
		return ""
	}
	svc := rr.Service()
	scheme := svc.Protocol()
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
}

// modulesExecuted counts the modules that ran at least once — what
// scanResult.modules_run reports. A module whose CanProcess rejected every
// item, or a run whose baseline never answered, executes nothing.
func modulesExecuted(e *core.Executor) int {
	if e == nil {
		return 0
	}
	n := 0
	for _, m := range e.ModuleMetrics() {
		if m.Invocations > 0 {
			n++
		}
	}
	return n
}

// unreachableIssue is the result's `unreachable` entry for a target whose
// baseline got no answer: the first classified baseline failure, or a generic
// "no HTTP answer" when the executor recorded none.
func unreachableIssue(target string, failures []core.BaselineFailure) database.TargetIssue {
	issue := database.TargetIssue{Target: target, Code: http.TransportErrOther, Detail: "no HTTP answer"}
	if len(failures) > 0 {
		issue.Code, issue.Detail = failures[0].Class, failures[0].Detail
	}
	return issue
}

// schemeHint is the remediation for a target nothing answered on whose scheme
// was inferred rather than given.
func schemeHint(source, resolved string) string {
	if source != schemeSourceDefault || !strings.HasPrefix(resolved, "https://") {
		return ""
	}
	authority := strings.TrimPrefix(resolved, "https://")
	return "inferred https:// (no Origin/Referer); pass -t http://" + authority + " if it is plain http"
}

// printUnreachableResult is the human line for an input that did not answer,
// in place of "Native scan completed ... No findings.".
func printUnreachableResult(result *scanResult) {
	reason := "no HTTP answer"
	if result.Unreachable != nil {
		reason = http.DescribeTransportClass(result.Unreachable.Code)
	}
	fmt.Fprintf(os.Stderr, "\n%s %s unreachable (%s) — %d modules ran — Scan ID: %s\n",
		terminal.ErrorSymbol(),
		terminal.Cyan(result.Target),
		reason,
		result.ModulesRun,
		terminal.BoldCyan(result.ScanUUID))
	if result.Unreachable != nil && result.Unreachable.Detail != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", terminal.Gray(result.Unreachable.Detail))
	}
	if hint := schemeHint(result.SchemeSource, result.ResolvedTarget); hint != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.TipPrefix(), terminal.Gray(hint))
	}
	if hint := runner.ProxyUnreachableHint(globalProxy, []database.TargetIssue{{Target: result.Target}}); hint != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.TipPrefix(), terminal.Gray(hint))
	}
}
