package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// Scope admission on the CLI: the verdict over a scan's targets, computed
// before any request is sent. scan, scan-url and scan-request gate on it at
// entry like every sender (sendScopeGate): a target the configured scope
// refuses — host, path, port, scope.cidr, or the private-address and
// instance-metadata blocks for an IP-literal host — ends the command with exit
// 2, error.code out_of_scope, before a plan, a scan row or a request; so does
// VIGOLIUM_REQUIRE_SCOPE=1 with a scope that names no hosts. The runner owns the decision for runner scans
// (runner.AdmitTargets in RunNativeScan); the CLI computes the same verdict for
// its banner and scan.started, and owns it outright on the scan-url /
// scan-request direct path, which has no runner.

// scanIgnoreScope is --ignore-scope on scan-url / scan-request: scan the given
// target even when the configured scope refuses it. The direct path then applies
// no scope at all, as it did before scope admission; the runner path (-S, -o,
// phase flags) relaxes the host and path rules for this run.
var scanIgnoreScope bool

// scopeEscapeHint is appended to the remediation of a no_targets_in_scope error
// by commands that offer an escape hatch (--ignore-scope).
var scopeEscapeHint string

const ignoreScopeFlagUsage = "Scan the target even when the configured scope rejects it (relaxes scope.host/scope.path for this run)"

// stdinHoldsRawRequests reports whether piped stdin content is raw HTTP or curl
// rather than a URL list: the one shape detection that decides whether piped
// lines become targets. An explicit -I pins the format, so only an unset one is
// sniffed.
func stdinHoldsRawRequests(content string, inputModeExplicit bool) bool {
	return content != "" && !inputModeExplicit && detect.DetectStdinFormat(content) != detect.FormatURLs
}

// scanTargetAdmission is the scope verdict over the targets `vigolium scan`
// will seed — -t / positional targets, -T target-list lines and a piped URL
// list — or nil when the scan's input is not a target list (-i, raw requests on
// stdin, a DB rescan). It reads what executeNativeScan is about to seed without
// seeding it, because the banner and scan.started go out first.
func scanTargetAdmission(settings *config.Settings, opts *types.Options, inputModeExplicit bool) *types.TargetAdmission {
	if settings == nil {
		return nil
	}
	targets, _, ok := scanSeededTargets(opts, inputModeExplicit)
	if !ok {
		return nil
	}
	adm := runner.AdmitTargets(settings.Scope, targets)
	return &adm
}

// scanEntryScopeGate is `vigolium scan`'s entry gate over the targets it is
// about to seed (scanSeededTargets); a scan whose input is not a target list
// is judged record by record by the executor and the requester instead.
func scanEntryScopeGate(settings *config.Settings, opts *types.Options, inputModeExplicit bool) error {
	if settings == nil {
		return nil
	}
	targets, _, _ := scanSeededTargets(opts, inputModeExplicit)
	matcher := config.NewScopeMatcher(settings.Scope, targets...)
	return refuseOutOfScope(matcher, runner.AdmitTargets(settings.Scope, targets))
}

// refuseOutOfScope is the entry gate's verdict: --require-scope's empty-scope
// refusal (VIGOLIUM_REQUIRE_SCOPE), then out_of_scope naming every target the
// admission rejected with its rule.
func refuseOutOfScope(matcher *config.ScopeMatcher, adm types.TargetAdmission) error {
	require, err := requireScopeRequested(os.Getenv)
	if err != nil {
		return err
	}
	if require && !matcher.RestrictsHosts() {
		return emptyScopeError()
	}
	if len(adm.Rejected) == 0 {
		return nil
	}
	return clicommon.CLIError{
		Err:  fmt.Errorf("outside the configured scope, nothing sent: %s", runner.DescribeRejected(adm.Rejected, 10)),
		Code: apicontract.CodeOutOfScope,
		Hint: scopeRemediation(adm.Rejected),
	}
}

// relaxScopeForIgnore widens the host, path, CIDR and port rules to the
// defaults (include everything, exclude nothing) for --ignore-scope on the
// runner path. Body limits, origin mode and the status/content-type rules are
// left as configured: the flag is about which target may be scanned, not how
// responses are kept. The send-time instance-metadata block still applies (no
// rule names the endpoint); the private-address block lifts for the CLI
// targets themselves.
func relaxScopeForIgnore(scope *config.ScopeConfig) {
	def := config.DefaultScopeConfig()
	scope.Host = def.Host
	scope.Path = def.Path
	scope.CIDR = def.CIDR
	scope.Port = def.Port
	scope.IgnoreStaticFile = false
}

// scopeRuleKey names the config key behind a rejection rule, for the
// remediation line.
func scopeRuleKey(rule string) string {
	switch rule {
	case config.ScopeRuleStaticFile:
		return "scope.ignore_static_file"
	case config.ScopeRuleCLIOriginMode:
		return "scope.cli_origin_mode (or --scope-origin all)"
	case config.ScopeRuleMetadataAddress, config.ScopeRulePrivateAddress:
		return "scope.host.include or scope.cidr.include (name the address to lift the " + rule + " block)"
	default:
		return rule
	}
}

// scopeRemediation is the one line that tells the operator what to change: the
// config keys behind every rule that refused a target, and how to check them.
func scopeRemediation(rejected []types.TargetVerdict) string {
	seen := map[string]bool{}
	var keys []string
	for _, v := range rejected {
		key := scopeRuleKey(v.Rule)
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	line := "fix " + strings.Join(keys, ", ") + " in the config (check it with `vigolium config validate`)"
	if scopeEscapeHint != "" {
		line += ", " + scopeEscapeHint
	}
	return line
}

// noTargetsInScopeError is the command's error when scope admitted none of its
// targets: error.code no_targets_in_scope, exit 1. It wraps
// runner.ErrNoTargetsInScope so callers can still match it.
func noTargetsInScopeError(adm types.TargetAdmission) error {
	err := &runner.TargetsRejectedError{Admission: adm}
	return clicommon.NewCodedError(apicontract.CodeNoTargetsInScope,
		fmt.Errorf("%w; %s", err, scopeRemediation(adm.Rejected)))
}

// codedScanError maps the runner's typed "did nothing" errors — scope refused
// every target, or no admitted target answered the preflight — to the coded CLI
// error (exit 1, error.code no_targets_in_scope / no_targets_reachable). Every
// other error passes through untouched.
func codedScanError(err error) error {
	var rejected *runner.TargetsRejectedError
	if errors.As(err, &rejected) {
		return noTargetsInScopeError(rejected.Admission)
	}
	var unreachable *runner.TargetsUnreachableError
	if errors.As(err, &unreachable) {
		return noTargetsReachableError(unreachable.Unreachable, unreachable.Hint)
	}
	return extensionLoadExitError(err)
}

// printTargetAdmission writes the banner's scope line under the Targets line:
// silent when everything was admitted, a count and the rules when some targets
// were refused, and every refused target plus the remediation when none was
// admitted.
func printTargetAdmission(w io.Writer, adm *types.TargetAdmission) {
	if adm == nil || len(adm.Rejected) == 0 {
		return
	}
	rules := map[string]bool{}
	var ruleList []string
	for _, v := range adm.Rejected {
		if !rules[v.Rule] {
			rules[v.Rule] = true
			ruleList = append(ruleList, v.Rule)
		}
	}
	line := fmt.Sprintf("Scope: %s admitted / %s rejected (%s)",
		terminal.Orange(fmt.Sprintf("%d", len(adm.Admitted))),
		terminal.Orange(fmt.Sprintf("%d", len(adm.Rejected))),
		strings.Join(ruleList, ", "))
	if !adm.NoneAdmitted() {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.Yellow(terminal.SymbolWarning), line)
		return
	}
	_, _ = fmt.Fprintf(w, "  %s %s — nothing will be sent\n", terminal.Red(terminal.SymbolError), line)
	for _, v := range adm.Rejected {
		_, _ = fmt.Fprintf(w, "      %s %s\n", terminal.Cyan(v.Target), terminal.Gray("("+v.Rule+")"))
	}
	_, _ = fmt.Fprintf(w, "    %s %s\n", terminal.TipPrefix(), terminal.Gray(scopeRemediation(adm.Rejected)))
}

// directAdmission is the scope verdict for a scan-url / scan-request
// invocation, computed over every input before any request goes out.
type directAdmission struct {
	adm      types.TargetAdmission
	rejected map[string]types.TargetVerdict // by input target
	matcher  *config.ScopeMatcher           // the executor's scope filter
}

// admitDirectInputs loads the settings and admits every input's target, or
// returns nil under --ignore-scope (the direct path then applies no scope, as
// it always did). The matcher is built over all inputs, exactly as the runner
// builds its own over Targets, so origin mode sees the same index.
func admitDirectInputs(cfg *directSettings, inputs []scanInput) (*directAdmission, error) {
	if scanIgnoreScope || len(inputs) == 0 {
		return nil, nil
	}
	// Global → the resolved project's overlay: the scope a project narrowed
	// with `scope set --project` is the one that admits these inputs
	// (--scope-origin applied).
	settings, err := cfg.get()
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(inputs))
	for _, in := range inputs {
		targets = append(targets, in.target)
	}
	d := &directAdmission{
		adm:      runner.AdmitTargets(settings.Scope, targets),
		rejected: map[string]types.TargetVerdict{},
		matcher:  config.NewScopeMatcher(settings.Scope, targets...),
	}
	for _, v := range d.adm.Rejected {
		d.rejected[v.Target] = v
	}
	return d, nil
}

// refuse is scan-url / scan-request's entry gate (refuseOutOfScope) over the
// admission; nil under --ignore-scope.
func (d *directAdmission) refuse() error {
	if d == nil {
		return nil
	}
	return refuseOutOfScope(d.matcher, d.adm)
}

// verdict returns the rejection for target, if scope refused it.
func (d *directAdmission) verdict(target string) (types.TargetVerdict, bool) {
	if d == nil {
		return types.TargetVerdict{}, false
	}
	v, ok := d.rejected[target]
	return v, ok
}

// scopeMatcher is the executor's scope filter, nil under --ignore-scope.
func (d *directAdmission) scopeMatcher() *config.ScopeMatcher {
	if d == nil {
		return nil
	}
	return d.matcher
}

// settle turns the invocation's error into its final one: when scope refused
// every input, the command fails with no_targets_in_scope after each input's
// result was written. A runner-path input that was refused already returned
// that coded error, which is kept.
func (d *directAdmission) settle(err error) error {
	if d == nil || !d.adm.NoneAdmitted() {
		return err
	}
	if err == nil {
		return noTargetsInScopeError(d.adm)
	}
	return err
}
