package cli

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// sendScopeGate is the one scope check every command that sends requests runs
// before its first request (fuzz, dns, replay single and bulk, traffic
// --replay, kit param-mine, kit unlock-walk, finding verify): a host or path
// the configured scope refuses is not sent to, the command exits 2 with
// error.code out_of_scope, and --ignore-scope on that command overrides it.
//
// Both halves of the scope are enforced: scope.host (include, exclude, and the
// CLI origin mode) and scope.path (include, exclude) for every request whose
// path is known. A bare host (a dns name) is judged on the host rule alone. The
// static-file filter is not applied: it decides what is worth scanning, not
// what an operator may send on purpose.
//
// A project with no host scope configured admits every host — unless
// --require-scope (or VIGOLIUM_REQUIRE_SCOPE=1) is given, which makes a scope
// that names no hosts an out_of_scope refusal instead. A driver that always
// passes its own --config sets it so that a missing or empty scope fails
// closed rather than turning every sender into an open one.
//
// The scope is read from the settings the invocation loads: --config <file>
// when given (its scope section, whatever the global config says), else the
// discovered config, then the project overlay.
type sendScopeGate struct {
	matcher *config.ScopeMatcher
	ignore  bool
	require bool
}

// sendRequireScope is --require-scope on the senders. One variable for every
// command that registers it: the default is false on all of them, so the
// last-registered-wins binding cannot change a default.
var sendRequireScope bool

// requireScopeEnvVar is the environment form of --require-scope.
const requireScopeEnvVar = "VIGOLIUM_REQUIRE_SCOPE"

// requireScopeFlagUsage is --require-scope's help, shared by every sender.
const requireScopeFlagUsage = "Refuse to send (out_of_scope) when the configured scope names no hosts, instead of admitting every host (also VIGOLIUM_REQUIRE_SCOPE=1)"

// registerSendScopeFlags adds a sender's --ignore-scope (bound to ignore,
// with the command's own usage) and the shared --require-scope.
func registerSendScopeFlags(f *pflag.FlagSet, ignore *bool, ignoreUsage string) {
	f.BoolVar(ignore, "ignore-scope", false, ignoreUsage)
	f.BoolVar(&sendRequireScope, "require-scope", false, requireScopeFlagUsage)
}

// requireScopeRequested resolves --require-scope and its variable. The
// variable is parsed strictly (strictEnvBool): a misspelling is a usage error
// rather than a silent fail-open.
func requireScopeRequested(getenv func(string) string) (bool, error) {
	if sendRequireScope {
		return true, nil
	}
	v, _, err := strictEnvBool(getenv, requireScopeEnvVar)
	return v, err
}

// newSendScopeGate builds the gate from the scope scan-url and scan-request
// admit with: global settings with the invocation's project overlay, then
// --scope-origin, and the -t targets for the CLI origin mode. ignore is the
// command's --ignore-scope (nothing is loaded then, and --require-scope is
// moot: the caller has said to send regardless).
func newSendScopeGate(ignore bool) (sendScopeGate, error) {
	if ignore {
		return sendScopeGate{ignore: true}, nil
	}
	require, err := requireScopeRequested(os.Getenv)
	if err != nil {
		return sendScopeGate{}, err
	}
	settings, err := loadProjectSettings(globalConfig)
	if err != nil {
		return sendScopeGate{}, err
	}
	scope := settings.Scope
	if globalScopeOrigin != "" {
		scope.CLIOriginMode = globalScopeOrigin
	}
	return sendScopeGate{matcher: config.NewScopeMatcher(scope, globalTargets...), require: require}, nil
}

// sendTarget is one destination the gate judges: a host, and the request path
// when the caller knows it ("" when it does not).
type sendTarget struct {
	host string
	path string
}

// parseSendTarget reads a bare host, host:port or URL. Only a URL carries a
// path.
func parseSendTarget(v string) sendTarget {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			return urlSendTarget(u)
		}
	}
	return sendTarget{host: sendHostname(v)}
}

// urlSendTarget is the target of a request to u.
func urlSendTarget(u *url.URL) sendTarget {
	return sendTarget{host: strings.ToLower(u.Hostname()), path: requestPath(u)}
}

// requestPath is the path a request to u asks for: its escaped path, "/" when
// empty (a request to the origin asks for "/").
func requestPath(u *url.URL) string {
	return cmp.Or(u.EscapedPath(), "/")
}

// check refuses when any of entries is out of scope. Each entry may be a bare
// host, host:port or a URL (whose path is judged too); empty entries are
// skipped.
func (g sendScopeGate) check(entries ...string) error {
	targets := make([]sendTarget, 0, len(entries))
	for _, e := range entries {
		targets = append(targets, parseSendTarget(e))
	}
	return g.checkTargets(targets...)
}

// checkSource judges a parsed request: its destination host and the path on
// its request line (after a -t override, which changes only the host).
func (g sendScopeGate) checkSource(src *replaySource) error {
	if src == nil {
		return nil
	}
	path, _ := replaySourcePath(src)
	return g.checkTargets(sendTarget{host: strings.ToLower(src.Hostname), path: path})
}

// checkTargets is the gate itself.
func (g sendScopeGate) checkTargets(targets ...sendTarget) error {
	if g.ignore {
		return nil
	}
	if g.require && !g.matcher.RestrictsHosts() {
		return emptyScopeError()
	}
	if g.matcher == nil {
		return nil
	}
	var refused []string
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t.host == "" {
			continue
		}
		key := t.host + t.path
		if seen[key] {
			continue
		}
		seen[key] = true
		if t.path == "" {
			if !g.matcher.HostInScope(t.host) {
				refused = append(refused, t.host)
			}
			continue
		}
		if g.matcher.InScopeTarget(t.host, t.path) {
			continue
		}
		switch rule, pattern := g.matcher.RejectDetail(t.host, t.path); rule {
		case config.ScopeRulePathExclude, config.ScopeRulePathInclude:
			refused = append(refused, fmt.Sprintf("%s%s (%s %s)", t.host, t.path, rule, pattern))
		default:
			refused = append(refused, t.host)
		}
	}
	if len(refused) == 0 {
		return nil
	}
	return outOfScopeError(refused)
}

// admit is check for one target, the shape requestinput.Options.Admit takes.
func (g sendScopeGate) admit(target string) error { return g.check(target) }

// replaySourcePath is the path a parsed request will be sent to: the
// request-target on its first line (origin-form, or the path of an
// absolute-form URL), else the path of its URL. ok is false when neither is
// known.
func replaySourcePath(src *replaySource) (string, bool) {
	if target := httpmsg.NewHttpRequest(src.BaselineRequest).Path(); target != "" {
		if strings.HasPrefix(target, "/") {
			return target, true
		}
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return requestPath(u), true
		}
	}
	if src.URL != "" {
		if u, err := url.Parse(src.URL); err == nil && u.Host != "" {
			return requestPath(u), true
		}
	}
	return "", false
}

// outOfScopeError is the refusal: exit 2, error.code out_of_scope.
func outOfScopeError(refused []string) error {
	shown := refused
	more := ""
	if len(shown) > 10 {
		more = fmt.Sprintf(" (and %d more)", len(shown)-10)
		shown = shown[:10]
	}
	return clicommon.CLIError{
		Err:  fmt.Errorf("outside the configured scope, nothing sent: %s%s", strings.Join(shown, ", "), more),
		Code: apicontract.CodeOutOfScope,
		Hint: "pass --ignore-scope to send anyway, or widen scope.host.include / scope.path (vigolium scope ls shows the rules)",
	}
}

// emptyScopeError is --require-scope's refusal of a scope that names no hosts.
func emptyScopeError() error {
	return clicommon.CLIError{
		//vigolium:not-usage a refusal coded out_of_scope (exit 2), like outOfScopeError
		Err:  fmt.Errorf("--require-scope: the configured scope names no hosts (scope.host.include is empty), nothing sent"),
		Code: apicontract.CodeOutOfScope,
		Hint: "pass --config <file> with scope.host.include, add hosts with `vigolium scope add`, or drop --require-scope / VIGOLIUM_REQUIRE_SCOPE",
	}
}

// isOutOfScope reports whether err is the gate's refusal.
func isOutOfScope(err error) bool {
	var cliErr clicommon.CLIError
	return errors.As(err, &cliErr) && cliErr.Code == apicontract.CodeOutOfScope
}

// sendHostname is the hostname of a host, host:port or URL.
func sendHostname(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return strings.ToLower(strings.Trim(h, "[]"))
	}
	return strings.ToLower(strings.Trim(v, "[]"))
}
