package cli

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// sendScopeGate is the one scope check every command that sends requests runs
// before its first request (fuzz, dns, replay single and bulk, traffic
// --replay, kit param-mine, finding verify): a host the configured scope
// refuses is not sent to, the command exits 2 with error.code out_of_scope,
// and --ignore-scope on that command overrides it. A project with no host
// scope configured admits every host.
type sendScopeGate struct {
	matcher *config.ScopeMatcher
	ignore  bool
}

// newSendScopeGate builds the gate from the configured scope (and the -t
// targets, for the CLI origin mode). ignore is the command's --ignore-scope.
func newSendScopeGate(ignore bool) sendScopeGate {
	if ignore {
		return sendScopeGate{ignore: true}
	}
	return sendScopeGate{matcher: config.NewScopeMatcher(settingsOrDefaults().Scope, globalTargets...)}
}

// check refuses when any of hosts is out of scope. Each entry may be a bare
// host, host:port or a URL; empty entries are skipped.
func (g sendScopeGate) check(hosts ...string) error {
	if g.ignore || g.matcher == nil {
		return nil
	}
	var refused []string
	for _, h := range hosts {
		name := sendHostname(h)
		if name == "" || slices.Contains(refused, name) {
			continue
		}
		if !g.matcher.HostInScope(name) {
			refused = append(refused, name)
		}
	}
	if len(refused) == 0 {
		return nil
	}
	return outOfScopeError(refused)
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
		Err:  fmt.Errorf("outside the configured host scope, nothing sent: %s%s", strings.Join(shown, ", "), more),
		Code: apicontract.CodeOutOfScope,
		Hint: "pass --ignore-scope to send anyway, or widen scope.host.include (vigolium scope ls shows the rules)",
	}
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
