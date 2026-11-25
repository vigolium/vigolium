package http

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ScopeRefusal is the requester's send-time scope refusal: the destination,
// the scope rule that refused it and the pattern behind the rule. Nothing was
// sent. errors.Is(err, ErrHostOutOfScope) holds for it.
type ScopeRefusal struct {
	Host    string
	Port    int
	Rule    string
	Pattern string
}

func (e *ScopeRefusal) Error() string {
	dest := e.Host
	if e.Port > 0 {
		dest = net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	}
	if e.Pattern != "" {
		return fmt.Sprintf("request refused: %s is outside the scan scope (%s %s)", dest, e.Rule, e.Pattern)
	}
	return fmt.Sprintf("request refused: %s is outside the scan scope (%s)", dest, e.Rule)
}

// Is makes a ScopeRefusal match ErrHostOutOfScope.
func (e *ScopeRefusal) Is(target error) bool { return target == ErrHostOutOfScope }

// sendGuard is the requester's send-time scope check, shared by every clone of
// one requester: the request path (executeContext, every transport: the
// standard clients, the HTTP/2 fallback and the raw clients) and every
// redirect hop the standard client follows (makeScopedRedirectFunc).
//
// It judges a destination on the scope Services.SendScope holds: the host
// rule (RejectHost) and the destination rules (RejectAddress: port, explicit
// path exclusions, scope.cidr.exclude, and the private-address and
// instance-metadata blocks) over the addresses the host resolves to.
//
// Names are resolved through resolve, the same dialer the transports dial
// with, whose cache then serves the dial. Each name is resolved once per
// requester: a scan touches a bounded set of hosts, and re-resolving per
// request would double DNS on the hot path. A name that does not resolve is
// judged on its host and port alone; the send then fails on its own.
//
// The OAST client and the authentication login transport do not send through
// a Requester and are not judged here: a login flow may legitimately visit an
// identity provider the scan scope does not name.
type sendGuard struct {
	svc     *services.Services
	resolve func(host string) []netip.Addr
	addrs   sync.Map // lowercased hostname -> []netip.Addr
}

// newSendGuard builds the guard over svc's SendScope, resolving names with
// resolve (nil: names are never resolved). Nil-safe on use.
func newSendGuard(svc *services.Services, resolve func(host string) []netip.Addr) *sendGuard {
	return &sendGuard{svc: svc, resolve: resolve}
}

// check refuses a request for path to host:port with a *ScopeRefusal, or
// returns nil. hostRule false skips the host rule (a redirect hop under a mode
// that already decided which hosts it follows); the destination rules always
// apply. path "" skips the path exclusions.
func (g *sendGuard) check(host string, port int, path string, hostRule bool) error {
	if g == nil || host == "" {
		return nil
	}
	scope := g.svc.SendScopeOf()
	if scope == nil {
		return nil
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if hostRule {
		if rule, pattern := scope.RejectHost(host); rule != "" {
			return &ScopeRefusal{Host: host, Port: port, Rule: rule, Pattern: pattern}
		}
	}
	if rule, pattern := scope.RejectAddress(host, port, path, g.addresses(host)); rule != "" {
		return &ScopeRefusal{Host: host, Port: port, Rule: rule, Pattern: pattern}
	}
	return nil
}

// hostAdmits is the host rule as a predicate, or nil when no scope is
// installed (the in-scope redirect mode then falls back to same-apex).
func (g *sendGuard) hostAdmits() func(host string) bool {
	if g == nil {
		return nil
	}
	scope := g.svc.SendScopeOf()
	if scope == nil {
		return nil
	}
	return func(host string) bool {
		rule, _ := scope.RejectHost(strings.ToLower(strings.Trim(host, "[]")))
		return rule == ""
	}
}

// checkURL is check for a request to u.
func (g *sendGuard) checkURL(u *url.URL, hostRule bool) error {
	if g == nil || u == nil {
		return nil
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = httpmsg.GetDefaultPort(strings.ToLower(u.Scheme))
	}
	return g.check(u.Hostname(), port, u.EscapedPath(), hostRule)
}

// addresses is host's resolved addresses, cached; an IP literal is judged
// as itself by RejectAddress and is not resolved.
func (g *sendGuard) addresses(host string) []netip.Addr {
	if g.resolve == nil {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if v, ok := g.addrs.Load(host); ok {
		return v.([]netip.Addr)
	}
	addrs := g.resolve(host)
	g.addrs.Store(host, addrs)
	return addrs
}

// dnsResolver adapts a dialer's GetDNSData to the guard's resolver.
func dnsResolver(lookup func(host string) (a, aaaa []string, err error)) func(string) []netip.Addr {
	return func(host string) []netip.Addr {
		a, aaaa, err := lookup(host)
		if err != nil {
			zap.L().Debug("Send scope: name did not resolve; judged on host and port", zap.String("host", host), zap.Error(err))
			return nil
		}
		out := make([]netip.Addr, 0, len(a)+len(aaaa))
		for _, s := range append(append([]string(nil), a...), aaaa...) {
			if ip, err := netip.ParseAddr(s); err == nil {
				out = append(out, ip.Unmap())
			}
		}
		return out
	}
}
