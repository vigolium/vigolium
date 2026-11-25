package config

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/pathglob"
	"go.uber.org/zap"
)

// Address and port scope: scope.cidr, scope.port, and the private-address and
// cloud-metadata block every send-time check applies.
//
// The host rule judges names; these rules judge where a request actually goes.
// An IP-literal host is judged by scope.cidr in the host decision itself
// (hostVerdict). A hostname is judged on the addresses it resolves to only at
// send time (RejectAddress), because only the sender resolves it.

// Scope rejection rules for the address and port checks. Like the ScopeRule*
// constants in scope_matcher.go, they name the key (or block) that refused.
const (
	ScopeRuleCIDRExclude = "scope.cidr.exclude"
	ScopeRuleCIDRInclude = "scope.cidr.include"
	ScopeRulePortExclude = "scope.port.exclude"
	ScopeRulePortInclude = "scope.port.include"
	// ScopeRuleMetadataAddress refuses a cloud instance-metadata endpoint
	// (MetadataHosts, metadataAddrs) no explicit scope entry names.
	ScopeRuleMetadataAddress = "metadata_address"
	// ScopeRulePrivateAddress refuses a private, loopback, link-local or
	// otherwise non-public address no explicit scope entry covers, under a
	// scope that names hosts (blocksPrivate).
	ScopeRulePrivateAddress = "private_address"
)

// Scope rule classes for the address and port rules (ScopeRuleClasses).
const (
	ScopeClassCIDR = "cidr"
	ScopeClassPort = "port"
)

// MetadataHosts are the cloud instance-metadata hostnames the send-time check
// refuses unless the scope names them exactly. A scanner running on a cloud
// instance that follows a target's name or redirect to one of these reads its
// OWN instance's credentials into the store.
var MetadataHosts = []string{"metadata.google.internal"}

// metadataAddrs are the instance-metadata addresses: AWS/GCP/Azure/OCI IPv4
// and AWS Nitro IPv6.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
}

// cgnatPrefix is RFC 6598 shared address space, which netip's IsPrivate does
// not cover and which carriers and cloud VPCs use for internal services.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// portRange is one inclusive port range of scope.port.
type portRange struct{ lo, hi int }

func (r portRange) String() string {
	if r.lo == r.hi {
		return strconv.Itoa(r.lo)
	}
	return strconv.Itoa(r.lo) + "-" + strconv.Itoa(r.hi)
}

// netRules is the compiled address and port half of a ScopeConfig.
type netRules struct {
	cidrInclude []netip.Prefix
	cidrExclude []netip.Prefix
	portInclude []portRange // nil: every port
	portExclude []portRange
	// named holds the hosts and addresses scope.host.include names exactly
	// (entries without a glob metacharacter); targets the CLI target hosts.
	// With scope.cidr.include they are what lifts the address blocks: the
	// metadata block only for a rule naming the endpoint itself, the private
	// block for a rule or target naming the host or the address.
	named   map[string]struct{}
	targets map[string]struct{}
}

// compileNetRules parses scope.cidr and scope.port and collects the explicit
// hosts. An entry that does not parse is warned about and skipped (ValidateScope
// reports it as an error); skipping an include entry narrows, never widens.
func compileNetRules(cfg ScopeConfig, targetHosts []string) netRules {
	var n netRules
	n.cidrInclude = parsePrefixes(cfg.CIDR.Include, "scope.cidr.include")
	n.cidrExclude = parsePrefixes(cfg.CIDR.Exclude, "scope.cidr.exclude")
	if !isDefaultPassAll(ScopeRule{Include: cfg.Port.Include}) {
		n.portInclude = parsePortRanges(cfg.Port.Include, "scope.port.include")
		if n.portInclude == nil {
			// Every include entry was invalid: the rule admits nothing rather
			// than everything.
			n.portInclude = []portRange{}
		}
	}
	n.portExclude = parsePortRanges(cfg.Port.Exclude, "scope.port.exclude")
	n.named = map[string]struct{}{}
	for _, p := range cfg.Host.Include {
		if h := normalizeScopeHost(p); h != "" && !strings.ContainsAny(h, "*?[") {
			n.named[h] = struct{}{}
		}
	}
	n.targets = map[string]struct{}{}
	for _, t := range targetHosts {
		if h := normalizeScopeHost(extractHostFromTarget(t)); h != "" {
			n.targets[h] = struct{}{}
		}
	}
	return n
}

// normalizeScopeHost lowercases a host and strips IPv6 brackets and a trailing
// root dot, the spelling every address-scope comparison uses.
func normalizeScopeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

// ParseScopePrefix parses one scope.cidr entry: a prefix ("10.0.0.0/8") or a
// bare address (a /32 or /128).
func ParseScopePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func parsePrefixes(entries []string, key string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		p, ok := ParseScopePrefix(e)
		if !ok {
			zap.L().Warn("Ignoring a scope entry that is not an address or prefix", zap.String("key", key), zap.String("entry", e))
			continue
		}
		out = append(out, p)
	}
	return out
}

// ParseScopePortRange parses one scope.port entry: "443" or "8000-8100"
// (1-65535, low <= high).
func ParseScopePortRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(s)
	a, b, isRange := strings.Cut(s, "-")
	lo, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
			return 0, 0, false
		}
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

func parsePortRanges(entries []string, key string) []portRange {
	var out []portRange
	for _, e := range entries {
		switch strings.TrimSpace(e) {
		case "":
			continue
		case "*":
			out = append(out, portRange{1, 65535})
			continue
		}
		lo, hi, ok := ParseScopePortRange(e)
		if !ok {
			zap.L().Warn("Ignoring a scope entry that is not a port or port range", zap.String("key", key), zap.String("entry", e))
			continue
		}
		out = append(out, portRange{lo, hi})
	}
	return out
}

// scopeHostAddr is host as an address when it is an IP literal.
func scopeHostAddr(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(host), "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func prefixContaining(prefixes []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	for _, p := range prefixes {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

// portVerdict judges port against scope.port; port <= 0 (unknown) is not
// judged.
func (m *ScopeMatcher) portVerdict(port int) (rule, pattern string) {
	if m == nil || port <= 0 {
		return "", ""
	}
	for _, r := range m.net.portExclude {
		if port >= r.lo && port <= r.hi {
			return ScopeRulePortExclude, r.String()
		}
	}
	if m.net.portInclude == nil {
		return "", ""
	}
	for _, r := range m.net.portInclude {
		if port >= r.lo && port <= r.hi {
			return "", ""
		}
	}
	return ScopeRulePortInclude, strings.Join(m.cfg.Port.Include, ", ")
}

// PortInScope reports whether scope.port admits port (an unknown port, <= 0,
// is admitted). Nil-safe.
func (m *ScopeMatcher) PortInScope(port int) bool {
	rule, _ := m.portVerdict(port)
	return rule == ""
}

// ipHostVerdict is the address half of hostVerdict for an IP-literal host:
// excluded is a scope.cidr.exclude refusal; admitted means a scope.cidr.include
// prefix holds it (the host rule's include side and origin mode are then not
// consulted); required means scope.cidr.include is the only list that can
// admit it and does not.
func (m *ScopeMatcher) ipHostVerdict(a netip.Addr) (excluded netip.Prefix, isExcluded, admitted, required bool) {
	if p, ok := prefixContaining(m.net.cidrExclude, a); ok {
		return p, true, false, false
	}
	if _, ok := prefixContaining(m.net.cidrInclude, a); ok {
		return netip.Prefix{}, false, true, false
	}
	return netip.Prefix{}, false, false, len(m.net.cidrInclude) > 0 && !hostIncludeNamesHosts(m.cfg.Host.Include)
}

// isMetadataHost reports whether host names an instance-metadata endpoint by
// name or address.
func isMetadataHost(host string) bool {
	h := normalizeScopeHost(host)
	for _, mh := range MetadataHosts {
		if h == mh {
			return true
		}
	}
	if a, ok := scopeHostAddr(h); ok {
		return isMetadataAddr(a)
	}
	return false
}

func isMetadataAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, m := range metadataAddrs {
		if a == m {
			return true
		}
	}
	return false
}

// IsNonPublicAddr reports whether a is loopback, private (RFC 1918, ULA),
// link-local, CGNAT shared space or unspecified: an address that reaches the
// scanner's own machine or network rather than a public target.
func IsNonPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsInterfaceLocalMulticast() || (a.Is4() && cgnatPrefix.Contains(a))
}

// namesMetadata reports whether a scope rule names this instance-metadata
// endpoint itself: a literal scope.host.include entry equal to the metadata
// hostname or the address, or a scope.cidr.include prefix holding the address.
// A CLI target does not count, nor does an in-scope name that happens to
// resolve there: a name pointed at the metadata address is the attack the
// block exists for.
func (m *ScopeMatcher) namesMetadata(host string, a netip.Addr) bool {
	if isMetadataHost(host) {
		if _, ok := m.net.named[normalizeScopeHost(host)]; ok {
			return true
		}
	}
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if _, ok := m.net.named[a.String()]; ok {
		return true
	}
	_, ok := prefixContaining(m.net.cidrInclude, a)
	return ok
}

// coversPrivate reports whether the operator named host or a exactly: a
// literal scope.host.include entry or a CLI target equal to the hostname or
// the address, or a scope.cidr.include prefix holding the address. A lab on
// loopback named as the target is covered; a discovered name that resolves
// into a private range is not.
func (m *ScopeMatcher) coversPrivate(host string, a netip.Addr) bool {
	for _, k := range []string{normalizeScopeHost(host), a.Unmap().String()} {
		if _, ok := m.net.named[k]; ok {
			return true
		}
		if _, ok := m.net.targets[k]; ok {
			return true
		}
	}
	_, ok := prefixContaining(m.net.cidrInclude, a.Unmap())
	return ok
}

// blocksPrivate reports whether the private-address block applies: the scope
// names which hosts are in it (RestrictsHosts) or which addresses
// (scope.cidr.include). A scope that names nothing admits every host by
// design, and has no entry that could lift the block for a lab on loopback;
// the metadata block applies regardless.
func (m *ScopeMatcher) blocksPrivate() bool {
	return m.RestrictsHosts() || len(m.net.cidrInclude) > 0
}

// RejectAddress is the destination half of the send-time check: it names the
// rule that refuses sending a request for path to host:port when host resolves
// to addrs, or "" when nothing does. The host rule itself (include side and
// origin mode) is RejectHost's; this judges what the host rule cannot:
//
//   - scope.port against port (<= 0: unknown, not judged);
//   - scope.path.exclude against path ("" is not judged) — the exclude side
//     only, as ExplicitlyExcluded: an include list narrows what is scanned,
//     not what a module may ask for;
//   - the instance-metadata block (MetadataHosts, 169.254.169.254,
//     fd00:ec2::254) on host and every address, lifted only by a scope rule
//     naming the endpoint itself (namesMetadata);
//   - scope.cidr.exclude against an IP-literal host and every address;
//   - the private-address block (IsNonPublicAddr) on every address, under a
//     scope that names hosts or addresses (blocksPrivate), lifted by a rule or
//     CLI target naming the host or the address (coversPrivate).
//
// An IP-literal host is judged as its own address whether or not addrs holds
// it. Nil-safe: no matcher refuses nothing.
func (m *ScopeMatcher) RejectAddress(host string, port int, path string, addrs []netip.Addr) (rule, pattern string) {
	if m == nil {
		return "", ""
	}
	if rule, pattern := m.portVerdict(port); rule != "" {
		return rule, pattern
	}
	if path != "" {
		if p, ok := excludePatternWith(pathglob.ScopePath(path), m.cfg.Path, pathGlobMatch); ok {
			return ScopeRulePathExclude, p
		}
	}
	h := normalizeScopeHost(host)
	if isMetadataHost(h) {
		a, _ := scopeHostAddr(h)
		if !m.namesMetadata(h, a) {
			return ScopeRuleMetadataAddress, h
		}
	}
	if a, ok := scopeHostAddr(h); ok {
		addrs = append([]netip.Addr{a}, addrs...)
	}
	private := m.blocksPrivate()
	for _, a := range addrs {
		a = a.Unmap()
		if p, ok := prefixContaining(m.net.cidrExclude, a); ok {
			return ScopeRuleCIDRExclude, p.String()
		}
		if isMetadataAddr(a) && !m.namesMetadata(h, a) {
			return ScopeRuleMetadataAddress, a.String()
		}
		if private && IsNonPublicAddr(a) && !m.coversPrivate(h, a) {
			return ScopeRulePrivateAddress, a.String()
		}
	}
	return "", ""
}

// RejectHost names the host-rule verdict on host (RejectDetail's host half:
// the runtime allow-set, scope.cidr for an IP literal, scope.host, the origin
// mode), "" when host is in scope. Answered from the host cache when host is
// in scope, so the send-time path pays one map read. Nil-safe.
func (m *ScopeMatcher) RejectHost(host string) (rule, pattern string) {
	if m == nil || m.hostInScope(host) {
		return "", ""
	}
	return m.hostVerdict(host)
}

// RejectTarget is RejectDetail for a destination whose port is known: the
// port rule, then the host and path rules, then the address rules an
// IP-literal or metadata host can be judged on without resolving it. It is
// what a command's entry gate asks before sending anything (scan, scan-url,
// scan-request, the senders); port <= 0 skips the port rule.
func (m *ScopeMatcher) RejectTarget(host string, port int, path string) (rule, pattern string) {
	if m == nil {
		return "", ""
	}
	if rule, pattern := m.portVerdict(port); rule != "" {
		return rule, pattern
	}
	if path == "" {
		if rule, pattern := m.hostVerdict(host); rule != "" {
			return rule, pattern
		}
	} else if rule, pattern := m.RejectDetail(host, path); rule != "" {
		return rule, pattern
	}
	return m.RejectAddress(host, 0, "", nil)
}

// DefaultPortForScheme is the port a URL without one connects to: the
// scheme's default from httpmsg.GetDefaultPort, 80 for a scheme it does not
// know.
func DefaultPortForScheme(scheme string) int {
	if p := httpmsg.GetDefaultPort(scheme); p > 0 {
		return p
	}
	return 80
}
