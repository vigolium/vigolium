package config

import (
	"net/netip"
	"testing"
)

func netScope(edit func(*ScopeConfig)) ScopeConfig {
	cfg := *DefaultScopeConfig()
	edit(&cfg)
	return cfg
}

// A private target inside scope.cidr.include is admitted at entry and at send
// time; a private address the scope does not name is refused by the block.
func TestScopeCIDR_PrivateTargetAdmittedByRule(t *testing.T) {
	cfg := netScope(func(c *ScopeConfig) {
		c.Host = ScopeRule{Include: []string{"*.example.com"}}
		c.CIDR = ScopeRule{Include: []string{"10.20.0.0/16"}}
	})
	m := NewScopeMatcher(cfg)
	if rule, _ := m.RejectTarget("10.20.3.4", 8080, "/"); rule != "" {
		t.Fatalf("CIDR-scoped private target refused at entry: %s", rule)
	}
	if rule, _ := m.RejectHost("10.20.3.4"); rule != "" {
		t.Fatalf("CIDR-scoped private target refused by the host rule: %s", rule)
	}
	if rule, _ := m.RejectAddress("10.20.3.4", 8080, "/", nil); rule != "" {
		t.Fatalf("CIDR-scoped private target refused at send time: %s", rule)
	}
	// A hostname the host rule admits, resolving inside the prefix.
	if rule, _ := m.RejectAddress("app.example.com", 443, "/", []netip.Addr{netip.MustParseAddr("10.20.0.9")}); rule != "" {
		t.Fatalf("in-scope name resolving into scope.cidr.include refused: %s", rule)
	}
	// The same name resolving to a private address outside it.
	if rule, pattern := m.RejectAddress("app.example.com", 443, "/", []netip.Addr{netip.MustParseAddr("192.168.1.5")}); rule != ScopeRulePrivateAddress || pattern != "192.168.1.5" {
		t.Fatalf("private resolution outside the rule = %q %q, want %q", rule, pattern, ScopeRulePrivateAddress)
	}
	// An IP literal outside the include list, with a host rule that names no IPs.
	if rule, _ := m.RejectTarget("10.30.0.1", 80, "/"); rule != ScopeRuleHostInclude {
		t.Fatalf("IP outside scope.cidr.include = %q, want %q", rule, ScopeRuleHostInclude)
	}
}

// With a host rule that names no hosts, scope.cidr.include is the only list
// that admits an IP literal.
func TestScopeCIDR_IncludeRequiredWhenHostRuleOpen(t *testing.T) {
	m := NewScopeMatcher(netScope(func(c *ScopeConfig) {
		c.CIDR = ScopeRule{Include: []string{"192.0.2.0/24"}}
	}))
	if !m.HostInScope("192.0.2.10") {
		t.Fatal("IP inside scope.cidr.include refused")
	}
	if rule, pattern := m.RejectDetail("198.51.100.1", "/"); rule != ScopeRuleCIDRInclude || pattern != "192.0.2.0/24" {
		t.Fatalf("IP outside scope.cidr.include = %q %q", rule, pattern)
	}
	if !m.HostInScope("www.example.org") {
		t.Fatal("scope.cidr.include narrowed a hostname")
	}
}

// scope.cidr.exclude refuses an IP literal and any address a name resolves to,
// whatever the include side admits.
func TestScopeCIDR_Exclude(t *testing.T) {
	m := NewScopeMatcher(netScope(func(c *ScopeConfig) {
		c.CIDR = ScopeRule{Include: []string{"10.0.0.0/8"}, Exclude: []string{"10.0.5.0/24", "2001:db8::1"}}
	}))
	if rule, pattern := m.RejectDetail("10.0.5.7", "/"); rule != ScopeRuleCIDRExclude || pattern != "10.0.5.0/24" {
		t.Fatalf("excluded IP literal = %q %q", rule, pattern)
	}
	if rule, _ := m.RejectAddress("api.example.net", 443, "", []netip.Addr{netip.MustParseAddr("2001:db8::1")}); rule != ScopeRuleCIDRExclude {
		t.Fatalf("name resolving into scope.cidr.exclude = %q", rule)
	}
}

// The instance-metadata endpoints are refused even by an open scope, and only
// an explicit entry naming them lifts the block; a glob does not.
func TestScopeMetadataBlock(t *testing.T) {
	open := NewScopeMatcher(*DefaultScopeConfig())
	for _, host := range []string{"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "METADATA.GOOGLE.INTERNAL."} {
		if rule, _ := open.RejectTarget(host, 80, "/latest/meta-data/"); rule != ScopeRuleMetadataAddress {
			t.Errorf("%s under the default scope = %q, want %q", host, rule, ScopeRuleMetadataAddress)
		}
	}
	// A public name that resolves to the metadata address.
	if rule, _ := open.RejectAddress("rebind.example.com", 80, "/", []netip.Addr{netip.MustParseAddr("169.254.169.254")}); rule != ScopeRuleMetadataAddress {
		t.Errorf("name resolving to the metadata address = %q", rule)
	}
	glob := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.Host = ScopeRule{Include: []string{"169.254.*"}} }))
	if rule, _ := glob.RejectTarget("169.254.169.254", 80, "/"); rule != ScopeRuleMetadataAddress {
		t.Errorf("a glob lifted the metadata block: %q", rule)
	}
	named := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.Host = ScopeRule{Include: []string{"169.254.169.254"}} }))
	if rule, _ := named.RejectTarget("169.254.169.254", 80, "/"); rule != "" {
		t.Errorf("an explicit host entry did not lift the metadata block: %q", rule)
	}
	cidr := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.CIDR = ScopeRule{Include: []string{"169.254.169.254/32"}} }))
	if rule, _ := cidr.RejectTarget("169.254.169.254", 80, "/"); rule != "" {
		t.Errorf("an explicit CIDR entry did not lift the metadata block: %q", rule)
	}
}

// A loopback lab named as the CLI target or in scope.host.include keeps
// working; a loopback address nothing names is refused under a scope that
// names hosts, and left alone under a scope that names none.
func TestScopePrivateBlock_LoopbackNamedExplicitly(t *testing.T) {
	byTarget := NewScopeMatcher(*DefaultScopeConfig(), "http://127.0.0.1:3000/")
	if rule, _ := byTarget.RejectTarget("127.0.0.1", 3000, "/"); rule != "" {
		t.Fatalf("loopback CLI target refused: %s", rule)
	}
	if rule, _ := byTarget.RejectAddress("127.0.0.1", 3000, "/", nil); rule != "" {
		t.Fatalf("loopback CLI target refused at send time: %s", rule)
	}
	byHost := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.Host = ScopeRule{Include: []string{"127.0.0.1", "localhost"}} }))
	if rule, _ := byHost.RejectAddress("localhost", 8080, "/", []netip.Addr{netip.MustParseAddr("::1")}); rule != "" {
		t.Fatalf("loopback named in scope.host.include refused: %s", rule)
	}
	restricted := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.Host = ScopeRule{Include: []string{"*.example.com"}} }))
	if rule, _ := restricted.RejectAddress("intranet.example.com", 80, "/", []netip.Addr{netip.MustParseAddr("127.0.0.1")}); rule != ScopeRulePrivateAddress {
		t.Fatalf("an in-scope name resolving to loopback = %q, want %q", rule, ScopeRulePrivateAddress)
	}
	open := NewScopeMatcher(*DefaultScopeConfig())
	if rule, _ := open.RejectAddress("127.0.0.1", 80, "/", nil); rule != "" {
		t.Fatalf("a scope naming nothing applied the private block: %s", rule)
	}
}

func TestScopePort(t *testing.T) {
	m := NewScopeMatcher(netScope(func(c *ScopeConfig) {
		c.Port = ScopeRule{Include: []string{"443", "8000-8100"}, Exclude: []string{"8081"}}
	}))
	for port, want := range map[int]string{443: "", 8050: "", 0: "", 80: ScopeRulePortInclude, 8081: ScopeRulePortExclude} {
		if rule, _ := m.RejectTarget("a.example.com", port, "/"); rule != want {
			t.Errorf("port %d = %q, want %q", port, rule, want)
		}
		if rule, _ := m.RejectAddress("a.example.com", port, "", nil); rule != want {
			t.Errorf("send-time port %d = %q, want %q", port, rule, want)
		}
	}
	if !NewScopeMatcher(*DefaultScopeConfig()).PortInScope(1) {
		t.Error("the default scope refused a port")
	}
}

// The send-time path check enforces explicit exclusions only.
func TestScopeRejectAddress_PathExcludeOnly(t *testing.T) {
	m := NewScopeMatcher(netScope(func(c *ScopeConfig) {
		c.Path = ScopeRule{Include: []string{"/api/*"}, Exclude: []string{"/logout*"}}
	}))
	if rule, _ := m.RejectAddress("a.example.com", 443, "/.git/config", nil); rule != "" {
		t.Errorf("the include side refused a send: %q", rule)
	}
	if rule, _ := m.RejectAddress("a.example.com", 443, "/logout?x=1", nil); rule != ScopeRulePathExclude {
		t.Errorf("an excluded path = %q", rule)
	}
}

func TestValidateScope_CIDRAndPort(t *testing.T) {
	issues := ValidateScope(netScope(func(c *ScopeConfig) {
		c.CIDR = ScopeRule{Include: []string{"10.0.0.0/8", "not-a-cidr"}}
		c.Port = ScopeRule{Include: []string{"443", "70000", "90-80"}}
	}))
	bad := map[string]int{}
	for _, is := range issues {
		if is.Code == IssueScopePatternInvalid {
			bad[is.Key]++
		}
	}
	if bad["scope.cidr.include"] != 1 || bad["scope.port.include"] != 2 {
		t.Fatalf("invalid entries = %v, want 1 cidr and 2 port", bad)
	}
}

// Neither a CLI target nor a named host resolving there lifts the metadata
// block: only a rule naming the endpoint itself does.
func TestScopeMetadataBlock_TargetsAndNamesDoNotLift(t *testing.T) {
	byTarget := NewScopeMatcher(*DefaultScopeConfig(), "http://169.254.169.254/")
	if rule, _ := byTarget.RejectTarget("169.254.169.254", 80, "/"); rule != ScopeRuleMetadataAddress {
		t.Errorf("a CLI target lifted the metadata block: %q", rule)
	}
	named := NewScopeMatcher(netScope(func(c *ScopeConfig) { c.Host = ScopeRule{Include: []string{"app.example.com"}} }))
	if rule, _ := named.RejectAddress("app.example.com", 443, "/", []netip.Addr{netip.MustParseAddr("169.254.169.254")}); rule != ScopeRuleMetadataAddress {
		t.Errorf("a named host resolving to the metadata address = %q", rule)
	}
	if rule, _ := named.RejectAddress("app.example.com", 443, "/", []netip.Addr{netip.MustParseAddr("10.0.0.1")}); rule != "" {
		t.Errorf("a named host resolving to a private address = %q, want admitted", rule)
	}
}
