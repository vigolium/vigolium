package modkit

import (
	"net"
	"strconv"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// HeaderClassSet is a set of infra.HeaderClass values.
type HeaderClassSet uint8

// HeaderClasses builds a set.
func HeaderClasses(cs ...infra.HeaderClass) HeaderClassSet {
	var s HeaderClassSet
	for _, c := range cs {
		s |= 1 << uint(c)
	}
	return s
}

// Has reports whether c is in s.
func (s HeaderClassSet) Has(c infra.HeaderClass) bool { return s&(1<<uint(c)) != 0 }

// AllTestableHeaderClasses is every class but noise.
var AllTestableHeaderClasses = HeaderClasses(infra.HeaderClassApp, infra.HeaderClassNegotiation,
	infra.HeaderClassLogged, infra.HeaderClassRouting)

// HeaderInterest returns which header classes a vulnerability class tests:
// SQLi reaches logged and negotiation headers (log tables, locale
// lookups), command injection logged ones, traversal negotiation ones (locale
// file includes), SSRF routing ones. Everything else tests application headers
// only.
func HeaderInterest(vulnClass string) HeaderClassSet {
	switch vulnClass {
	case VulnClassSQLi, VulnClassNoSQLi:
		return HeaderClasses(infra.HeaderClassLogged, infra.HeaderClassNegotiation, infra.HeaderClassApp)
	case VulnClassCmdi:
		return HeaderClasses(infra.HeaderClassLogged, infra.HeaderClassApp)
	case VulnClassLFI:
		return HeaderClasses(infra.HeaderClassNegotiation, infra.HeaderClassApp)
	case VulnClassSSRF:
		return HeaderClasses(infra.HeaderClassRouting, infra.HeaderClassApp)
	default:
		return HeaderClasses(infra.HeaderClassApp)
	}
}

// HeaderClassAware lets a module override HeaderInterest.
type HeaderClassAware interface {
	HeaderClassSet() HeaderClassSet
}

// headerGateModule is what the gate needs from a module.
type headerGateModule interface {
	ID() string
	AllowedInsertionPointTypes() InsertionPointTypeSet
}

// HeaderClaims holds the once-per-host claims for logged, negotiation and
// routing headers: (origin, module, header) → claimed. Shared across a phase's
// executors.
type HeaderClaims struct {
	cache *lru.Cache[string, struct{}]
}

// headerClaimsSize bounds the claim set.
const headerClaimsSize = 65536

// NewHeaderClaims returns an empty claim set.
func NewHeaderClaims() *HeaderClaims {
	c, _ := lru.New[string, struct{}](headerClaimsSize)
	return &HeaderClaims{cache: c}
}

func headerClaimKey(origin, moduleID, header string) string {
	return origin + "\x00" + moduleID + "\x00" + header
}

// HeaderClaim takes the (origin, module, header) claim; true when this caller
// won it.
func (sc *ScanContext) HeaderClaim(origin, moduleID, header string) bool {
	if sc == nil || sc.HeaderClaims == nil {
		return true
	}
	seen, _ := sc.HeaderClaims.cache.ContainsOrAdd(headerClaimKey(origin, moduleID, strings.ToLower(header)), struct{}{})
	return !seen
}

// ReleaseHeaderClaim gives a claim back (the call it was taken for was
// cancelled or timed out, so the header was not really tested).
func (sc *ScanContext) ReleaseHeaderClaim(origin, moduleID, header string) {
	if sc == nil || sc.HeaderClaims == nil {
		return
	}
	sc.HeaderClaims.cache.Remove(headerClaimKey(origin, moduleID, strings.ToLower(header)))
}

// headerOnlyTypes reports whether a module tests headers and nothing else —
// a header-specialised module, whose interest is every testable class.
func headerOnlyTypes(t InsertionPointTypeSet) bool {
	return t != 0 && t&^HeaderTypes == 0
}

// HeaderGateDecision is the gate's verdict for one header point.
type HeaderGateDecision struct {
	Allow bool
	// Claimed is set when the decision took a once-per-host claim the caller
	// should release if the test did not complete.
	Claimed bool
}

// GateHeaderPoint decides whether module tests header point ip of a record on
// origin: noise headers never; headers outside the module's class
// interest (HeaderInterest by vuln class, a HeaderClassAware override, or —
// for header-only modules — every testable class) never; logged, negotiation
// and routing headers once per (origin, module, header); application headers
// per point. Non-header points always pass. HeaderPointsAll turns the gate
// off. class is infra.ClassifyHeader(ip.Name()), computed by the caller so a
// point shared by many modules is classified once.
func GateHeaderPoint(sc *ScanContext, module headerGateModule, vulnClass, origin string, ip httpmsg.InsertionPoint, class infra.HeaderClass) HeaderGateDecision {
	if ip == nil || ip.Type() != httpmsg.INS_HEADER || (sc != nil && sc.HeaderPointsAll) {
		return HeaderGateDecision{Allow: true}
	}
	if class == infra.HeaderClassNoise {
		return HeaderGateDecision{}
	}
	interest := HeaderInterest(vulnClass)
	if aware, ok := module.(HeaderClassAware); ok {
		interest = aware.HeaderClassSet()
	} else if headerOnlyTypes(module.AllowedInsertionPointTypes()) {
		interest = AllTestableHeaderClasses
	}
	if !interest.Has(class) {
		return HeaderGateDecision{}
	}
	if class == infra.HeaderClassApp {
		return HeaderGateDecision{Allow: true}
	}
	if !sc.HeaderClaim(origin, module.ID(), ip.Name()) {
		return HeaderGateDecision{}
	}
	return HeaderGateDecision{Allow: true, Claimed: true}
}

// moduleVulnClass reads a module's VulnClass() when it has one.
func moduleVulnClass(m any) string {
	if v, ok := m.(interface{ VulnClass() string }); ok {
		return v.VulnClass()
	}
	return ""
}

// RecordOrigin is the scheme://host:port identity header claims are keyed on.
func RecordOrigin(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if svc := item.Service(); svc != nil && svc.Host() != "" {
		return svc.Protocol() + "://" + net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
	}
	return RegistryHostKey(item)
}

// FilterPointsFor applies the header gate to a whole-request module's own
// point loop (sqli_time_blind, sqli_boolean_blind, command_injection_timing,
// command_injection_echo, code_exec), so header points are gated the same way
// the executor gates per-insertion-point modules. Gated points are counted
// through ScanContext.OnHeaderGated.
func FilterPointsFor(sc *ScanContext, module headerGateModule, item *httpmsg.HttpRequestResponse, points []httpmsg.InsertionPoint) []httpmsg.InsertionPoint {
	if sc != nil && sc.HeaderPointsAll {
		return points
	}
	vulnClass := moduleVulnClass(module)
	origin := RecordOrigin(item)
	out := points[:0:0]
	for _, ip := range points {
		if ip == nil || ip.Type() != httpmsg.INS_HEADER {
			out = append(out, ip)
			continue
		}
		if GateHeaderPoint(sc, module, vulnClass, origin, ip, infra.ClassifyHeader(ip.Name())).Allow {
			out = append(out, ip)
			continue
		}
		if sc != nil && sc.OnHeaderGated != nil {
			sc.OnHeaderGated(module.ID())
		}
	}
	return out
}
