package modkit

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

type gateMod struct {
	id    string
	types InsertionPointTypeSet
}

func (m gateMod) ID() string                                        { return m.id }
func (m gateMod) AllowedInsertionPointTypes() InsertionPointTypeSet { return m.types }

type hdrPoint struct{ name string }

func (h hdrPoint) Name() string                     { return h.name }
func (h hdrPoint) BaseValue() string                { return "v" }
func (h hdrPoint) Type() httpmsg.InsertionPointType { return httpmsg.INS_HEADER }
func (h hdrPoint) BuildRequest(p []byte) []byte     { return p }
func (h hdrPoint) PayloadOffsets(p []byte) []int    { return []int{0, len(p)} }
func (h hdrPoint) IsBaseValueEmpty() bool           { return false }

func TestClassifyHeader(t *testing.T) {
	for name, want := range map[string]infra.HeaderClass{
		"Sec-Fetch-Mode": infra.HeaderClassNoise, "sec-ch-ua": infra.HeaderClassNoise,
		"If-None-Match": infra.HeaderClassNoise, "Priority": infra.HeaderClassNoise,
		"Accept-Language": infra.HeaderClassNegotiation, "User-Agent": infra.HeaderClassLogged,
		"X-Forwarded-For": infra.HeaderClassLogged, "X-Forwarded-Host": infra.HeaderClassRouting,
		"Origin": infra.HeaderClassRouting, "X-Tenant": infra.HeaderClassApp,
	} {
		if got := infra.ClassifyHeader(name); got != want {
			t.Errorf("ClassifyHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

// The header gate (ECON-1).
func TestGateHeaderPoint(t *testing.T) {
	sc := &ScanContext{HeaderClaims: NewHeaderClaims()}
	sqli := gateMod{"sqli-x", AllInsertionPointTypes}
	xss := gateMod{"xss-x", AllInsertionPointTypes}
	lfi := gateMod{"lfi-x", AllInsertionPointTypes}
	ssrf := gateMod{"ssrf-x", AllInsertionPointTypes}
	headerOnly := gateMod{"hdr-x", HeaderTypes}
	const o1, o2 = "https://a.test:443", "https://b.test:443"

	allow := func(m gateMod, class, origin, header string) bool {
		return GateHeaderPoint(sc, m, class, origin, hdrPoint{header}).Allow
	}
	if allow(sqli, VulnClassSQLi, o1, "Sec-Fetch-Mode") {
		t.Error("noise header tested")
	}
	if !allow(sqli, VulnClassSQLi, o1, "User-Agent") {
		t.Error("SQLi must test User-Agent")
	}
	if allow(sqli, VulnClassSQLi, o1, "User-Agent") {
		t.Error("logged header tested twice on one origin")
	}
	if !allow(sqli, VulnClassSQLi, o2, "User-Agent") {
		t.Error("logged header must be tested once per origin, not once per scan")
	}
	if allow(xss, VulnClassXSS, o1, "User-Agent") {
		t.Error("XSS has no interest in logged headers")
	}
	if !allow(lfi, VulnClassLFI, o1, "Accept-Language") {
		t.Error("traversal must test Accept-Language")
	}
	if !allow(ssrf, VulnClassSSRF, o1, "X-Forwarded-Host") || allow(xss, VulnClassXSS, o1, "X-Forwarded-Host") {
		t.Error("routing headers are SSRF-only")
	}
	for i := 0; i < 3; i++ {
		if !allow(sqli, VulnClassSQLi, o1, "X-Tenant") {
			t.Error("application headers are tested per point, every time")
		}
	}
	if !allow(headerOnly, "", o1, "Origin") {
		t.Error("a header-only module tests every testable class")
	}

	// Release puts a claim back.
	sc.ReleaseHeaderClaim(o1, "sqli-x", "User-Agent")
	if !allow(sqli, VulnClassSQLi, o1, "User-Agent") {
		t.Error("released claim not re-claimable")
	}

	off := &ScanContext{HeaderPointsAll: true}
	if !GateHeaderPoint(off, xss, VulnClassXSS, o1, hdrPoint{"Sec-Fetch-Mode"}).Allow {
		t.Error("header_points: all must disable the gate")
	}
}
