package cors_misconfiguration

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// corsProbe defines a single CORS test case.
type corsProbe struct {
	name       string
	origin     string              // literal origin to send, or "" if originFunc is used
	originFunc func(string) string // computes origin from target host (for subdomain bypass)
	check      func(acao, acac string) bool
	sev        severity.Severity
	desc       string
}

var probes = []corsProbe{
	{
		name:   "Reflected Origin",
		origin: "https://evil.example.com",
		check: func(acao, _ string) bool {
			return acao == "https://evil.example.com"
		},
		sev:  severity.Low,
		desc: "The server reflects arbitrary Origin values in Access-Control-Allow-Origin, allowing any site to read cross-origin responses.",
	},
	{
		name:   "Null Origin",
		origin: "null",
		check: func(acao, _ string) bool {
			return acao == "null"
		},
		sev:  severity.Low,
		desc: "The server allows the null origin, which can be exploited via sandboxed iframes or redirects to perform cross-origin requests.",
	},
	{
		name:   "Wildcard with Credentials",
		origin: "https://example.com",
		check: func(acao, acac string) bool {
			return acao == "*" && strings.EqualFold(acac, "true")
		},
		sev:  severity.Low,
		desc: "The server sets Access-Control-Allow-Origin to wildcard (*) while also allowing credentials, which is a misconfiguration that browsers should reject but may indicate insecure CORS logic.",
	},
	{
		name: "Subdomain Bypass",
		originFunc: func(host string) string {
			return "https://evil." + host
		},
		check: func(acao, _ string) bool {
			// acao must match the injected origin; checked by caller with the actual sent origin
			return acao != ""
		},
		sev:  severity.Low,
		desc: "The server trusts subdomains of the target host as allowed origins. An attacker controlling any subdomain (e.g. via subdomain takeover) can read cross-origin responses.",
	},
	{
		name: "Prefix Bypass",
		originFunc: func(host string) string {
			return "https://evil-" + host
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		sev:  severity.Low,
		desc: "The server uses incorrect prefix matching for origin validation. An attacker can register a domain prefixed with the target host to bypass CORS restrictions.",
	},
	{
		name: "Suffix Bypass",
		originFunc: func(host string) string {
			return "https://" + host + ".evil.com"
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		sev:  severity.Low,
		desc: "The server uses incorrect suffix matching for origin validation. An attacker can use a subdomain of their own domain that ends with the target hostname to bypass CORS restrictions.",
	},
	{
		name: "Port-Based Bypass",
		originFunc: func(host string) string {
			return "https://" + host + ":8443"
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		sev:  severity.Low,
		desc: "The server trusts origins on non-standard ports of the target host, which may be exploitable if other services run on those ports.",
	},
	{
		name:   "HTTP Scheme Confusion",
		origin: "http://evil.example.com",
		check: func(acao, _ string) bool {
			return acao == "http://evil.example.com"
		},
		sev:  severity.Low,
		desc: "The server reflects HTTP-scheme origins in ACAO, enabling mixed-content cross-origin attacks.",
	},
}

// Module implements the CORS misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CORS Misconfiguration module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("cors_misconfiguration"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (to confirm the host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	// Require a response to confirm the host is reachable
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerHost runs CORS misconfiguration probes once per unique host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		// Determine probe origin
		origin := probe.origin
		if probe.originFunc != nil {
			origin = probe.originFunc(host)
		}

		result, err := m.runProbe(ctx, httpClient, probe, origin)
		if err != nil {
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// runProbe executes a single CORS probe and returns a result if the check passes.
func (m *Module) runProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	probe corsProbe,
	origin string,
) (*output.ResultEvent, error) {
	// Set the Origin header on the raw request
	modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Origin", origin)
	if err != nil {
		return nil, err
	}

	// Parse the modified request
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	// Execute the request
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	// Read CORS headers
	acao := resp.Response().Header.Get("Access-Control-Allow-Origin")
	acac := resp.Response().Header.Get("Access-Control-Allow-Credentials")

	// For subdomain bypass, the check function needs the actual sent origin
	passes := false
	if probe.originFunc != nil {
		// Subdomain bypass: ACAO must exactly match the sent evil origin
		passes = acao == origin
	} else {
		passes = probe.check(acao, acac)
	}

	if !passes {
		return nil, nil
	}

	target := ctx.Target()

	return &output.ResultEvent{
		URL:     target,
		Matched: target,
		Request: string(modifiedRaw),
		ExtractedResults: []string{
			fmt.Sprintf("ACAO: %s", acao),
			fmt.Sprintf("ACAC: %s", acac),
			fmt.Sprintf("Probe: %s", probe.name),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("CORS Misconfiguration: %s", probe.name),
			Description: probe.desc,
			Severity:    probe.sev,
			Confidence:  severity.Certain,
			Reference:   []string{"https://portswigger.net/web-security/cors"},
		},
	}, nil
}
