package aem_ssrf

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const reproduceRounds = 2

// ssrfServlet is a known SSRF-capable AEM proxy/fetch servlet.
type ssrfServlet struct {
	id   string
	name string
	path string
	ref  []string
}

var servlets = []ssrfServlet{
	{
		id:   "contentinsight-reporting",
		name: "AEM ContentInsight Reporting-Services Proxy",
		path: "/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet",
	},
	{
		id:   "opensocial-proxy",
		name: "AEM OpenSocial Proxy",
		path: "/libs/opensocial/proxy",
	},
	{
		id:   "shindig-proxy",
		name: "AEM Shindig Proxy",
		path: "/libs/shindig/proxy",
	},
	{
		id:   "salesforce-secret",
		name: "AEM SalesforceSecretServlet (CVE-2018-12809)",
		path: "/libs/mcm/salesforce/customer.json",
		ref:  []string{"https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html"},
	},
	{
		id:   "accesstoken-verify",
		name: "AEM accesstoken/verify Service (CVE-2025-54249)",
		path: "/services/accesstoken/verify",
	},
	{
		id:   "sitecatalyst",
		name: "AEM SiteCatalyst Segments Proxy (SSRF→RCE)",
		path: "/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet",
		ref:  []string{"https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"},
	},
	{
		id:   "autoprovisioning",
		name: "AEM Cloud Services AutoProvisioning Servlet (SSRF→RCE)",
		path: "/libs/cq/cloudservicesprovisioning/content/autoprovisioning.json",
		ref:  []string{"https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps"},
	},
	{
		id:   "opensocial-makerequest",
		name: "AEM OpenSocial makeRequest Proxy",
		path: "/libs/opensocial/makeRequest",
	},
	{
		id:   "dam-cloud-proxy",
		name: "AEM DAM Cloud Proxy (ExternalJobServlet)",
		path: "/libs/dam/cloud/proxy.json",
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
		ds: dedup.LazyDiskSet("aem_ssrf"),
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
	for _, s := range servlets {
		if res := m.probe(ctx, httpClient, scanCtx, s, baseURL); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// probe confirms the servlet is a specific mount (responds as a handler, while a
// random sibling under the same directory 404s) rather than a catch-all, and
// reproduces — WITHOUT ever supplying a url= value, so no SSRF request is sent.
func (m *Module) probe(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	scanCtx *modkit.ScanContext,
	s ssrfServlet,
	baseURL string,
) *output.ResultEvent {
	res := aem.Get(ctx, client, s.path, nil)
	if !res.OK || !aem.ServletResponded(res.Status) {
		return nil
	}
	if modkit.ResemblesObservedPage(ctx, res.Body) {
		return nil
	}
	// A random sibling under the same directory must 404 — otherwise this is a
	// wildcard/catch-all mount, not the specific servlet.
	if !aem.SiblingIs404(ctx, client, s.path) {
		return nil
	}
	// Reproduce the servlet's specific response.
	if !aem.ReproduceMarker(ctx, client, s.path, reproduceRounds, func(r aem.ProbeResult) bool {
		return aem.ServletResponded(r.Status)
	}) {
		return nil
	}
	return m.build(s, res.Status, baseURL)
}

func (m *Module) build(s ssrfServlet, status int, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + s.path
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           matchedURL,
		Matched:       matchedURL,
		MatcherStatus: true,
		ExtractedResults: []string{
			"servlet: " + s.id,
			fmt.Sprintf("path: %s (status %d)", s.path, status),
			"detection-only: no SSRF request was sent (url= left unset)",
		},
		Info: output.Info{
			Name: s.name + " Exposed",
			Description: fmt.Sprintf(
				"The SSRF-capable AEM servlet %s is reachable (status %d, a specific mount — a random sibling 404s) and reproduced across %d rounds. Detection-only: no destination URL was supplied, so no server-side request was triggered. Confidence is Tentative because SSRF exploitation was not confirmed by design.",
				s.path, status, reproduceRounds,
			),
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
			Tags:       []string{"aem", "adobe", "ssrf", "exposure"},
			Reference:  s.ref,
		},
	}
}
