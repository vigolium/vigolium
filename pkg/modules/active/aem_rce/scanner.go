package aem_rce

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
		ds: dedup.LazyDiskSet("aem_rce"),
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

	// Marker-based UI surfaces (Groovy Console, ACS Fiddle).
	for _, s := range uiSurfaces {
		if res := m.probeUI(ctx, httpClient, s, baseURL); res != nil {
			results = append(results, res)
		}
	}
	// Reachability-based deserialization surface (GetDocumentServlet).
	if res := m.probeGetDocument(ctx, httpClient, baseURL); res != nil {
		results = append(results, res)
	}
	// WebDAV PUT advertised on a content path (OPTIONS only — no write).
	if res := m.probePutAdvertised(ctx, httpClient, baseURL); res != nil {
		results = append(results, res)
	}

	return results, nil
}

// uiSurface is an RCE-capable console/tool identified by its page markers.
type uiSurface struct {
	id      string
	name    string
	paths   []string
	markers [][]string
	tags    []string
	ref     []string
}

var uiSurfaces = []uiSurface{
	{
		id:    "groovy-console",
		name:  "AEM Groovy Console Exposed (RCE-capable)",
		paths: []string{"/etc/groovyconsole.html", "/groovyconsole", "/etc/groovyconsole/jcr:content.html"},
		markers: [][]string{
			{"<title>Groovy Console</title>", "Groovy Web Console", "Run Script"},
			{"groovy", "Groovy"},
		},
		tags: []string{"groovy", "console"},
		ref:  []string{"https://github.com/orbinson/aem-groovy-console"},
	},
	{
		id:    "acs-fiddle",
		name:  "AEM ACS Commons Fiddle Exposed (JSP execution)",
		paths: []string{"/etc/acs-tools/aem-fiddle.html", "/etc/acs-tools/aem-fiddle/_jcr_content.html"},
		markers: [][]string{
			{"AEM Fiddle", "aem-fiddle", "Fiddle"},
			{"acs", "ACS"},
		},
		tags: []string{"acs-commons", "fiddle"},
		ref:  []string{"https://adobe-consulting-services.github.io/acs-aem-commons/"},
	},
}

func (m *Module) probeUI(ctx *httpmsg.HttpRequestResponse, client *http.Requester, s uiSurface, baseURL string) *output.ResultEvent {
	for _, path := range s.paths {
		res := aem.Get(ctx, client, path, nil)
		if !res.OK || res.Status != 200 {
			continue
		}
		body := modkit.StripReflectedProbePath(res.Body, path)
		if _, ok := modkit.MatchAllGroups(body, s.markers); !ok {
			continue
		}
		if modkit.ResemblesObservedPage(ctx, res.Body) {
			continue
		}
		if modkit.SiblingServesAnyMarker(nil, ctx, client, path, s.markers[0]) {
			continue
		}
		if !aem.ReproduceMarker(ctx, client, path, reproduceRounds, func(r aem.ProbeResult) bool {
			_, ok := modkit.MatchAllGroups(r.Body, s.markers)
			return r.Status == 200 && ok
		}) {
			continue
		}
		return &output.ResultEvent{
			ModuleID:      ModuleID,
			Host:          aem.HostFromBase(baseURL),
			URL:           baseURL + path,
			Matched:       baseURL + path,
			MatcherStatus: true,
			ExtractedResults: []string{
				"surface: " + s.id,
				"path: " + path,
				"detection-only: no script/JSP was executed",
			},
			Info: output.Info{
				Name: s.name,
				Description: fmt.Sprintf(
					"The RCE-capable AEM surface %s is reachable at %s (confirmed across %d rounds). Detection-only: no code was executed.",
					s.name, path, reproduceRounds,
				),
				Severity:   severity.Critical,
				Confidence: severity.Firm,
				Tags:       append([]string{"aem", "adobe", "rce"}, s.tags...),
				Reference:  s.ref,
			},
		}
	}
	return nil
}

// probeGetDocument confirms the AEM Forms GetDocumentServlet (CVE-2025-49533
// deserialization endpoint) is a specific mount, without sending a gadget.
func (m *Module) probeGetDocument(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL string) *output.ResultEvent {
	const path = "/FormServer/servlet/GetDocumentServlet"
	res := aem.Get(ctx, client, path, nil)
	if !res.OK || !aem.ServletResponded(res.Status) {
		return nil
	}
	if modkit.ResemblesObservedPage(ctx, res.Body) {
		return nil
	}
	if !aem.SiblingIs404(ctx, client, path) {
		return nil
	}
	if !aem.ReproduceMarker(ctx, client, path, reproduceRounds, func(r aem.ProbeResult) bool {
		return aem.ServletResponded(r.Status)
	}) {
		return nil
	}
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           baseURL + path,
		Matched:       baseURL + path,
		MatcherStatus: true,
		ExtractedResults: []string{
			"surface: getdocumentservlet",
			fmt.Sprintf("path: %s (status %d)", path, res.Status),
			"detection-only: no deserialization gadget was sent",
		},
		Info: output.Info{
			Name: "AEM Forms GetDocumentServlet Reachable (CVE-2025-49533 deserialization surface)",
			Description: fmt.Sprintf(
				"The AEM Forms GetDocumentServlet is reachable at %s (status %d, a specific mount). It is the CVE-2025-49533 insecure-deserialization endpoint. Detection-only: no serialized gadget was sent, so RCE was not confirmed by design.",
				path, res.Status,
			),
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
			Tags:       []string{"aem", "adobe", "rce", "deserialization", "cve", "cve2025"},
		},
	}
}

// probePutAdvertised reports a content path that advertises the WebDAV PUT method
// via OPTIONS — a write surface — without performing any write.
func (m *Module) probePutAdvertised(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseURL string) *output.ResultEvent {
	for _, path := range []string{"/content/usergenerated/", "/content/dam/"} {
		res := aem.Options(ctx, client, path, nil)
		if !res.OK || res.Header == nil {
			continue
		}
		allow := strings.ToUpper(res.Header.Get("Allow"))
		if !strings.Contains(allow, "PUT") {
			continue
		}
		return &output.ResultEvent{
			ModuleID:      ModuleID,
			Host:          aem.HostFromBase(baseURL),
			URL:           baseURL + path,
			Matched:       baseURL + path,
			MatcherStatus: true,
			ExtractedResults: []string{
				"surface: webdav-put",
				"path: " + path,
				"Allow: " + res.Header.Get("Allow"),
				"detection-only: no content was written",
			},
			Info: output.Info{
				Name: "AEM Content Path Advertises WebDAV PUT",
				Description: fmt.Sprintf(
					"OPTIONS %s advertises the PUT method (Allow: %s), indicating a Sling/WebDAV write surface. Detection-only: no write was attempted, so anonymous-write is not confirmed (Tentative).",
					path, res.Header.Get("Allow"),
				),
				Severity:   severity.Suspect,
				Confidence: severity.Tentative,
				Tags:       []string{"aem", "adobe", "webdav", "write"},
			},
		}
	}
	return nil
}
