package tomcat_manager_exposure

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	detect401   bool // if true, also detect 401 with WWW-Authenticate as Tomcat
}

var probes = []probe{
	{
		path:        "/manager/html",
		name:        "Tomcat Manager",
		markers:     []string{"Tomcat Manager", "Tomcat Web Application Manager", "Deploy", "Undeploy"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Critical,
		desc:        "Tomcat Manager web interface is accessible, enabling WAR deployment and application management. Brute-force or default credentials may lead to full server compromise",
		detect401:   true,
	},
	{
		path:        "/host-manager/html",
		name:        "Tomcat Host Manager",
		markers:     []string{"Host Manager", "Tomcat Virtual Host Manager", "Add Virtual Host"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Critical,
		desc:        "Tomcat Host Manager is accessible, enabling virtual host manipulation. Combined with default credentials, this can lead to server compromise",
		detect401:   true,
	},
	{
		path:        "/manager/status",
		name:        "Tomcat Server Status",
		markers:     []string{"Server Status", "JVM", "HTTP", "AJP", "Max threads"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Tomcat server status page exposed, revealing JVM information, connector details, and thread usage",
		detect401:   true,
	},
	{
		path:        "/examples/",
		name:        "Tomcat Examples",
		markers:     []string{"Servlet Examples", "JSP Examples", "WebSocket Examples", "examples"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "Tomcat example servlets are deployed, indicating incomplete hardening. Example apps may contain known vulnerabilities",
	},
	{
		path:        "/docs/",
		name:        "Tomcat Documentation",
		markers:     []string{"Apache Tomcat", "Documentation Index", "tomcat"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Info,
		desc:        "Tomcat documentation pages are deployed, revealing server version and indicating incomplete hardening",
	},
}

// Module implements the Tomcat Manager Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Tomcat Manager Exposure module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("tomcat_manager_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed Tomcat Manager and Host Manager interfaces.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-tomcat-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode

	// Check for 401 with Tomcat auth challenge
	if p.detect401 && status == 401 {
		wwwAuth := resp.Response().Header.Get("WWW-Authenticate")
		if strings.Contains(wwwAuth, "Tomcat") || strings.Contains(wwwAuth, "tomcat") {
			urlx, _ := ctx.URL()
			targetURL := urlx.Scheme + "://" + urlx.Host + p.path
			return &output.ResultEvent{
				URL:              targetURL,
				Matched:          targetURL,
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
				ExtractedResults: []string{"WWW-Authenticate: " + wwwAuth},
				Info: output.Info{
					Name:        fmt.Sprintf("Tomcat Admin Interface: %s (Auth Required)", p.name),
					Description: p.desc,
					Severity:    severity.Medium,
					Confidence:  severity.Firm,
					Tags:        []string{"tomcat", "java", "admin", "misconfiguration"},
					Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
				},
			}
		}
	}

	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	matched := false
	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponse().String(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Tomcat Admin Interface: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"tomcat", "java", "admin", "misconfiguration"},
			Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
		},
	}
}
