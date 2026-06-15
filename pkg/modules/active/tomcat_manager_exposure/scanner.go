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
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Generic words ("Deploy",
	// "JVM", "HTTP", "AJP", "Server Status", "Documentation Index") never form a
	// group on their own — they appear on unrelated pages; each probe anchors on a
	// Tomcat-specific title/label.
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	detect401   bool // if true, also detect 401 with WWW-Authenticate as Tomcat
	bypass      bool // if true, also probe reverse-proxy path-normalization bypasses
}

var probes = []probe{
	{
		path: "/manager/html",
		name: "Tomcat Manager",
		// Anchor on the manager title, corroborate with a deploy action.
		markers:     [][]string{{"Tomcat Manager", "Tomcat Web Application Manager"}, {"Deploy", "Undeploy", "WAR file to deploy"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Critical,
		desc:        "Tomcat Manager web interface is accessible, enabling WAR deployment and application management. Brute-force or default credentials may lead to full server compromise",
		detect401:   true,
		bypass:      true,
	},
	{
		path:        "/host-manager/html",
		name:        "Tomcat Host Manager",
		markers:     [][]string{{"Tomcat Virtual Host Manager", "Host Manager"}, {"Add Virtual Host", "host-manager"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Critical,
		desc:        "Tomcat Host Manager is accessible, enabling virtual host manipulation. Combined with default credentials, this can lead to server compromise",
		detect401:   true,
		bypass:      true,
	},
	{
		path: "/manager/status",
		name: "Tomcat Server Status",
		// Require a Tomcat-status-specific token AND a status detail, so a page with
		// only "JVM"/"HTTP" cannot match.
		markers:     [][]string{{"Max threads", "Apache Tomcat", "Tomcat"}, {"Server Status", "JVM", "Current threads busy"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Tomcat server status page exposed, revealing JVM information, connector details, and thread usage",
		detect401:   true,
		bypass:      true,
	},
	{
		path:        "/examples/",
		name:        "Tomcat Examples",
		markers:     [][]string{{"Servlet Examples", "JSP Examples", "WebSocket Examples"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "Tomcat example servlets are deployed, indicating incomplete hardening. Example apps may contain known vulnerabilities",
	},
	{
		path:        "/docs/",
		name:        "Tomcat Documentation",
		markers:     [][]string{{"Apache Tomcat"}},
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// manager app mounted under a non-root path is reached, not just /manager.
	// Claim each (host, base) pair up front so a fully-deduped request issues no
	// traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	// Walk the bases and, once per host, fall back to the reverse-proxy path-
	// normalization bypass for any bypass-eligible admin endpoint the direct root
	// probe found blocked. The shared driver owns the status/hit bookkeeping and
	// the once-per-host + blocked-status gating.
	results := modkit.DriveProbesWithBypass(bases, probes, urlx.Path,
		func(p probe) string { return p.name },
		func(p probe) string { return p.path },
		func(p probe) bool { return p.bypass },
		func(p probe, probePath string) (*output.ResultEvent, int) {
			return m.probeEndpoint(ctx, httpClient, p, probePath, fp)
		})

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
	probePath string,
	fp *notFoundFingerprint,
) (*output.ResultEvent, int) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, 0
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil, 0
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, 0
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, 0
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, 0
	}

	status := resp.Response().StatusCode

	// Check for 401 with Tomcat auth challenge
	if p.detect401 && status == 401 {
		wwwAuth := resp.Response().Header.Get("WWW-Authenticate")
		if strings.Contains(wwwAuth, "Tomcat") || strings.Contains(wwwAuth, "tomcat") {
			urlx, _ := ctx.URL()
			targetURL := urlx.Scheme + "://" + urlx.Host + probePath
			return &output.ResultEvent{
				URL:              targetURL,
				Matched:          targetURL,
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: []string{"WWW-Authenticate: " + wwwAuth},
				Info: output.Info{
					Name:        fmt.Sprintf("Tomcat Admin Interface: %s (Auth Required)", p.name),
					Description: p.desc,
					Severity:    severity.Medium,
					Confidence:  severity.Firm,
					Tags:        []string{"tomcat", "java", "admin", "misconfiguration"},
					Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
				},
			}, status
		}
	}

	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil, status
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil, status
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil, status
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil, status
			}
		}
	}

	// Catch-all / shell guard: a body textually equivalent to the originally
	// observed page means the app served its standard shell for this path —
	// "the same body with or without the probe".
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil, status
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil, status
		}
	}

	if status != 200 {
		return nil, status
	}

	// Strip the reflected probe path before matching so a marker that is also the
	// path slug ("examples" for /examples/) can't match on a reflected href alone.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	// Require every marker group (Tomcat-specific anchor + corroboration), not a
	// single generic word like "Deploy" or "JVM", then drop the finding if a
	// nonexistent sibling under the same parent satisfies the same groups (a
	// sub-directory catch-all that 200s every child path). Root-level probes are
	// already covered by the random-path 404 fingerprint above.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, matchBody, p.markers)
	if !ok {
		return nil, status
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Tomcat Admin Interface: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"tomcat", "java", "admin", "misconfiguration"},
			Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
		},
	}, status
}
