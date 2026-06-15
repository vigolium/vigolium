package java_sensitive_files

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

// decoyRounds is how many same-parent/same-extension negative-control probes a
// candidate must survive before it is reported. An extension-scoped catch-all
// (e.g. an app shell that routes /WEB-INF/<anything>.xml to the same page) is
// disproved by requesting random sibling .xml paths; multiple rounds beat a shell
// that varies slightly per request (an embedded session token / path echo).
const decoyRounds = 2

type probe struct {
	path string
	name string
	// markerGroups is an AND-of-OR confirmation: the body must contain at least
	// one substring from EVERY group. Each probe anchors on a STRUCTURAL token the
	// real file always carries (an XML root tag, a manifest header, a fully-
	// qualified Spring property key) so a catch-all/SPA shell that merely contains
	// a bare word like "servlet" or "filter" in its JavaScript cannot match.
	markerGroups [][]string
	antiMarkers  []string
	sev          severity.Severity
	desc         string
}

var probes = []probe{
	{
		path: "/WEB-INF/web.xml",
		name: "WEB-INF/web.xml",
		markerGroups: [][]string{
			{"<web-app"},
			{"</web-app>", "<servlet", "<filter", "<servlet-mapping", "<welcome-file", "<context-param", "<session-config"},
		},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Java web deployment descriptor exposed, revealing servlet mappings, filters, and security constraints",
	},
	{
		path:         "/META-INF/MANIFEST.MF",
		name:         "META-INF/MANIFEST.MF",
		markerGroups: [][]string{{"Manifest-Version:"}},
		antiMarkers:  []string{"<html", "<!DOCTYPE", "404"},
		sev:          severity.Medium,
		desc:         "Java manifest file exposed, revealing build metadata, implementation details, and classpath information",
	},
	{
		path: "/META-INF/maven/",
		name: "META-INF Maven Directory",
		markerGroups: [][]string{
			{"Index of /", "Parent Directory", "Directory listing for"},
			{"pom.xml", "pom.properties", "maven"},
		},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Maven metadata directory listing exposed, revealing project coordinates and dependency details",
	},
	{
		path: "/application.properties",
		name: "Spring Application Properties",
		markerGroups: [][]string{{
			"spring.datasource", "spring.application", "spring.profiles", "spring.jpa",
			"server.port", "management.endpoints", "management.endpoint", "logging.level",
			"eureka.client", "jdbc:",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.properties file exposed, potentially containing database credentials, API keys, and internal service URLs",
	},
	{
		path: "/application.yml",
		name: "Spring Application YAML",
		markerGroups: [][]string{{
			"spring:", "datasource:", "management:", "eureka:", "hibernate:", "jpa:",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.yml file exposed, potentially containing credentials and configuration",
	},
	{
		path: "/application.yaml",
		name: "Spring Application YAML (alt)",
		markerGroups: [][]string{{
			"spring:", "datasource:", "management:", "eureka:", "hibernate:", "jpa:",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.yaml file exposed",
	},
	{
		path: "/application-prod.properties",
		name: "Spring Production Properties",
		markerGroups: [][]string{{
			"spring.datasource", "spring.application", "spring.profiles", "spring.jpa",
			"server.port", "management.endpoints", "eureka.client", "jdbc:",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot production configuration file exposed, likely containing production credentials",
	},
	{
		path: "/application-dev.properties",
		name: "Spring Dev Properties",
		markerGroups: [][]string{{
			"spring.datasource", "spring.application", "spring.profiles", "spring.jpa",
			"server.port", "management.endpoints", "eureka.client", "jdbc:",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Boot development configuration file exposed",
	},
	{
		path: "/bootstrap.properties",
		name: "Spring Bootstrap Properties",
		markerGroups: [][]string{{
			"spring.cloud", "spring.application.name", "spring.config", "eureka.client", "config.server",
		}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Cloud bootstrap configuration exposed, potentially revealing config server and service discovery details",
	},
	{
		path: "/bootstrap.yml",
		name: "Spring Bootstrap YAML",
		markerGroups: [][]string{
			{"cloud:", "eureka:", "config:", "spring:"},
			{"uri:", "service-url:", "name:", "discovery:", "server:"},
		},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Cloud bootstrap.yml exposed",
	},
	{
		path: "/pom.xml",
		name: "Maven POM",
		markerGroups: [][]string{
			{"<project"},
			{"<modelVersion>", "<artifactId>", "<groupId>", "<dependencies>", "<parent>"},
		},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Maven POM file exposed, revealing project dependencies, versions, and build configuration",
	},
	{
		path: "/build.gradle",
		name: "Gradle Build File",
		markerGroups: [][]string{
			{"dependencies", "plugins", "repositories"},
			{"implementation ", "testImplementation", "mavenCentral", "compileOnly", "runtimeOnly", "apply plugin"},
		},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Medium,
		desc:        "Gradle build file exposed, revealing project dependencies and build configuration",
	},
}

type notFoundFingerprint struct {
	status   int
	bodyHash string
	bodyLen  int
}

// Module implements the Java Sensitive Files active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Java Sensitive Files module.
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
		ds: dedup.LazyDiskSet("java_sensitive_files"),
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
		if result := m.probeFile(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-java-files-404-" + utils.RandomString(8)

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
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))

	status := 0
	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}

	return &notFoundFingerprint{
		status:   status,
		bodyHash: hash,
		bodyLen:  len(body),
	}
}

func (m *Module) probeFile(
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
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "user") {
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

	// Catch-all / SPA shell guard: a framework app (Salesforce, a SPA fallback)
	// returns the same application shell for any path. A path-probe whose body is
	// textually equivalent to the page originally observed on this host is that
	// shell, not an exposed file — drop it even if a weak marker appears inside.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Structural confirmation: require a hit from EVERY marker group (anchor tag
	// plus a corroborating element), so a bare "servlet"/"filter" word in an app
	// shell's JavaScript cannot forge a web.xml finding.
	matchedMarkers, ok := modkit.MatchAllGroups(body, p.markerGroups)
	if !ok {
		return nil
	}

	// Multi-round extension-scoped catch-all guard: confirm a random sibling that
	// shares this path's directory AND extension (e.g. /WEB-INF/<rand>.xml) does
	// NOT return the same markers or the same body. This subtracts the host that
	// routes every /<dir>/*.<ext> to one shell — the case the root soft-404
	// fingerprint cannot see.
	markerMatch := func(b string) bool {
		_, sibOK := modkit.MatchAllGroups(b, p.markerGroups)
		return sibOK
	}
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, markerMatch) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Java Sensitive File: %s", p.name),
			Description: p.desc,
			Severity:    modkit.CapSeverity(p.sev, severity.Medium),
			Confidence:  ModuleConfidence,
			Tags:        []string{"java", "spring", "sensitive-file", "misconfiguration"},
			Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
		},
	}
}
