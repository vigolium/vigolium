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

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	{
		path:        "/WEB-INF/web.xml",
		name:        "WEB-INF/web.xml",
		markers:     []string{"<web-app", "</web-app>", "servlet", "filter"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Java web deployment descriptor exposed, revealing servlet mappings, filters, and security constraints",
	},
	{
		path:        "/META-INF/MANIFEST.MF",
		name:        "META-INF/MANIFEST.MF",
		markers:     []string{"Manifest-Version", "Main-Class", "Implementation-"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Medium,
		desc:        "Java manifest file exposed, revealing build metadata, implementation details, and classpath information",
	},
	{
		path:        "/META-INF/maven/",
		name:        "META-INF Maven Directory",
		markers:     []string{"Index of", "Parent Directory", "pom.xml", "pom.properties"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Maven metadata directory listing exposed, revealing project coordinates and dependency details",
	},
	{
		path:        "/application.properties",
		name:        "Spring Application Properties",
		markers:     []string{"spring.", "server.", "management.", "datasource", "jdbc"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.properties file exposed, potentially containing database credentials, API keys, and internal service URLs",
	},
	{
		path:        "/application.yml",
		name:        "Spring Application YAML",
		markers:     []string{"spring:", "server:", "management:", "datasource:", "port:"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.yml file exposed, potentially containing credentials and configuration",
	},
	{
		path:        "/application.yaml",
		name:        "Spring Application YAML (alt)",
		markers:     []string{"spring:", "server:", "management:", "datasource:"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot application.yaml file exposed",
	},
	{
		path:        "/application-prod.properties",
		name:        "Spring Production Properties",
		markers:     []string{"spring.", "server.", "datasource", "password"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.Critical,
		desc:        "Spring Boot production configuration file exposed, likely containing production credentials",
	},
	{
		path:        "/application-dev.properties",
		name:        "Spring Dev Properties",
		markers:     []string{"spring.", "server.", "datasource"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Boot development configuration file exposed",
	},
	{
		path:        "/bootstrap.properties",
		name:        "Spring Bootstrap Properties",
		markers:     []string{"spring.", "cloud.", "config.", "eureka."},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Cloud bootstrap configuration exposed, potentially revealing config server and service discovery details",
	},
	{
		path:        "/bootstrap.yml",
		name:        "Spring Bootstrap YAML",
		markers:     []string{"spring:", "cloud:", "config:", "eureka:"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "404"},
		sev:         severity.High,
		desc:        "Spring Cloud bootstrap.yml exposed",
	},
	{
		path:        "/pom.xml",
		name:        "Maven POM",
		markers:     []string{"<project", "<modelVersion>", "<groupId>", "<artifactId>"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Maven POM file exposed, revealing project dependencies, versions, and build configuration",
	},
	{
		path:        "/build.gradle",
		name:        "Gradle Build File",
		markers:     []string{"dependencies", "plugins", "repositories", "implementation"},
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
			Name:        fmt.Sprintf("Java Sensitive File: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"java", "spring", "sensitive-file", "misconfiguration"},
			Reference:   []string{"https://tomcat.apache.org/tomcat-10.1-doc/security-howto.html"},
		},
	}
}
