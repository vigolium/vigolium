package spring_debug_exposure

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
		path:        "/error",
		name:        "Whitelabel Error Page",
		markers:     []string{"Whitelabel Error Page", "There was an unexpected error", "status="},
		antiMarkers: []string{"404", "nginx", "Apache"},
		sev:         severity.Low,
		desc:        "Spring Boot Whitelabel Error Page is enabled, confirming Spring Boot is running and may reveal version information",
	},
	{
		path:        "/error?trace=true",
		name:        "Whitelabel Error with Stack Trace",
		markers:     []string{"org.springframework", "at java.", "at org.", "Caused by:", ".java:"},
		antiMarkers: []string{},
		sev:         severity.Medium,
		desc:        "Spring Boot Whitelabel Error Page returns full stack traces when trace parameter is provided, revealing internal packages, libraries, and code paths",
	},
	{
		path:        "/error?message=true&trace=true",
		name:        "Whitelabel Error with Message and Trace",
		markers:     []string{"org.springframework", "Exception", "Caused by:"},
		antiMarkers: []string{},
		sev:         severity.Medium,
		desc:        "Spring Boot error page returns detailed error messages and stack traces",
	},
	{
		path:        "/.~~spring-boot!~/restart",
		name:        "Spring DevTools Remote Restart",
		markers:     []string{"status", "restart", "spring"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Spring Boot DevTools remote restart endpoint is accessible, potentially allowing remote application restart and configuration manipulation",
	},
	{
		path:        "/actuator/startup",
		name:        "Actuator Startup Events",
		markers:     []string{`"timeline"`, `"startupStep"`, `"spring.boot"`, `"spring.beans"`},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Boot startup events endpoint exposed, revealing application initialization details, bean creation order, and timing data",
	},
	{
		path:        "/actuator/conditions",
		name:        "Actuator Auto-Configuration Report",
		markers:     []string{`"positiveMatches"`, `"negativeMatches"`, `"unconditionalClasses"`},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Spring Boot auto-configuration conditions endpoint exposed, revealing which configurations are active and why",
	},
	{
		path:        "/actuator/scheduledtasks",
		name:        "Actuator Scheduled Tasks",
		markers:     []string{`"cron"`, `"fixedDelay"`, `"fixedRate"`, `"target"`},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Spring Boot scheduled tasks endpoint exposed, revealing internal task scheduling and method names",
	},
	{
		path:        "/actuator/caches",
		name:        "Actuator Caches",
		markers:     []string{`"cacheManagers"`, `"caches"`, `"target"`},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Spring Boot caches endpoint exposed, revealing cache manager configuration and cache names",
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Spring Debug Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Spring Debug Exposure module.
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
		ds: dedup.LazyDiskSet("spring_debug_exposure"),
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

// ScanPerRequest probes the host for exposed Spring Boot debug endpoints.
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
	randomPath := "/vigolium-spring-debug-404-" + utils.RandomString(8)

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
			Name:        fmt.Sprintf("Spring Debug: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"spring", "java", "debug", "information-disclosure"},
			Reference:   []string{"https://docs.spring.io/spring-boot/docs/current/reference/html/web.html#web.servlet.spring-mvc.error-handling"},
		},
	}
}
