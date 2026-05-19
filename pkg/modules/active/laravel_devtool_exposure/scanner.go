package laravel_devtool_exposure

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
	refs        []string
}

var probes = []probe{
	// Web Tinker - interactive PHP console
	{
		path:    "/tinker",
		name:    "Laravel Web Tinker",
		markers: []string{"tinker", "Tinker", "REPL", "Execute", "spatie"},
		sev:     severity.Critical,
		desc:    "Laravel Web Tinker (interactive PHP console) is publicly accessible, allowing arbitrary code execution",
		refs:    []string{"https://github.com/spatie/laravel-web-tinker"},
	},
	{
		path:    "/web-tinker",
		name:    "Laravel Web Tinker (alt)",
		markers: []string{"tinker", "Tinker", "REPL", "Execute", "spatie"},
		sev:     severity.Critical,
		desc:    "Laravel Web Tinker (interactive PHP console) is publicly accessible at alternate path",
		refs:    []string{"https://github.com/spatie/laravel-web-tinker"},
	},
	// Clockwork profiling
	{
		path:        "/__clockwork/latest",
		name:        "Clockwork Profiling (latest)",
		markers:     []string{"clockwork", "databaseQueries", "timelineData", "controller", "middleware"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Clockwork profiling endpoint exposed, leaking database queries, routes, timings, and request data",
		refs:        []string{"https://github.com/itsgoingd/clockwork"},
	},
	{
		path:        "/__clockwork/app",
		name:        "Clockwork App",
		markers:     []string{"clockwork", "Clockwork"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Clockwork profiling app is publicly accessible",
		refs:        []string{"https://github.com/itsgoingd/clockwork"},
	},
	{
		path:        "/_clockwork/latest",
		name:        "Clockwork Profiling (underscore)",
		markers:     []string{"clockwork", "databaseQueries", "timelineData", "controller", "middleware"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Clockwork profiling endpoint exposed at /_clockwork path",
		refs:        []string{"https://github.com/itsgoingd/clockwork"},
	},
	{
		path:        "/_clockwork/app",
		name:        "Clockwork App (underscore)",
		markers:     []string{"clockwork", "Clockwork"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Clockwork profiling app is publicly accessible at /_clockwork path",
		refs:        []string{"https://github.com/itsgoingd/clockwork"},
	},
	// Laravel Pulse monitoring
	{
		path:        "/pulse",
		name:        "Laravel Pulse",
		markers:     []string{"pulse", "Pulse", "laravel", "livewire"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Medium,
		desc:        "Laravel Pulse monitoring dashboard is publicly accessible, revealing application performance data and server metrics",
		refs:        []string{"https://laravel.com/docs/pulse"},
	},
	// Log Viewer
	{
		path:        "/log-viewer",
		name:        "Laravel Log Viewer",
		markers:     []string{"log-viewer", "Log Viewer", "LogViewer", "log viewer"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Laravel Log Viewer is publicly accessible, exposing application logs containing stack traces, secrets, and user data",
		refs:        []string{"https://github.com/opcodesio/log-viewer"},
	},
	{
		path:        "/log-viewer/api/logs",
		name:        "Laravel Log Viewer API",
		markers:     []string{"logs", "file", "level_counts", "laravel"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Laravel Log Viewer API is publicly accessible, allowing programmatic access to application logs",
		refs:        []string{"https://github.com/opcodesio/log-viewer"},
	},
}

type notFoundFingerprint struct {
	status   int
	bodyHash string
	bodyLen  int
}

// Module implements the Laravel Developer Tool Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Developer Tool Exposure module.
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
		ds: dedup.LazyDiskSet("laravel_devtool_exposure"),
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
	randomPath := "/vigolium-devtool-404-" + utils.RandomString(8)

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
			Name:        fmt.Sprintf("Laravel Dev Tool Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "devtools", "misconfiguration"},
			Reference:   p.refs,
		},
	}
}
