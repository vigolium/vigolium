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

// decoyRounds is how many same-directory negative-control probes the catch-all
// disproof issues per candidate. A universal catch-all / echo host that answers
// EVERY path with the same 200 shell (often reflecting the request URI, and —
// under a gzip + bogus Content-Length: 0 transport quirk — captured as only a
// truncated TAIL fragment) trips at least one round and the candidate is dropped.
// Two rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
}

// accepts reports whether body satisfies this probe's marker requirement (any
// single marker hit). Centralized so the primary match and the catch-all decoy
// disproof apply the EXACT same predicate — the decoy sibling must be judged by
// the same rule the candidate was, so a truncated-tail echo / catch-all server
// that serves the marker for every path is disproved.
func (p probe) accepts(body string) (matched []string, ok bool) {
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

var probes = []probe{
	// Web Tinker - interactive PHP console
	{
		path:    "/tinker",
		name:    "Laravel Web Tinker",
		markers: []string{"tinker", "Tinker", "web-tinker", "spatie"},
		sev:     severity.Critical,
		desc:    "Laravel Web Tinker (interactive PHP console) is publicly accessible, allowing arbitrary code execution",
		refs:    []string{"https://github.com/spatie/laravel-web-tinker"},
	},
	{
		path:    "/web-tinker",
		name:    "Laravel Web Tinker (alt)",
		markers: []string{"tinker", "Tinker", "web-tinker", "spatie"},
		sev:     severity.Critical,
		desc:    "Laravel Web Tinker (interactive PHP console) is publicly accessible at alternate path",
		refs:    []string{"https://github.com/spatie/laravel-web-tinker"},
	},
	// Clockwork profiling
	{
		path:        "/__clockwork/latest",
		name:        "Clockwork Profiling (latest)",
		markers:     []string{"clockwork", "databaseQueries", "timelineData"},
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
		markers:     []string{"clockwork", "databaseQueries", "timelineData"},
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
		markers:     []string{"Laravel Pulse", "pulse-dashboard"},
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
		markers:     []string{"level_counts", "log-viewer", "\"folders\":"},
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
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
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

	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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

	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
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

	// Strip the reflected probe path (and any echoed request body) before matching:
	// the /tinker and /web-tinker markers ("tinker", "web-tinker") are the path slug
	// itself, so a page echoing the requested path (a <form action>, an href, a
	// JSON route name) — the truncated-tail echo server — would forge a Critical RCE
	// finding. After the strip a marker only counts when it comes from the
	// endpoint's own content. The original body is kept for stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	matchedMarkers, ok := p.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof (truncation-proof): the reflected-path strip
	// above kills an echoed-slug marker, but a universal catch-all shell that
	// carries a weak tool name as a CONSTANT word for every path (a "clockwork" /
	// "log-viewer" reference in a bundle name, surviving in the truncated tail)
	// slips past it. Probe guaranteed-nonexistent siblings sharing this path's
	// directory: if a random same-shape path returns the same status and ALSO
	// satisfies this probe's predicate, the host serves this content for ANY path,
	// so the match proves nothing. A genuinely exposed dev tool has no such sibling
	// (the decoy 404s), so this costs no true positives, and it is robust to the
	// body-truncation quirk because the decoy is run through the same predicate.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := p.accepts(b)
		return sibOK
	}) {
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
			Name:        fmt.Sprintf("Laravel Dev Tool Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "devtools", "misconfiguration"},
			Reference:   p.refs,
		},
	}
}
