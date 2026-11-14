package django_debug_exposure

import (
	"fmt"
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
	method      string
	body        string
	contentType string
	name        string
	desc        string
}

var debugMarkers = []string{
	"You're seeing this error because you have <code>DEBUG = True</code>",
	"Django tried these URL patterns",
	"Using the URLconf defined in",
	"Traceback (most recent call last)",
	"Request Method:",
	"Request URL:",
	"Django Version:",
}

var debugAntiMarkers = []string{
	"404 Not Found",
	"Not Found",
}

// Module implements the Django Debug Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Django Debug Exposure module.
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
		ds: dedup.LazyDiskSet("django_debug_exposure"),
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

// ScanPerRequest probes the host for Django DEBUG=True information disclosure.
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

	var results []*output.ResultEvent

	probes := []probe{
		{
			path:   "/vigolium-django-debug-" + utils.RandomString(8),
			method: "GET",
			name:   "Django Debug 404 Page",
			desc:   "Django DEBUG=True detected via debug 404 page, exposing URL patterns, settings, and internal configuration",
		},
		{
			path:        "/",
			method:      "POST",
			body:        "{",
			contentType: "application/json",
			name:        "Django Debug 500 Page",
			desc:        "Django DEBUG=True detected via debug 500 page triggered by malformed JSON, exposing stack traces and settings",
		},
	}

	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, scanCtx, p); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p probe,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), p.method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	if p.contentType != "" {
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", p.contentType)
		if err != nil {
			return nil
		}
	}
	if p.body != "" {
		modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(p.body))
		if err != nil {
			return nil
		}
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	// Status discipline against the universal catch-all / echo host. A genuine
	// Django technical debug page is rendered only on an error — a 404 URL-resolution
	// failure or a 500 unhandled exception — so it carries a 4xx/5xx status, NEVER a
	// 2xx. A catch-all / echo host instead answers LITERALLY ANY path with a 200
	// text/html shell; when a gzip + bogus Content-Length:0 transport quirk truncates
	// the captured body to a tail fragment, the leading "404 Not Found" anti-marker is
	// lost while a reflected "Request Method:" / "Django Version:" token survives in
	// the tail and would forge a finding. The surviving HTTP status still
	// discriminates — the soft-404 body fingerprint below cannot, because a REFLECTING
	// catch-all serves a distinct head per path — so drop any 2xx here.
	if status := resp.Response().StatusCode; status >= 200 && status < 300 {
		return nil
	}

	body := resp.Body().String()

	for _, anti := range debugAntiMarkers {
		if strings.Contains(body, anti) && !strings.Contains(body, "Django") {
			return nil
		}
	}

	matched := false
	var matchedMarkers []string
	for _, marker := range debugMarkers {
		if strings.Contains(body, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	// Strict drop-on-fail: reject markers that are merely part of the host's
	// catch-all / SPA shell (the same 200 body served for a random path). Genuine
	// Django debug pages are 404/500 responses whose status differs from the
	// (2xx) wildcard shell, so they are never matched by this gate.
	location := resp.Response().Header.Get("Location")
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, resp.Response().StatusCode, []byte(body), location) {
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
			Name:        fmt.Sprintf("Django Debug Exposure: %s", p.name),
			Description: p.desc,
			Severity:    severity.High,
			Confidence:  ModuleConfidence,
			Tags:        []string{"python", "django", "debug", "information-disclosure"},
			Reference:   []string{"https://docs.djangoproject.com/en/stable/ref/settings/#debug"},
		},
	}
}
