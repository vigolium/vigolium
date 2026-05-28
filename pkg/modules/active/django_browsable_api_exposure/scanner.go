package django_browsable_api_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

var (
	markers     = []string{"django-rest-framework", "rest_framework", "browsable-api", "api-breadcrumb", "content-main"}
	antiMarkers = []string{"404 Not Found"}
)

// Module implements the Django Browsable API Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Django Browsable API Exposure module.
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
		ds: dedup.LazyDiskSet("django_browsable_api_exposure"),
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

// ScanPerRequest probes the host for DRF browsable API exposure.
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

	var results []*output.ResultEvent

	// Probe 1: Re-request the original URL with Accept: text/html.
	if result := m.probeWithAcceptHTML(ctx, httpClient, "", "Original endpoint with Accept: text/html"); result != nil {
		results = append(results, result)
	}

	// Probe 2: Request /api/ with Accept: text/html.
	if result := m.probeWithAcceptHTML(ctx, httpClient, "/api/", "DRF API root"); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) probeWithAcceptHTML(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	overridePath string,
	name string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}

	if overridePath != "" {
		modifiedRaw, err = httpmsg.SetPath(modifiedRaw, overridePath)
		if err != nil {
			return nil
		}
	}

	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Accept", "text/html")
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
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "auth") {
			return nil
		}
	}

	body := resp.Body().String()

	for _, anti := range antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	matched := false
	var matchedMarkers []string
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	urlx, _ := ctx.URL()
	probePath := overridePath
	if probePath == "" {
		probePath = urlx.Path
	}
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Django Browsable API Exposure: %s", name),
			Description: "Django REST Framework browsable API is enabled in production, exposing interactive API documentation and schema details",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"python", "django", "drf", "browsable-api", "information-disclosure"},
			Reference:   []string{"https://www.django-rest-framework.org/topics/browsable-api/"},
		},
	}
}
