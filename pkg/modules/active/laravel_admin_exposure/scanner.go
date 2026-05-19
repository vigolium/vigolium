package laravel_admin_exposure

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
	method      string
	body        string
	contentType string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
}

var probes = []probe{
	// Admin panels
	{
		path:        "/nova",
		name:        "Laravel Nova",
		markers:     []string{"Nova", "nova", "laravel-nova", "inertia"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Laravel Nova admin panel is accessible without authentication",
		refs:        []string{"https://nova.laravel.com/docs"},
	},
	{
		path:        "/nova/login",
		name:        "Laravel Nova Login",
		markers:     []string{"Nova", "nova", "login", "email", "password"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Laravel Nova admin login page is publicly accessible, confirming Nova is installed",
		refs:        []string{"https://nova.laravel.com/docs"},
	},
	{
		path:        "/filament",
		name:        "Laravel Filament",
		markers:     []string{"filament", "Filament", "filament-panels", "livewire"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Laravel Filament admin panel is accessible without authentication",
		refs:        []string{"https://filamentphp.com/docs"},
	},
	{
		path:        "/filament/login",
		name:        "Laravel Filament Login",
		markers:     []string{"filament", "Filament", "login", "email"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Laravel Filament admin login page is publicly accessible, confirming Filament is installed",
		refs:        []string{"https://filamentphp.com/docs"},
	},
	{
		path:        "/admin",
		name:        "Admin Panel (generic)",
		markers:     []string{"dashboard", "Dashboard", "admin", "Admin", "backpack", "Backpack", "voyager", "Voyager"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Admin panel at /admin is accessible without authentication",
	},
	{
		path:        "/backoffice",
		name:        "Back Office",
		markers:     []string{"dashboard", "Dashboard", "admin", "backoffice"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.High,
		desc:        "Back office panel is accessible without authentication",
	},
	// API documentation
	{
		path:        "/api/documentation",
		name:        "Swagger API Documentation (L5)",
		markers:     []string{"swagger", "Swagger", "openapi", "api-docs"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Swagger API documentation (L5-Swagger) is publicly accessible, increasing attack surface discovery",
		refs:        []string{"https://github.com/DarkaOnLine/L5-Swagger"},
	},
	{
		path:        "/docs/api",
		name:        "Scramble API Documentation",
		markers:     []string{"scramble", "Scramble", "openapi", "api"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Scramble API documentation is publicly accessible",
		refs:        []string{"https://scramble.dedoc.co/"},
	},
	{
		path:        "/openapi.json",
		name:        "OpenAPI Spec (JSON)",
		markers:     []string{"openapi", "paths", "info", "components"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "OpenAPI specification is publicly accessible, revealing all API endpoints and schemas",
	},
	{
		path:        "/openapi.yaml",
		name:        "OpenAPI Spec (YAML)",
		markers:     []string{"openapi:", "paths:", "info:"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "OpenAPI specification (YAML) is publicly accessible, revealing all API endpoints and schemas",
	},
	// GraphQL introspection
	{
		path:        "/graphql",
		method:      "POST",
		body:        `{"query":"{ __schema { queryType { name } } }"}`,
		contentType: "application/json",
		name:        "GraphQL Introspection",
		markers:     []string{"__schema", "queryType", "data"},
		antiMarkers: []string{"introspection", "disabled", "not allowed"},
		sev:         severity.Medium,
		desc:        "GraphQL endpoint with introspection enabled, revealing the full API schema and all available operations",
		refs:        []string{"https://lighthouse-php.com/master/security/authentication.html"},
	},
}

type notFoundFingerprint struct {
	status   int
	bodyHash string
	bodyLen  int
}

// Module implements the Laravel Admin Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Admin Exposure module.
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
		ds: dedup.LazyDiskSet("laravel_admin_exposure"),
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
	randomPath := "/vigolium-admin-404-" + utils.RandomString(8)

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

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	method := p.method
	if method == "" {
		method = "GET"
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
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
			strings.Contains(strings.ToLower(location), "user") ||
			strings.Contains(strings.ToLower(location), "auth") {
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

	refs := p.refs
	if len(refs) == 0 {
		refs = []string{"https://laravel.com/docs"}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponse().String(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Laravel Admin Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "admin", "exposure"},
			Reference:   refs,
		},
	}
}
