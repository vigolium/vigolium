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
	"github.com/vigolium/vigolium/pkg/spitolas/loginsig"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path        string
	method      string
	body        string
	contentType string
	name        string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. The first group is always a
	// framework/endpoint-specific anchor (e.g. "laravel-nova", `"openapi"`) that a
	// generic application shell, login wall, or i18n catch-all cannot satisfy;
	// later groups corroborate. A bare generic token ("login", "email", "admin",
	// "data") never appears as a standalone group — that single-OR-token model is
	// exactly what let a Salesforce/Visualforce login shell match "/nova/login" on
	// the word "login" alone (see scan_detect_test.go).
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
	// requireUnauth marks a probe that claims unauthenticated access to a
	// privileged surface (an admin panel). A page that renders a login form is
	// gated, not exposed, so for these probes a login wall is a false positive —
	// the separate "*/login" probes cover the "framework is installed" signal.
	requireUnauth bool
}

var probes = []probe{
	// Admin panels
	{
		path: "/nova",
		name: "Laravel Nova",
		// Anchor on Nova-unique strings only — a bare "nova" substring matches
		// "innovation"/"Casanova" and "inertia" is used by many non-Nova SPAs.
		markers:       [][]string{{"laravel-nova", "Laravel Nova", "/nova-api/", "data-nova", "window.Nova"}},
		antiMarkers:   []string{"404 Not Found"},
		sev:           severity.High,
		desc:          "Laravel Nova admin panel is accessible without authentication",
		refs:          []string{"https://nova.laravel.com/docs"},
		requireUnauth: true,
	},
	{
		path: "/nova/login",
		name: "Laravel Nova Login",
		// Require the Nova anchor AND a login-form signal. The old list let a bare
		// "login"/"email"/"password" match any login wall (the Salesforce shell FP).
		markers: [][]string{
			{"laravel-nova", "Laravel Nova", "/nova-api/", "data-nova", "window.Nova"},
			{"password", "Password", `name="email"`, "Sign in", "Log in"},
		},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Laravel Nova admin login page is publicly accessible, confirming Nova is installed",
		refs:        []string{"https://nova.laravel.com/docs"},
	},
	{
		path: "/filament",
		name: "Laravel Filament",
		// "filament"/"filament-panels" are Filament-unique; "livewire" alone is not
		// (Livewire ships in many non-Filament Laravel apps), so it is dropped.
		markers:       [][]string{{"filament-panels", "/filament/assets/", "fi-sidebar", "filament", "Filament"}},
		antiMarkers:   []string{"404 Not Found"},
		sev:           severity.High,
		desc:          "Laravel Filament admin panel is accessible without authentication",
		refs:          []string{"https://filamentphp.com/docs"},
		requireUnauth: true,
	},
	{
		path: "/filament/login",
		name: "Laravel Filament Login",
		markers: [][]string{
			{"filament-panels", "/filament/assets/", "fi-sidebar", "filament", "Filament"},
			{"password", "Password", `name="email"`, "Sign in", "Log in"},
		},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Laravel Filament admin login page is publicly accessible, confirming Filament is installed",
		refs:        []string{"https://filamentphp.com/docs"},
	},
	{
		path: "/admin",
		name: "Admin Panel (generic)",
		// A bare "admin"/"dashboard" word is hopeless for confirmation — a path-
		// routing app reflects the probe path ("/.../admin") into a <form action>/
		// breadcrumb, and the word appears verbatim on unrelated pages. So this
		// probe only fires when a NAMED Laravel admin package is identifiable
		// (Backpack, Voyager); a generic /admin that we cannot attribute to a
		// framework is left to the dedicated dashboard/exposure modules.
		markers:       [][]string{{"backpack", "Backpack", "laravel-backpack", "voyager", "Voyager", "laravel-voyager"}},
		antiMarkers:   []string{"404 Not Found"},
		sev:           severity.High,
		desc:          "Laravel admin panel (Backpack/Voyager) at /admin is accessible without authentication",
		requireUnauth: true,
	},
	{
		path: "/backoffice",
		name: "Back Office",
		// Same reasoning as /admin: require a named admin package, not the bare
		// "backoffice"/"admin" word (which is also the reflected probe path).
		markers:       [][]string{{"backpack", "Backpack", "laravel-backpack", "voyager", "Voyager", "laravel-voyager"}},
		antiMarkers:   []string{"404 Not Found"},
		sev:           severity.High,
		desc:          "Laravel back-office admin panel (Backpack/Voyager) is accessible without authentication",
		requireUnauth: true,
	},
	// API documentation
	{
		path: "/api/documentation",
		name: "Swagger API Documentation (L5)",
		// Anchor on the Swagger-UI bootstrap strings, not the bare word "swagger"
		// (which appears in unrelated docs/changelogs) or "openapi".
		markers:     [][]string{{"swagger-ui", "SwaggerUIBundle", "swagger-initializer", "Swagger UI"}},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Swagger API documentation (L5-Swagger) is publicly accessible, increasing attack surface discovery",
		refs:        []string{"https://github.com/DarkaOnLine/L5-Swagger"},
	},
	{
		path: "/docs/api",
		name: "Scramble API Documentation",
		// Require the Scramble anchor AND an API-doc signal; "api" alone is far too
		// generic to confirm anything.
		markers: [][]string{
			{"Scramble", "dedoc/scramble", "dedoc"},
			{"openapi", "swagger", "stoplight", "elements-api"},
		},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Low,
		desc:        "Scramble API documentation is publicly accessible",
		refs:        []string{"https://scramble.dedoc.co/"},
	},
	{
		path: "/openapi.json",
		name: "OpenAPI Spec (JSON)",
		// A real spec carries the version key AND a paths object — require both, and
		// drop bare "info"/"components" (generic JSON keys present in many payloads).
		markers:     [][]string{{`"openapi"`, `"swagger"`}, {`"paths"`}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "OpenAPI specification is publicly accessible, revealing all API endpoints and schemas",
	},
	{
		path:        "/openapi.yaml",
		name:        "OpenAPI Spec (YAML)",
		markers:     [][]string{{"openapi:", "swagger:"}, {"paths:"}},
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
		// Require the introspection-result shape (__schema AND a schema-type field).
		// Bare "data" matched any JSON object with a top-level data key.
		markers:     [][]string{{"__schema"}, {"queryType", "mutationType", `"types"`}},
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so an
	// admin panel mounted under a sub-directory install (e.g. /blog/admin) is
	// reached, not just the root. Claim each (host, base) pair up front so a
	// fully-deduped request issues no traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeEndpoint(ctx, httpClient, p, base+p.path, fp); result != nil {
				results = append(results, result)
			}
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
	probePath string,
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
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
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

	// Catch-all / shell guard: a body textually equivalent to the page originally
	// observed means "the same with or without the probe" — the app routed this
	// sub-path back to its standard shell (a login wall, a landing page) rather
	// than serving a distinct admin surface. The soft-404 fingerprint above only
	// catches a random *root* path; this catches a sub-path that re-renders the
	// observed page (e.g. /tai-khoan/dang-nhap/admin == /tai-khoan/dang-nhap/).
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

	// Login-wall guard: an admin-panel probe claims unauthenticated access, but a
	// page rendering a password field is gated — reaching the login form is not
	// reaching the panel. The "*/login" probes intentionally match these at low
	// severity, so only drop for the unauthenticated-access probes.
	if p.requireUnauth && loginsig.BodyLooksLikeLogin([]byte(body)) {
		return nil
	}

	// Self-reflection guard: a path-routing app echoes the probe path back into the
	// page (a <form action>, a canonical link, a breadcrumb), so the literal path
	// segment — e.g. "admin" inside action="/.../admin" — appears in the body of an
	// unrelated page and trips a weak marker. Strip the reflected probe path before
	// matching so a marker only counts when it comes from the endpoint's own
	// content, not from our own request.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	// Structural confirmation: the body must satisfy EVERY marker group (an anchor
	// group plus any corroboration), not just contain one weak token — this keeps a
	// generic login shell / API JSON from matching on "login" or "data". Then drop
	// the finding if a nonexistent sibling under the same parent satisfies the SAME
	// groups (a sub-directory catch-all that 200s every child path with one shell).
	// Root-level probes are already covered by the random-path 404 fingerprint above.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, matchBody, p.markers)
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	refs := p.refs
	if len(refs) == 0 {
		refs = []string{"https://laravel.com/docs"}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
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
