package swagger_exposure

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// probePaths are common Swagger/OpenAPI/Redoc UI and spec routes. The first
// positive hit per host is enough to report the exposure, so this list favours
// the most prevalent paths rather than exhaustiveness (api-spec-ingest owns the
// wide spec-discovery surface).
var probePaths = []string{
	// Interactive documentation UIs
	"swagger-ui.html",
	"swagger-ui/",
	"swagger/index.html",
	"swagger/",
	"swagger",
	"api/swagger-ui.html",
	"api/swagger/index.html",
	"api/docs",
	"docs",
	"redoc",
	"redoc/",
	"api-docs",
	// Machine-readable specifications
	"openapi.json",
	"swagger.json",
	"openapi.yaml",
	"swagger.yaml",
	"v2/api-docs",
	"v3/api-docs",
	"api/openapi.json",
	"api/swagger.json",
	"api-docs/swagger.json",
	"swagger-resources",
	".well-known/openapi.json",
}

// uiMarkerGroups identify real documentation loaders. Every group must match:
// one broad product token is only a mention, bundle, or reflected route slug.
var uiMarkerGroups = []struct {
	name   string
	groups [][]string
}{
	{name: "swagger-ui", groups: [][]string{
		{`id="swagger-ui"`, `id='swagger-ui'`},
		{"swaggeruibundle", "swagger-ui-bundle.js", "swaggeruistandalonepreset"},
	}},
	{name: "redoc", groups: [][]string{
		{"<redoc", "redoc.init"},
		{"spec-url", "redoc.standalone.js"},
	}},
	{name: "rapidoc", groups: [][]string{
		{"<rapi-doc", "rapidoc"},
		{"spec-url", "specurl"},
	}},
	{name: "stoplight-elements", groups: [][]string{
		{"<elements-api", "stoplight-elements"},
		{"apidescriptionurl", "api-description-url"},
	}},
}

// Module is the active Swagger/OpenAPI exposure detection scanner.
type Module struct {
	modkit.BaseActiveModule
	hostDS dedup.Lazy[dedup.DiskSet] // per-host dedup: probe & report once per host
}

// New creates a new Swagger Exposure module.
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
		hostDS: dedup.LazyDiskSet("swagger_exposure_host"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess requires a request with a valid URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

// IncludesBaseCanProcess returns false because we override CanProcess entirely.
func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(service, cleanRaw),
		ctx.Response(),
	)

	urlx, err := anonymousCtx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// docs UI/spec mounted under an API gateway or service prefix (e.g.
	// /api/swagger-ui.html, /orders/v3/api-docs) is reached, not just the root.
	// Dedup per (host, base) — IsSeen is test-and-set — so each base is probed
	// once per host across all requests.
	hostKey := urlx.Scheme + "|" + urlx.Host
	var hostDS *dedup.DiskSet
	if scanCtx != nil {
		hostDS = m.hostDS.Get(scanCtx.DedupMgr())
	}
	bases := modkit.UnclaimedBasePaths(hostDS, hostKey, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	// Build a base GET request from the observed request.
	var rawHTTP []byte
	if anonymousCtx.Request().Method() != "GET" {
		rawHTTP, err = httpmsg.SetMethod(anonymousCtx.Request().Raw(), "GET")
		if err != nil {
			return nil, nil
		}
	} else {
		rawHTTP = anonymousCtx.Request().Raw()
	}

	baseURL := urlx.Scheme + "://" + urlx.Host

	for _, base := range bases {
		for _, path := range probePaths {
			probePath := base + "/" + path

			modifiedRaw, err := httpmsg.SetPath(rawHTTP, probePath)
			if err != nil {
				continue
			}

			// SetPath produces well-formed raw, so wrap directly instead
			// of re-parsing on this hot path.
			fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, service)

			resp, _, err := anonymousClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
			if err != nil {
				continue
			}
			if resp.Response() == nil || infra.IsBlockedResponse(resp) {
				resp.Close()
				continue
			}

			statusCode := resp.Response().StatusCode
			// Copy the body before Close: resp.Body().Bytes() aliases the pooled
			// *bytes.Buffer that Close() returns to a process-global pool, so reading
			// `body` afterwards (DetectSpecType, looksLikeSwaggerUI) races with a
			// concurrent request reusing that buffer. (Same fix as idor_detection.)
			body := append([]byte(nil), resp.Body().Bytes()...)
			fullResponse := resp.FullResponseString()
			resp.Close()

			if statusCode != 200 || len(body) < 32 {
				continue
			}

			var kind string
			switch {
			case specutil.DetectSpecType(body) != specutil.Unknown:
				// Structural spec detection (JSON/YAML shape) — a reflected HTML
				// slug cannot satisfy it, so no slug-reflection guard is needed.
				kind = "OpenAPI/Swagger specification document"
			default:
				marker, ok := swaggerUIMarker(body)
				if !ok {
					continue
				}
				// A path-reflecting SPA/CMS shell serves one page for every route and
				// reflects the requested slug into it, so a "docs UI" body carrying a UI
				// marker that IS its own path slug (/redoc, /swagger-ui/) is that shell,
				// not a real docs page. Run the memoized wildcard-shell guard first
				// (site root + random directory, body similarity), then fall back to the
				// per-candidate slug-reflection canary probe for the residual reflecting
				// host the shell guard misses (e.g. a 302 root). Both cost no true
				// positives — a genuine Swagger/Redoc UI is never ~equal to the homepage,
				// and SlugReflectionFP requires an exact 200 canary reflection.
				if modkit.ResemblesCatchAllShell(scanCtx, anonymousCtx, anonymousClient, string(body)) {
					continue
				}
				if modkit.SlugReflectionFP(anonymousCtx, anonymousClient, probePath, []string{marker}) {
					continue
				}
				kind = "interactive API documentation UI"
			}

			// First confirmed exposure is sufficient — stop probing this host.
			hit := baseURL + probePath
			return []*output.ResultEvent{
				{
					ModuleID:      ModuleID,
					RecordKind:    output.RecordKindObservation,
					EvidenceGrade: output.EvidenceGradeObservation,
					URL:           hit,
					Matched:       hit,
					Request:       string(modifiedRaw),
					Response:      fullResponse,
					Info: output.Info{
						Name: "API Documentation Observed",
						Description: "A credential-free request reached a " + kind + " at " + probePath +
							". This is security-relevant reconnaissance; it does not prove that any documented operation is sensitive or unauthorized.",
						Severity:   ModuleSeverity,
						Confidence: ModuleConfidence,
						Tags:       ModuleTags,
					},
					Metadata: map[string]any{
						"credential_free":        true,
						"documentation_kind":     kind,
						"authorization_bypassed": false,
						"sensitive_route_proven": false,
					},
				},
			}, nil
		}
	}

	return nil, nil
}

// looksLikeSwaggerUI reports whether the response body looks like a rendered
// Swagger/Redoc/RapiDoc documentation page.
func looksLikeSwaggerUI(body []byte) bool {
	_, ok := swaggerUIMarker(body)
	return ok
}

// swaggerUIMarker returns the first documentation product whose complete loader
// marker groups are present. A single title, bundle name, or route slug is not a
// UI and cannot satisfy this predicate.
func swaggerUIMarker(body []byte) (string, bool) {
	n := len(body)
	if n > 32<<10 {
		n = 32 << 10
	}
	s := strings.ToLower(string(body[:n]))
	for _, product := range uiMarkerGroups {
		matched := true
		for _, group := range product.groups {
			groupMatched := false
			for _, marker := range group {
				if strings.Contains(s, marker) {
					groupMatched = true
					break
				}
			}
			if !groupMatched {
				matched = false
				break
			}
		}
		if matched {
			return product.name, true
		}
	}
	return "", false
}
