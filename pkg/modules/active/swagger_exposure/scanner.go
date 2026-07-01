package swagger_exposure

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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

// uiMarkers identify a rendered API documentation UI page. Kept specific to
// avoid false positives on generic HTML.
var uiMarkers = []string{
	"swagger-ui",
	"swaggeruibundle",
	"redoc",
	"rapidoc",
	"stoplight-elements",
	"swagger ui",
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
	urlx, err := ctx.URL()
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
	hostDS := m.hostDS.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(hostDS, hostKey, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	// Build a base GET request from the observed request.
	var rawHTTP []byte
	if ctx.Request().Method() != "GET" {
		rawHTTP, err = httpmsg.SetMethod(ctx.Request().Raw(), "GET")
		if err != nil {
			return nil, nil
		}
	} else {
		rawHTTP = ctx.Request().Raw()
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
			fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
			if err != nil {
				continue
			}

			statusCode := resp.Response().StatusCode
			// Copy the body before Close: resp.Body().Bytes() aliases the pooled
			// *bytes.Buffer that Close() returns to a process-global pool, so reading
			// `body` afterwards (DetectSpecType, looksLikeSwaggerUI) races with a
			// concurrent request reusing that buffer. (Same fix as idor_detection.)
			body := append([]byte(nil), resp.Body().Bytes()...)
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
				// Slug-reflection guard: a probe like /<dir>/redoc whose only signal
				// is the UI marker "redoc" self-matches when a content route echoes
				// the requested slug into the page. Confirm the marker is not merely
				// the reflected path segment before reporting.
				if modkit.SlugReflectionFP(ctx, httpClient, probePath, []string{marker}) {
					continue
				}
				kind = "interactive API documentation UI"
			}

			// First confirmed exposure is sufficient — stop probing this host.
			hit := baseURL + probePath
			return []*output.ResultEvent{
				{
					URL:     hit,
					Matched: hit,
					Info: output.Info{
						Name: ModuleName,
						Description: "Publicly accessible " + kind + " exposed at " + probePath +
							". This discloses the API attack surface (endpoints, parameters, " +
							"authentication scheme) to unauthenticated users.",
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

// swaggerUIMarker returns the first UI marker found in body (and true), or ""
// (and false) if none match. The caller needs the specific marker so it can apply
// the slug-reflection guard: a probe like /<dir>/redoc whose only signal is the
// marker "redoc" self-matches when a content route echoes the requested slug.
func swaggerUIMarker(body []byte) (string, bool) {
	n := len(body)
	if n > 8192 {
		n = 8192
	}
	s := strings.ToLower(string(body[:n]))
	for _, marker := range uiMarkers {
		if strings.Contains(s, marker) {
			return marker, true
		}
	}
	return "", false
}
