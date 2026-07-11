package fastapi_docs_exposure

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Bare generic JSON keys
	// ("paths","info") never form a group on their own — a generic JSON catch-all
	// or status payload satisfies them; only the version-key anchor confirms a spec.
	markers [][]string
	desc    string
	spec    bool
}

var probes = []probe{
	{
		path: "/docs",
		name: "Swagger UI",
		// Swagger-UNIQUE markers only — bare "openapi" is a generic token present in
		// many JS bundles/SPA shells.
		markers: [][]string{{`id="swagger-ui"`, `id='swagger-ui'`}, {"SwaggerUIBundle", "SwaggerUIStandalonePreset"}},
		desc:    "A Swagger UI loader is reachable without credentials at a FastAPI-default path. This is an API attack-surface observation, not an authorization flaw.",
	},
	{
		path: "/redoc",
		name: "ReDoc",
		// Drop generic "openapi"; keep "redoc"/"ReDoc" (the <redoc> element survives
		// the reflected-path strip while a reflected href "/redoc" does not).
		markers: [][]string{{"<redoc", "Redoc.init"}, {"spec-url", "redoc.standalone.js"}},
		desc:    "A ReDoc loader is reachable without credentials at a FastAPI-default path. This is an API attack-surface observation, not an authorization flaw.",
	},
	{
		path: "/openapi.json",
		name: "OpenAPI Spec",
		// A real spec carries the openapi/swagger version key AND a paths/info
		// object; require both so a generic JSON body with only "info" or "paths"
		// (an arbitrary API response, a catch-all) cannot match.
		markers: [][]string{{`"openapi"`, `"swagger"`}, {`"paths"`, `"info"`}},
		desc:    "A structurally valid OpenAPI specification is reachable without credentials at a FastAPI-default path. This records documented API attack surface.",
		spec:    true,
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the FastAPI Docs Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new FastAPI Docs Exposure module.
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
		ds: dedup.LazyDiskSet("fastapi_docs_exposure"),
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

// ScanPerRequest probes the host for exposed FastAPI documentation endpoints.
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
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// FastAPI sub-app mounted under a prefix (e.g. /api/docs, /v1/openapi.json) is
	// reached, not just the root. Claim each (host, base) pair up front so a
	// fully-deduped request issues no traffic — including the soft-404 fingerprint.
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(anonymousCtx, anonymousClient)

	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeEndpoint(anonymousCtx, anonymousClient, p, base+p.path, fp); result != nil {
				return []*output.ResultEvent{result}, nil
			}
		}
	}

	return nil, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-fastapi-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

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
	probePath string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
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

	// Catch-all / SPA-shell guard: a body textually equivalent to the originally
	// observed page means the app returned its standard shell for this path —
	// "the same body with or without the probe" — not a real docs surface.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	if status != 200 {
		return nil
	}
	if p.spec && specutil.DetectSpecType([]byte(body)) == specutil.Unknown {
		return nil
	}

	// Strip the reflected probe path before matching: the /redoc marker "redoc" is
	// the path slug, so a page echoing a href/canonical "/redoc" would otherwise
	// match. The real ReDoc page still matches via its <redoc> element (no leading
	// slash), which the strip leaves intact.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	// Require every marker group (anchor + corroboration), not a single weak token,
	// then drop the finding if a nonexistent sibling under the same parent satisfies
	// the same groups — a sub-directory catch-all that 200s every child of /api/.
	// Root-level probes are already covered by the random-path 404 fingerprint above.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, matchBody, p.markers)
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("API Documentation Observed at FastAPI-Default Path: %s", p.name),
			Description: p.desc,
			Severity:    severity.Info,
			Confidence:  ModuleConfidence,
			Tags:        []string{"python", "fastapi", "exposure", "api-docs"},
			Reference:   []string{"https://fastapi.tiangolo.com/tutorial/metadata/"},
		},
		Metadata: map[string]any{
			"credential_free":        true,
			"framework_confirmed":    false,
			"authorization_bypassed": false,
			"sensitive_route_proven": false,
		},
	}
}
