package django_browsable_api_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

var (
	// A real browsable renderer needs both a DRF/framework anchor and an interface
	// structure marker. A source-code mention or generic Bootstrap layout alone is
	// not enough.
	drfMarkerGroups = [][]string{
		{"django-rest-framework", "/static/rest_framework/", "rest_framework"},
		{"browsable-api", "api-breadcrumb", "content-main"},
	}
	// corroborators are generic layout tokens that DRF's template also uses but
	// which occur widely in unrelated themes/SPAs ("content-main", "api-breadcrumb").
	// They are recorded as supporting evidence only — NEVER a sole trigger. The
	// motivating false-positive class: the module re-requests the ORIGINAL page
	// with Accept: text/html, so any benign 200 HTML shell carrying a "content-main"
	// div would otherwise be reported as a Django browsable-API exposure.
	corroborators = []string{"api-breadcrumb", "content-main"}
	antiMarkers   = []string{"404 Not Found"}
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

// hasStrongMarker reports whether body carries a DRF-specific browsable-API
// anchor. It is the accept predicate shared by the probe and the catch-all decoy
// confirmation: a guaranteed-nonexistent sibling carrying the same anchor proves
// the host is a catch-all / echo shell rather than a real browsable endpoint.
func hasDRFBrowsableMarkers(body string) bool {
	_, ok := modkit.MatchAllGroups(body, drfMarkerGroups)
	return ok
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

	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
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

	// Probe 1: Re-request the original URL with Accept: text/html.
	if result := m.probeWithAcceptHTML(anonymousCtx, anonymousClient, "", "Original endpoint with Accept: text/html"); result != nil {
		return []*output.ResultEvent{result}, nil
	}

	// Probe 2: Request /api/ with Accept: text/html.
	if result := m.probeWithAcceptHTML(anonymousCtx, anonymousClient, "/api/", "DRF API root"); result != nil {
		return []*output.ResultEvent{result}, nil
	}

	return nil, nil
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

	urlx, err := ctx.URL()
	if err != nil || urlx == nil {
		return nil
	}
	probePath := overridePath
	if probePath == "" {
		probePath = urlx.Path // intentionally drop credential-bearing query strings
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil
	}

	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Accept", "text/html")
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

	for _, anti := range antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}
	contentType := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
		return nil
	}

	matchedMarkers, ok := modkit.MatchAllGroups(body, drfMarkerGroups)
	if !ok {
		return nil
	}

	// Catch-all / echo confirmation. The genuine DRF browsable API legitimately IS
	// an HTML 200 document, so content-type cannot separate it from a universal
	// catch-all / echo host that answers LITERALLY ANY path with the same 200
	// text/html shell. Compounding this, a gzip + bogus Content-Length:0 transport
	// quirk can truncate the captured body to a tail fragment (no leading
	// <!DOCTYPE/<html> head), so the "404 Not Found" anti-marker is gone while a
	// reflected "django-rest-framework" / "rest_framework" token survives in the
	// tail and forges a finding. Disprove it by probing guaranteed-nonexistent
	// siblings under this path's directory and dropping the finding when they return
	// the SAME 200 status carrying the same DRF anchor — a real browsable API serves
	// its markers only at its own route (siblings 404), so a genuine finding stands.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, probePath, body, status, 2, hasDRFBrowsableMarkers) {
		return nil
	}

	// Record any generic layout tokens as supporting evidence only.
	for _, marker := range corroborators {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}

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
			Name:        fmt.Sprintf("Django REST Framework Browsable API Observed: %s", name),
			Description: "A credential-free HTML request returned a marker-confirmed DRF browsable interface. This records interactive API attack surface; it does not prove unauthorized access to a protected operation.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"python", "django", "drf", "browsable-api", "information-disclosure"},
			Reference:   []string{"https://www.django-rest-framework.org/topics/browsable-api/"},
		},
		Metadata: map[string]any{
			"credential_free":        true,
			"authorization_bypassed": false,
			"write_action_tested":    false,
		},
	}
}
