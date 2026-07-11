package aspnet_health_exposure

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

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the ASP.NET Health Endpoint Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new ASP.NET Health Endpoint Exposure module.
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
		ds: dedup.LazyDiskSet("aspnet_health_exposure"),
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

// ScanPerRequest probes the host for exposed health and monitoring endpoints.
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

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// known endpoint mounted under a context path (e.g. /myapp/<endpoint>) is
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
			if result := m.probeEndpoint(ctx, httpClient, scanCtx, p, base+p.path, fp); result != nil {
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
	randomPath := "/vigolium-health-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
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

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
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
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
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

	// Catch-all / shell guard: a body textually equivalent to the originally
	// observed page means the app served its standard shell for this path —
	// "the same body with or without the probe".
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

	// Strip the reflected probe path before matching so a marker that is also the
	// path slug ("ready" for /health/ready) can't match on a reflected href alone.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	matched := false
	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(matchBody, marker) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
		return nil
	}

	// Wildcard-shell / path-reflecting-SPA guard (memoized, cheapest-first). A
	// brand/CMS shell (e.g. Frontify) serves one application shell for every unknown
	// path and reflects the requested slug into it ({"view":"healthchecks-ui"}), so a
	// weak slug marker self-matches with no endpoint behind it — and the reflected
	// slug + per-request CSRF token defeat the random-path 404 fingerprint above.
	// ResemblesCatchAllShell confirms the shell POSITIVELY from independent samples
	// (site root + a random directory) via body similarity; a genuinely exposed
	// dashboard is never ~equal to the homepage, so it costs no true positives.
	if modkit.ResemblesCatchAllShell(scanCtx, ctx, httpClient, body) {
		return nil
	}

	// Sub-directory catch-all guard: now that we probe under context-path prefixes,
	// drop the finding if a nonexistent sibling under the same parent returns the
	// same markers (a handler that 200s every child path).
	if modkit.SiblingServesAnyMarker(scanCtx, ctx, httpClient, probePath, p.markers) {
		return nil
	}

	// Slug-reflection guard: several markers ARE their own last path segment
	// ("healthchecks-ui" for /healthchecks-ui, "browserLink" for /_vs/browserLink), so
	// a route that echoes the requested slug self-matches them. SlugReflectionFP probes
	// a canary at the probe's base directory (the web root for these single-segment
	// paths) and drops only when the whole match is the reflected slug — the residual
	// reflecting host that the shell guard above misses (e.g. a 302 root). See its doc.
	if modkit.SlugReflectionFP(ctx, httpClient, probePath, matchedMarkers) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Health/Monitoring Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "health-check", "monitoring", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/health-checks"},
		},
	}
}
