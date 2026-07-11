package wp_misconfig

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
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("wp_misconfig"),
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

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// sub-directory WordPress install (e.g. /blog/wp-login.php) is reached, not
	// just the root. Claim each (host, base) pair up front so a fully-deduped
	// request issues no traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, probe := range wpProbes {
			if result := m.probeFile(ctx, httpClient, scanCtx, probe, base+probe.path, fp); result != nil {
				results = append(results, result)
			}
		}
	}
	return results, nil
}

// wpCronEmptyIsSpecific reports whether a 200-with-empty-body response is
// specific to wp-cron.php rather than a blanket behaviour the host exhibits for
// any .php path (PHP disabled, a catch-all returning a blank 200, etc.). It
// fetches a random nonexistent .php path; if that ALSO returns a 200 with an
// empty/whitespace body, the empty-200 signal is meaningless and wp-cron must
// not be reported. Fails OPEN on an inconclusive transient error.
func (m *Module) wpCronEmptyIsSpecific(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	randomPath := "/vgm-wpcron-" + utils.RandomString(8) + ".php"
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return true
	}
	raw, err = httpmsg.SetPath(raw, randomPath)
	if err != nil {
		return true
	}
	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return true
	}
	defer resp.Close()
	if resp.Response() == nil {
		return true
	}
	if resp.Response().StatusCode == 200 && len(strings.TrimSpace(resp.Body().String())) == 0 {
		return false // blanket empty-200 for any .php path → not specific to wp-cron
	}
	return true
}

func (m *Module) fingerprint404(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *notFoundFingerprint {
	randomPath := "/vgm-wp-404-" + utils.RandomString(8)
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}
	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
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

func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	probe wpProbe,
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
	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
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
		if strings.Contains(strings.ToLower(location), "login") {
			return nil
		}
	}

	body := resp.Body().String()

	// Check against 404 fingerprint
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

	// Check anti-markers
	for _, anti := range probe.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Special case: wp-cron.php returns 200 with empty body when functional.
	// Strict drop-on-fail: only report when the empty-200 is SPECIFIC to
	// wp-cron.php (a random .php path does not also return an empty 200), so a
	// host that blanket-returns blank 200s for any .php path is not flagged.
	if probe.path == "/wp-cron.php" {
		if len(strings.TrimSpace(body)) == 0 && m.wpCronEmptyIsSpecific(ctx, httpClient) {
			urlx, _ := ctx.URL()
			targetURL := urlx.Scheme + "://" + urlx.Host + probePath
			return &output.ResultEvent{
				URL:     targetURL,
				Matched: targetURL,
				Request: string(modifiedRaw),
				// The empty-200 response IS the proof (specific to wp-cron.php).
				// resp is still open here (deferred Close), so capture the real
				// response rather than letting the executor backfill a baseline.
				Response: resp.FullResponseString(),
				Info: output.Info{
					Name:        probe.name,
					Description: probe.desc,
					Severity:    probe.sev,
					Confidence:  ModuleConfidence,
					Tags:        []string{"wordpress", "misconfiguration"},
				},
			}
		}
		return nil
	}

	// Require at least one marker match
	if len(probe.markers) == 0 {
		return nil
	}

	var matchedMarkers []string
	for _, marker := range probe.markers {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}

	// Soft-404 / SPA-shell gate: reject a marker match that is just the host's
	// wildcard shell (same 200 body served for a random path).
	location := resp.Response().Header.Get("Location")
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, status, []byte(body), location) {
		return nil
	}

	// Sub-directory catch-all guard: ConfirmNotSoft404 above compares against a
	// host-wide random path, which cannot see a catch-all scoped to a sub-directory
	// prefix (now that we probe under context paths). Drop the finding if a
	// nonexistent sibling under the same parent returns the same markers.
	if modkit.SiblingServesAnyMarker(scanCtx, ctx, httpClient, probePath, probe.markers) {
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
			Name:        probe.name,
			Description: probe.desc,
			Severity:    probe.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"wordpress", "misconfiguration"},
		},
	}
}
