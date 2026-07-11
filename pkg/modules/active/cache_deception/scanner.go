package cache_deception

import (
	"fmt"
	"math"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type pathConfusionTechnique struct {
	suffix string
	desc   string
}

var techniques = []pathConfusionTechnique{
	{".css", "Static extension append (.css)"},
	{".js", "Static extension append (.js)"},
	{".png", "Static extension append (.png)"},
	{".svg", "Static extension append (.svg)"},
	{"/..%2f..%2fstatic.css", "Path separator confusion (double dot-segment encoded)"},
	{"%2f.css", "Path separator confusion (encoded slash + extension)"},
	{"/nonexistent.css", "Trailing static path segment"},
}

var authHeadersToStrip = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type observedResponse struct {
	status int
	body   string
	full   string
	cache  infra.CacheInfo
	ok     bool
}

// Module implements the Web Cache Deception active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("cache_deception"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest first proves that the baseline is protected by comparing it
// with an isolated credential-free request. A same-session cache hit is only a
// candidate. A finding requires two anonymous confused-path requests to receive
// the protected baseline with cache-hit evidence.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil || ctx.Request() == nil || !strings.EqualFold(ctx.Request().Method(), "GET") {
		return nil, nil
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	baseline, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, nil
	}
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 || baseline.BodyLen < 200 {
		return nil, nil
	}

	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	if wildcard.MatchesBody(baseline.StatusCode, baseline.Response.Body()) {
		return nil, nil
	}

	attackerClient, cloneErr := httpClient.CloneWithoutCredentials()
	if cloneErr != nil {
		return nil, nil
	}
	cleanOriginalRaw, stripErr := stripCredentials(ctx.Request().Raw())
	if stripErr != nil {
		return nil, nil
	}
	anonymousOriginal := fetchResponse(attackerClient, ctx.Service(), cleanOriginalRaw)
	if !anonymousOriginal.ok || responseMatchesBaseline(anonymousOriginal, baseline.StatusCode, baseline.BodyLen, baseline.Response.BodyToString()) {
		// If a credential-free request already receives the same content, there is
		// no authenticated resource for cache deception to disclose.
		return nil, nil
	}

	originalPath, pathErr := httpmsg.GetPath(ctx.Request().Raw())
	if pathErr != nil {
		return nil, nil
	}
	baselineReqStr := string(ctx.Request().Raw())
	baselineRespStr := string(baseline.Response.Raw())

	for _, technique := range techniques {
		confusedPath := originalPath + technique.suffix
		authRaw, setErr := httpmsg.SetPath(ctx.Request().Raw(), confusedPath)
		if setErr != nil {
			continue
		}
		probeID := strings.ToLower(modkit.FreshCanary())
		authRaw, setErr = httpmsg.AppendURLParameter(authRaw, "__vigolium_cache_probe", probeID)
		if setErr != nil {
			continue
		}

		prime := fetchResponse(httpClient, ctx.Service(), authRaw)
		authedReplay := fetchResponse(httpClient, ctx.Service(), authRaw)
		if !prime.ok || !authedReplay.ok ||
			!responseMatchesBaseline(authedReplay, baseline.StatusCode, baseline.BodyLen, baseline.Response.BodyToString()) ||
			!authedReplay.cache.Hit {
			continue
		}

		attackerRaw, stripErr := stripCredentials(authRaw)
		if stripErr != nil {
			continue
		}
		attackerFirst := fetchResponse(attackerClient, ctx.Service(), attackerRaw)
		attackerReplay := fetchResponse(attackerClient, ctx.Service(), attackerRaw)
		firstMatch := responseMatchesBaseline(attackerFirst, baseline.StatusCode, baseline.BodyLen, baseline.Response.BodyToString())
		replayMatch := responseMatchesBaseline(attackerReplay, baseline.StatusCode, baseline.BodyLen, baseline.Response.BodyToString())
		crossClientLeak := firstMatch && replayMatch && (attackerFirst.cache.Hit || attackerReplay.cache.Hit)

		kind := output.RecordKindCandidate
		grade := output.EvidenceGradeDifferential
		sev := severity.Low
		name := "Authenticated Cache-Hit Candidate: " + technique.desc
		description := fmt.Sprintf("The isolated confused path returned the protected baseline with %s to the authenticated client, but two credential-free attacker requests did not reproduce the protected content. This may be a private or per-user cache.", authedReplay.cache.Evidence)
		additional := []string{
			output.BuildEvidence("protected baseline", baselineReqStr, baselineRespStr),
			output.BuildEvidence("authenticated cache prime", string(authRaw), prime.full),
		}
		if crossClientLeak {
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeImpact
			sev = ModuleSeverity
			name = "Cross-Client Web Cache Deception: " + technique.desc
			description = fmt.Sprintf("Two credential-free requests to the isolated confused path received the protected authenticated baseline, with shared-cache evidence (%s). This directly confirms cross-client disclosure.", firstNonEmptyCacheEvidence(attackerFirst.cache, attackerReplay.cache, authedReplay.cache))
			additional = append(additional,
				output.BuildEvidence("anonymous attacker replay 1", string(attackerRaw), attackerFirst.full),
				output.BuildEvidence("anonymous attacker replay 2", string(attackerRaw), attackerReplay.full),
			)
		}

		return []*output.ResultEvent{{
			ModuleID:           ModuleID,
			RecordKind:         kind,
			EvidenceGrade:      grade,
			Host:               urlx.Host,
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            string(authRaw),
			Response:           authedReplay.full,
			AdditionalEvidence: additional,
			ExtractedResults: []string{
				"technique=" + technique.desc,
				"confused_path=" + confusedPath,
				"authenticated_cache_evidence=" + authedReplay.cache.Evidence,
				fmt.Sprintf("anonymous_baseline_status=%d cross_client_replay=%t", anonymousOriginal.status, crossClientLeak),
			},
			Info: output.Info{Name: name, Description: description, Severity: sev, Confidence: ModuleConfidence, Tags: ModuleTags},
			Metadata: map[string]any{
				"protected_baseline":      true,
				"cross_client_replay":     crossClientLeak,
				"isolated_cache_key":      probeID,
				"normal_url_cache_primed": false,
			},
		}}, nil
	}
	return nil, nil
}

func fetchResponse(client *http.Requester, service *httpmsg.Service, raw []byte) observedResponse {
	req := httpmsg.NewRequestResponseRaw(raw, service)
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return observedResponse{}
	}
	defer resp.Close()
	return observedResponse{
		status: resp.Response().StatusCode,
		body:   resp.Body().String(),
		full:   resp.FullResponseString(),
		cache:  infra.CacheState(resp.Response().Header.Get),
		ok:     true,
	}
}

func responseMatchesBaseline(observation observedResponse, baselineStatus, baselineLength int, baselineBody string) bool {
	if !observation.ok || observation.status < 200 || observation.status >= 300 || observation.status != baselineStatus || len(observation.body) == 0 {
		return false
	}
	if math.Abs(float64(len(observation.body)-baselineLength))/float64(baselineLength) > 0.10 {
		return false
	}
	return modkit.BodiesSimilar(baselineBody, observation.body)
}

func stripCredentials(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, header := range authHeadersToStrip {
		clean, err = httpmsg.RemoveHeader(clean, header)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func firstNonEmptyCacheEvidence(caches ...infra.CacheInfo) string {
	for _, cache := range caches {
		if cache.Evidence != "" {
			return cache.Evidence
		}
	}
	return "cache hit"
}
