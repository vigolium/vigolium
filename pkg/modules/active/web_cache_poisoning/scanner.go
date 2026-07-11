package web_cache_poisoning

import (
	"fmt"
	mrand "math/rand/v2"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type cacheProbe struct {
	headerName string
	desc       string
	hostShaped bool
	value      func(string) string
}

var probes = []cacheProbe{
	{"X-Forwarded-Host", "X-Forwarded-Host controls a cached URL authority", true, func(canary string) string { return "vgn-" + canary + ".invalid" }},
	{"X-Forwarded-Scheme", "X-Forwarded-Scheme changes cached URL generation", false, func(canary string) string { return "vgnscheme-" + canary }},
	{"X-Original-URL", "X-Original-URL affects cached content", false, func(canary string) string { return "/vigolium-cache-" + canary }},
	{"X-Rewrite-URL", "X-Rewrite-URL affects cached content", false, func(canary string) string { return "/vigolium-cache-" + canary }},
	{"X-Forwarded-Port", "X-Forwarded-Port changes cached URL authority", false, func(string) string { return freshPort() }},
	{"Accept-Language", "Accept-Language affects cached content without a matching Vary key", false, func(canary string) string { return "vgn-lang-" + canary }},
}

var victimCredentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type cacheObservation struct {
	status   int
	body     string
	location string
	full     string
	ok       bool
}

// Module implements the Web Cache Poisoning active scanner.
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
		ds: dedup.LazyDiskSet("web_cache_poisoning"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest uses a unique query key so the test cannot poison the normal
// production URL. Header reflection in a cacheable response is only a candidate.
// A finding requires two clean requests from an isolated credential-free client
// to receive the poison value after the header-bearing request.
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

	for _, template := range probes {
		canary := strings.ToLower(modkit.FreshCanary())
		value := template.value(canary)

		isolatedRaw, appendErr := httpmsg.AppendURLParameter(ctx.Request().Raw(), "__vigolium_cache_probe", canary)
		if appendErr != nil {
			continue
		}
		isolatedRaw, err = stripVictimCredentials(isolatedRaw)
		if err != nil {
			continue
		}
		isolatedRaw, err = httpmsg.RemoveHeader(isolatedRaw, template.headerName)
		if err != nil {
			continue
		}

		victimClient, cloneErr := httpClient.CloneWithoutCredentials()
		if cloneErr != nil {
			continue
		}
		before := executeRaw(victimClient, ctx.Service(), isolatedRaw)
		if !before.ok {
			continue
		}
		if inBody, inLocation := probeReflected(template, value, before.body, before.location); inBody || inLocation {
			continue
		}

		poisonRaw, addErr := httpmsg.AddOrReplaceHeader(isolatedRaw, template.headerName, value)
		if addErr != nil {
			continue
		}
		poisonReq := httpmsg.NewRequestResponseRaw(poisonRaw, ctx.Service())
		poisonResp, _, executeErr := httpClient.Execute(poisonReq, http.Options{NoRedirects: true, NoClustering: true})
		if executeErr != nil || poisonResp == nil || poisonResp.Response() == nil {
			if poisonResp != nil {
				poisonResp.Close()
			}
			continue
		}

		responseObject := poisonResp.Response()
		body := poisonResp.Body().String()
		location := responseObject.Header.Get("Location")
		reflectedInBody, reflectedInLocation := probeReflected(template, value, body, location)
		if !reflectedInBody && !reflectedInLocation {
			poisonResp.Close()
			continue
		}
		cacheable, cacheEvidence := genuinelyCacheable(responseObject.Header.Get, responseObject.StatusCode, template.headerName)
		if !cacheable {
			poisonResp.Close()
			continue
		}

		poisonResponse := poisonResp.FullResponseString()
		poisonResp.Close()
		victimFirst := executeRaw(victimClient, ctx.Service(), isolatedRaw)
		victimReplay := executeRaw(victimClient, ctx.Service(), isolatedRaw)
		firstBody, firstLocation := probeReflected(template, value, victimFirst.body, victimFirst.location)
		replayBody, replayLocation := probeReflected(template, value, victimReplay.body, victimReplay.location)
		crossClientReplay := victimFirst.ok && victimReplay.ok &&
			(firstBody || firstLocation) && (replayBody || replayLocation)

		where := "response body"
		if !reflectedInBody {
			where = "Location header"
		}
		kind := output.RecordKindCandidate
		grade := output.EvidenceGradeDifferential
		severityLevel := severity.Medium
		name := fmt.Sprintf("Cache-Poisoning Candidate via %s", template.headerName)
		description := template.desc + ". The fresh value was absent from the clean baseline and reflected in an explicitly cacheable response, but a clean cross-client replay did not receive it."
		additional := []string(nil)
		if crossClientReplay {
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeImpact
			severityLevel = ModuleSeverity
			name = fmt.Sprintf("Cross-Client Cache Poisoning via %s", template.headerName)
			description = template.desc + ". Two header-free requests from an isolated credential-free client received the injected value after the poison request, confirming shared state replay."
			additional = append(additional,
				output.BuildEvidence("clean victim replay 1", string(isolatedRaw), victimFirst.full),
				output.BuildEvidence("clean victim replay 2", string(isolatedRaw), victimReplay.full),
			)
		}

		return []*output.ResultEvent{{
			ModuleID:           ModuleID,
			RecordKind:         kind,
			EvidenceGrade:      grade,
			Host:               urlx.Host,
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            string(poisonRaw),
			Response:           poisonResponse,
			AdditionalEvidence: additional,
			ExtractedResults: []string{
				fmt.Sprintf("header=%s value=%s", template.headerName, value),
				"reflected_in=" + where,
				"cacheable=" + cacheEvidence,
				fmt.Sprintf("clean_cross_client_replay=%t", crossClientReplay),
			},
			Info: output.Info{Name: name, Description: description, Severity: severityLevel, Confidence: ModuleConfidence, Tags: ModuleTags},
			Metadata: map[string]any{
				"header":              template.headerName,
				"probe_value":         value,
				"isolated_cache_key":  canary,
				"cross_client_replay": crossClientReplay,
				"normal_url_poisoned": false,
			},
		}}, nil
	}
	return nil, nil
}

func executeRaw(client *http.Requester, service *httpmsg.Service, raw []byte) cacheObservation {
	req := httpmsg.NewRequestResponseRaw(raw, service)
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return cacheObservation{}
	}
	defer resp.Close()
	return cacheObservation{
		status:   resp.Response().StatusCode,
		body:     resp.Body().String(),
		location: resp.Response().Header.Get("Location"),
		full:     resp.FullResponseString(),
		ok:       true,
	}
}

func stripVictimCredentials(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, header := range victimCredentialHeaders {
		clean, err = httpmsg.RemoveHeader(clean, header)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func probeReflected(probe cacheProbe, value, body, location string) (inBody, inLocation bool) {
	if probe.hostShaped {
		return modkit.HostReflectedAsAuthority(body, value), modkit.HostReflectedAsAuthority(location, value)
	}
	return strings.Contains(body, value), strings.Contains(location, value)
}

func freshPort() string {
	return strconv.Itoa(20000 + mrand.IntN(44536))
}

// genuinelyCacheable requires positive shared-cache evidence. Reflection plus
// absence of no-store is not sufficient.
func genuinelyCacheable(get func(string) string, status int, injectedHeader string) (bool, string) {
	if get == nil || get("Set-Cookie") != "" {
		return false, ""
	}
	cc := strings.ToLower(get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return false, ""
	}
	vary := strings.ToLower(get("Vary"))
	if strings.Contains(vary, "*") || injectedHeader != "" && headerListedInVary(vary, injectedHeader) {
		return false, ""
	}
	if cache := infra.CacheState(get); cache.Hit {
		return true, cache.Evidence
	}
	positive := strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") || hasPositiveMaxAge(cc)
	if status >= 300 && status < 400 {
		if positive {
			return true, "redirect cacheable via Cache-Control: " + get("Cache-Control")
		}
		return false, ""
	}
	if positive {
		return true, "Cache-Control: " + get("Cache-Control")
	}
	return false, ""
}

func headerListedInVary(vary, header string) bool {
	for _, token := range strings.Split(vary, ",") {
		if strings.EqualFold(strings.TrimSpace(token), strings.TrimSpace(header)) {
			return true
		}
	}
	return false
}

func hasPositiveMaxAge(cc string) bool {
	for _, directive := range strings.Split(cc, ",") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(directive, "max-age=") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(directive, "max-age=")))
		return err == nil && n > 0
	}
	return false
}
