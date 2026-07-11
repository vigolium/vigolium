package nextjs_draft_mode_exposure

import (
	"fmt"
	stdhttp "net/http"
	stdurl "net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
)

// draftProbe defines a single draft/preview endpoint probe.
type draftProbe struct {
	path string
	desc string
}

var (
	// Endpoints to probe, both with and without weak tokens.
	draftPaths = []draftProbe{
		{path: "/api/draft", desc: "App Router draft mode endpoint"},
		{path: "/api/preview", desc: "Pages Router preview mode endpoint"},
		{path: "/api/enable-preview", desc: "Custom preview mode endpoint"},
		{path: "/api/draft/enable", desc: "Nested draft mode endpoint"},
	}

	// Weak/common tokens to attempt.
	weakTokens = []string{
		"",
		"secret",
		"preview",
		"draft",
		"test",
		"1234",
	}

	// Cookies that indicate draft/preview mode was activated.
	bypassCookies = []string{
		"__prerender_bypass",
		"__next_preview_data",
	}
)

// Module implements the Next.js Draft Mode exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Draft Mode Exposure module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("nextjs_draft_mode_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerHost probes draft/preview endpoints once per host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Check if this is a Next.js host
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	target := ctx.Target()
	var results []*output.ResultEvent

	for _, probe := range draftPaths {
		for _, token := range weakTokens {
			probePath := probe.path
			if token != "" {
				probePath = fmt.Sprintf("%s?secret=%s", probe.path, token)
			}

			probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probePath)
			if err != nil {
				continue
			}
			probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

			// probeRaw is internally built (well-formed), so wrap directly
			// instead of re-parsing on this hot path.
			probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

			resp, _, err := httpClient.Execute(probeReq, http.Options{NoRedirects: true, NoClustering: true})
			if err != nil {
				continue
			}

			if resp.Response() == nil {
				resp.Close()
				continue
			}

			statusCode := resp.Response().StatusCode
			location := resp.Response().Header.Get("Location")
			previewCookie, active := activePreviewCookie(resp.Response().Cookies())

			if active {
				tokenDesc := "no secret token"
				if token != "" {
					tokenDesc = fmt.Sprintf("weak token: %q", token)
				}

				confirmed, verification := verifyDraftContent(ctx, httpClient, previewCookie.name, previewCookie.value, location)
				kind := output.RecordKindCandidate
				grade := output.EvidenceGradeCandidate
				name := "Next.js Draft Mode Activation Candidate"
				description := fmt.Sprintf("%s returned a live %s cookie with %s. Cookie issuance proves that the endpoint attempted to activate preview state, but no stable draft-content differential was observed on follow-up requests.", probe.desc, previewCookie.name, tokenDesc)
				if confirmed {
					kind = output.RecordKindFinding
					grade = output.EvidenceGradeBypass
					name = "Next.js Draft Mode Exposure"
					description = fmt.Sprintf("%s activated with %s and issued a live %s cookie. Repeated follow-up requests with that cookie returned stable content distinct from cookie-free controls, confirming access to alternate draft/preview content.", probe.desc, tokenDesc, previewCookie.name)
				}

				event := &output.ResultEvent{
					ModuleID:           ModuleID,
					Host:               host,
					URL:                target,
					Matched:            target,
					Request:            string(probeRaw),
					Response:           resp.FullResponseString(),
					AdditionalEvidence: verification,
					RecordKind:         kind,
					EvidenceGrade:      grade,
					ExtractedResults: []string{
						fmt.Sprintf("Endpoint: %s", probe.path),
						fmt.Sprintf("Token: %s", tokenDesc),
						fmt.Sprintf("Status: %d", statusCode),
						fmt.Sprintf("Active bypass cookie: %s", previewCookie.name),
						fmt.Sprintf("Draft content differential: %t", confirmed),
					},
					Info: output.Info{
						Name:        name,
						Description: description,
						Severity:    ModuleSeverity,
						Confidence:  ModuleConfidence,
						Tags:        []string{"nextjs", "draft-mode", "preview-mode", "authorization"},
						Reference: []string{
							"https://nextjs.org/docs/app/guides/draft-mode",
							"https://nextjs.org/docs/pages/building-your-application/configuring/preview-mode",
						},
					},
					Metadata: map[string]any{
						"endpoint":             probe.path,
						"weak_token":           token,
						"bypass_cookie":        previewCookie.name,
						"content_differential": confirmed,
					},
				}
				resp.Close()
				if confirmed {
					return []*output.ResultEvent{event}, nil
				}
				results = append(results, event)
				// A live activation candidate is enough for this endpoint; try other
				// endpoint shapes for a stronger content differential.
				break
			}

			resp.Close()
		}

	}

	if len(results) > 0 {
		return results[:1], nil
	}
	return nil, nil
}

type previewCookie struct {
	name  string
	value string
}

func activePreviewCookie(cookies []*stdhttp.Cookie) (previewCookie, bool) {
	now := time.Now()
	for _, cookie := range cookies {
		if cookie == nil || !isBypassCookie(cookie.Name) {
			continue
		}
		value := strings.TrimSpace(cookie.Value)
		deletedValue := strings.EqualFold(value, "deleted") || strings.EqualFold(value, "remove")
		if value == "" || deletedValue || cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && !cookie.Expires.After(now)) {
			continue
		}
		return previewCookie{name: cookie.Name, value: value}, true
	}
	return previewCookie{}, false
}

func isBypassCookie(name string) bool {
	for _, candidate := range bypassCookies {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

type contentProbe struct {
	status   int
	body     string
	request  string
	response string
}

func verifyDraftContent(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	cookieName, cookieValue, location string,
) (bool, []string) {
	raw := verificationRequestRaw(ctx, location)
	withoutCookie, err := httpmsg.RemoveHeader(raw, "Cookie")
	if err != nil {
		return false, nil
	}
	withCookie, err := httpmsg.SetCookie(withoutCookie, cookieName, cookieValue)
	if err != nil {
		return false, nil
	}

	anon1 := fetchContentProbe(ctx, client, withoutCookie)
	anon2 := fetchContentProbe(ctx, client, withoutCookie)
	draft1 := fetchContentProbe(ctx, client, withCookie)
	draft2 := fetchContentProbe(ctx, client, withCookie)
	if anon1 == nil || anon2 == nil || draft1 == nil || draft2 == nil {
		return false, nil
	}
	evidence := []string{
		anon1.request, anon1.response,
		draft1.request, draft1.response,
	}
	if anon1.status < 200 || anon1.status >= 300 || draft1.status < 200 || draft1.status >= 300 ||
		anon1.status != anon2.status || draft1.status != draft2.status {
		return false, evidence
	}
	if !modkit.BodiesSimilar(anon1.body, anon2.body) || !modkit.BodiesSimilar(draft1.body, draft2.body) {
		return false, evidence
	}
	if modkit.BodiesSimilar(anon1.body, draft1.body) {
		return false, evidence
	}
	return true, evidence
}

func verificationRequestRaw(ctx *httpmsg.HttpRequestResponse, location string) []byte {
	raw := append([]byte(nil), ctx.Request().Raw()...)
	if strings.TrimSpace(location) == "" {
		return raw
	}
	parsed, err := stdurl.Parse(location)
	if err != nil {
		return raw
	}
	if parsed.IsAbs() {
		urlx, err := ctx.URL()
		if err != nil || !strings.EqualFold(parsed.Host, urlx.Host) {
			return raw
		}
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	modified, err := httpmsg.SetPath(raw, path)
	if err != nil {
		return raw
	}
	return modified
}

func fetchContentProbe(ctx *httpmsg.HttpRequestResponse, client *http.Requester, raw []byte) *contentProbe {
	request := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(request, http.Options{NoRedirects: true, NoClustering: true, RawRequest: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	if resp.Response() == nil {
		return nil
	}
	return &contentProbe{
		status:   resp.Response().StatusCode,
		body:     resp.Body().String(),
		request:  string(raw),
		response: resp.FullResponseString(),
	}
}
