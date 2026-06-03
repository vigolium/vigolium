package nextjs_draft_mode_exposure

import (
	"fmt"
	"strings"

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
		{path: "/api/exit-preview", desc: "Preview exit endpoint (may leak state)"},
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

			probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
			if err != nil {
				continue
			}
			probeReq = probeReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(probeReq, http.Options{NoRedirects: true})
			if err != nil {
				continue
			}

			if resp.Response() == nil {
				resp.Close()
				continue
			}

			statusCode := resp.Response().StatusCode

			// Check for draft/preview bypass cookies in Set-Cookie headers
			var foundCookies []string
			for _, cookie := range resp.Response().Header["Set-Cookie"] {
				cookieLower := strings.ToLower(cookie)
				for _, bc := range bypassCookies {
					if strings.Contains(cookieLower, bc) {
						foundCookies = append(foundCookies, bc)
					}
				}
			}

			if len(foundCookies) > 0 {
				tokenDesc := "no secret token"
				if token != "" {
					tokenDesc = fmt.Sprintf("weak token: %q", token)
				}

				results = append(results, &output.ResultEvent{
					ModuleID: ModuleID,
					Host:     host,
					URL:      target,
					Matched:  target,
					Request:  string(probeRaw),
					Response: resp.FullResponseString(),
					ExtractedResults: []string{
						fmt.Sprintf("Endpoint: %s", probe.path),
						fmt.Sprintf("Token: %s", tokenDesc),
						fmt.Sprintf("Status: %d", statusCode),
						fmt.Sprintf("Bypass cookies: %s", strings.Join(foundCookies, ", ")),
					},
					Info: output.Info{
						Name:        "Next.js Draft Mode Exposure",
						Description: fmt.Sprintf("%s activated with %s — sets bypass cookies allowing access to unpublished content", probe.desc, tokenDesc),
						Severity:    ModuleSeverity,
						Confidence:  ModuleConfidence,
						Tags:        []string{"nextjs", "draft-mode", "preview-mode", "authorization"},
						Reference: []string{
							"https://nextjs.org/docs/app/guides/draft-mode",
							"https://nextjs.org/docs/pages/building-your-application/configuring/preview-mode",
						},
					},
					Metadata: map[string]any{
						"endpoint":       probe.path,
						"weak_token":     token,
						"bypass_cookies": foundCookies,
					},
				})
				resp.Close()
				// Found a working probe for this endpoint, skip remaining tokens
				break
			}

			resp.Close()
		}

		// Stop after first confirmed finding to minimize noise
		if len(results) > 0 {
			return results, nil
		}
	}

	return results, nil
}
