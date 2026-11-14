package js_framework_fingerprint

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the JS framework fingerprinting passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JS Framework Fingerprint module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("js_framework_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to fingerprint the JS framework.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	// Only process HTML responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host

	// Dedup by host — only fingerprint once
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	// Check each pattern
	for _, pat := range patterns {
		matched := false

		// Check header-based pattern
		if pat.headerName != "" {
			for _, hdr := range ctx.Response().Headers() {
				if strings.EqualFold(hdr.Name, pat.headerName) && strings.Contains(hdr.Value, pat.headerValue) {
					matched = true
					break
				}
			}
		}

		// Check body-based patterns
		if !matched && len(pat.bodyPatterns) > 0 {
			allMatch := true
			for _, bp := range pat.bodyPatterns {
				if !strings.Contains(body, bp) {
					allMatch = false
					break
				}
			}
			matched = allMatch
		}

		if !matched || !pat.strong {
			if !matched {
				continue
			}
			// Weak signal — skip unless no strong signal found later
			continue
		}

		// Strong match — build fingerprint
		fp := &jsframework.HostFingerprint{
			Framework: pat.framework,
			ExtraData: map[string]string{
				"detection": pat.name,
			},
		}

		// Next.js-specific: extract buildId and detect App Router
		if pat.framework == jsframework.NextJS {
			if m := jsframework.BuildIDRegex.FindStringSubmatch(body); len(m) > 1 {
				fp.BuildID = m[1]
			}
			fp.AppRouter = appRouterPattern.MatchString(body)
		}

		// Store in shared cache
		jsframework.Set(host, fp)

		scanCtx.MarkTech(host, string(pat.framework))
		if pat.framework == jsframework.NuxtJS {
			scanCtx.MarkTech(host, "nuxt") // alias used by recon + metaframework_fingerprint
		}
		// "javascript" is descriptive. "nodejs" is a backend stack tag, so it is
		// marked only on evidence the page was rendered by a Node server: a
		// static export (Gatsby, CRA, next export) runs on any backend, and
		// marking nodejs there excluded every other backend's modules.
		scanCtx.MarkTech(host, "javascript")
		if hasSSREvidence(ctx.Response(), pat.framework) {
			scanCtx.MarkTech(host, "nodejs")
		}
		// Every framework this module recognises client-side-routes the app, so the
		// host serves one JS-bootstrapped shell for many routes. Recorded as a
		// descriptive tag for recon output; deliberately
		// NOT in modkit.techTagCategories, which would auto-gate any module tagged
		// "spa" on a detection only this module and metaframework_fingerprint
		// publish — a gate armed before it has a reader, and half-published.
		scanCtx.MarkTech(host, "spa")

		routerType := ""
		if pat.framework == jsframework.NextJS {
			if fp.AppRouter {
				routerType = " (App Router)"
			} else {
				routerType = " (Pages Router)"
			}
		}

		// Claim the host only now that it matched: a host whose
		// first response showed nothing stays open for later responses.
		if diskSet != nil && !diskSet.ClaimOnMatch(host) {
			return nil, nil
		}
		return []*output.ResultEvent{
			{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Framework: %s%s", pat.framework, routerType),
					fmt.Sprintf("Detection: %s", pat.name),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("JS Framework Detected: %s", pat.framework),
					Description: fmt.Sprintf("Identified %s%s framework via %s", pat.framework, routerType, pat.name),
					Severity:    severity.Info,
					Confidence:  severity.Certain,
					Tags:        []string{"framework", "fingerprint", string(pat.framework)},
				},
				Metadata: map[string]any{
					"framework": string(pat.framework),
					"buildId":   fp.BuildID,
					"appRouter": fp.AppRouter,
				},
			},
		}, nil
	}

	return nil, nil
}

// hasSSREvidence reports whether resp shows it was rendered by a Node server
// running framework: a Node/framework X-Powered-By, or a framework's
// server-only response header. Remix always renders on a server (its
// __remixContext is the server's hydration payload), so its detection is
// itself the evidence. Static-only frameworks (Gatsby, CRA) never are.
func hasSSREvidence(resp *httpmsg.HttpResponse, framework jsframework.FrameworkType) bool {
	if resp == nil {
		return false
	}
	switch framework {
	case jsframework.Remix:
		return true
	case jsframework.NextJS, jsframework.NuxtJS, jsframework.SvelteKit:
	default:
		return false
	}
	for _, h := range resp.Headers() {
		name := strings.ToLower(h.Name)
		switch {
		case name == "x-powered-by":
			v := strings.ToLower(h.Value)
			if strings.Contains(v, "next.js") || strings.Contains(v, "nuxt") || strings.Contains(v, "express") {
				return true
			}
		case strings.HasPrefix(name, "x-nextjs-"), name == "x-sveltekit-page":
			return true
		}
	}
	return false
}
