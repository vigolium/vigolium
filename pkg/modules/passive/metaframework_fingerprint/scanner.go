package metaframework_fingerprint

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// frameworkPattern defines a detection rule for a meta-framework.
type frameworkPattern struct {
	framework string
	name      string
	// bodyPatterns are strings that must ALL appear in the HTML body.
	bodyPatterns []string
	// headerName and headerValue define an HTTP header check (optional).
	headerName  string
	headerValue string
	// strong indicates this is a high-confidence signal on its own.
	strong bool
}

var patterns = []frameworkPattern{
	// Remix — strong signals
	{
		framework:    "Remix",
		name:         "Remix (__remixContext)",
		bodyPatterns: []string{"__remixContext"},
		strong:       true,
	},
	{
		framework:    "Remix",
		name:         "Remix (__remixManifest)",
		bodyPatterns: []string{"__remixManifest"},
		strong:       true,
	},
	{
		framework:    "Remix",
		name:         "Remix (data-remix)",
		bodyPatterns: []string{"data-remix"},
		strong:       true,
	},

	// Astro — strong signals
	{
		framework:    "Astro",
		name:         "Astro (astro-island)",
		bodyPatterns: []string{"<astro-island"},
		strong:       true,
	},
	{
		framework:    "Astro",
		name:         "Astro (astro-slot)",
		bodyPatterns: []string{"<astro-slot"},
		strong:       true,
	},
	{
		framework:    "Astro",
		name:         "Astro (_astro/ assets)",
		bodyPatterns: []string{"/_astro/"},
		strong:       true,
	},
	{
		framework:   "Astro",
		name:        "Astro (x-astro header)",
		headerName:  "X-Astro",
		headerValue: "",
		strong:      true,
	},

	// SvelteKit — strong signals
	{
		framework:    "SvelteKit",
		name:         "SvelteKit (__sveltekit)",
		bodyPatterns: []string{"__sveltekit/"},
		strong:       true,
	},
	{
		framework:    "SvelteKit",
		name:         "SvelteKit (data-sveltekit)",
		bodyPatterns: []string{"data-sveltekit-"},
		strong:       true,
	},
	{
		framework:    "SvelteKit",
		name:         "SvelteKit (svelte-announcer)",
		bodyPatterns: []string{"svelte-announcer"},
		strong:       true,
	},

	// SolidStart — strong signals
	{
		framework:    "SolidStart",
		name:         "SolidStart (_server)",
		bodyPatterns: []string{"_server/", "solid-"},
		strong:       true,
	},
	{
		framework:    "SolidStart",
		name:         "SolidStart (data-hk)",
		bodyPatterns: []string{"data-hk="},
		strong:       false,
	},

	// Qwik — strong signals
	{
		framework:    "Qwik",
		name:         "Qwik (q:container)",
		bodyPatterns: []string{"q:container"},
		strong:       true,
	},
	{
		framework:    "Qwik",
		name:         "Qwik (qwik-loader)",
		bodyPatterns: []string{"qwikloader"},
		strong:       true,
	},
	{
		framework:    "Qwik",
		name:         "Qwik (q:base)",
		bodyPatterns: []string{"q:base="},
		strong:       true,
	},
}

// Module implements the Meta-Framework Fingerprint passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Meta-Framework Fingerprint module.
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
		ds: dedup.LazyDiskSet("passive_metaframework_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to fingerprint meta-frameworks.
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
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	for _, pat := range patterns {
		matched := false

		// Check header-based pattern
		if pat.headerName != "" {
			for _, hdr := range ctx.Response().Headers() {
				if strings.EqualFold(hdr.Name, pat.headerName) {
					if pat.headerValue == "" || strings.Contains(hdr.Value, pat.headerValue) {
						matched = true
						break
					}
				}
			}
		}

		// Check body-based patterns (all must match)
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
			continue
		}

		scanCtx.MarkTech(host, strings.ToLower(pat.framework))
		scanCtx.MarkTech(host, "javascript")
		scanCtx.MarkTech(host, "nodejs")

		return []*output.ResultEvent{
			{
				ModuleID: ModuleID,
				Host:     host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Framework: %s", pat.framework),
					fmt.Sprintf("Detection: %s", pat.name),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("Meta-Framework Detected: %s", pat.framework),
					Description: fmt.Sprintf("Identified %s framework via %s", pat.framework, pat.name),
					Severity:    severity.Info,
					Confidence:  severity.Certain,
					Tags:        []string{"framework", "fingerprint", strings.ToLower(pat.framework)},
				},
				Metadata: map[string]any{
					"framework": pat.framework,
				},
			},
		}, nil
	}

	return nil, nil
}
