package js_framework_fingerprint

import (
	"regexp"

	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
)

// frameworkPattern defines a detection rule for a JS framework.
type frameworkPattern struct {
	framework jsframework.FrameworkType
	name      string
	// bodyPatterns are strings that must appear in the HTML body (at least one must match).
	bodyPatterns []string
	// headerName and headerValue define an HTTP header check (optional).
	headerName  string
	headerValue string
	// strong indicates this is a high-confidence signal on its own.
	strong bool
}

// patterns is the ordered list of framework detection rules.
// Earlier entries take priority. Each entry is checked independently;
// the first strong match wins.
var patterns = []frameworkPattern{
	// Next.js — strong signals
	{
		framework:   jsframework.NextJS,
		name:        "Next.js (__NEXT_DATA__)",
		bodyPatterns: []string{"__NEXT_DATA__"},
		strong:      true,
	},
	{
		framework:   jsframework.NextJS,
		name:        "Next.js (x-powered-by header)",
		headerName:  "X-Powered-By",
		headerValue: "Next.js",
		strong:      true,
	},
	{
		framework:    jsframework.NextJS,
		name:         "Next.js (_next/static)",
		bodyPatterns: []string{"/_next/static/"},
		strong:       true,
	},
	// Nuxt.js
	{
		framework:    jsframework.NuxtJS,
		name:         "Nuxt.js (__NUXT__)",
		bodyPatterns: []string{"__NUXT__", "window.__NUXT_"},
		strong:       true,
	},
	{
		framework:    jsframework.NuxtJS,
		name:         "Nuxt.js (__nuxt)",
		bodyPatterns: []string{`id="__nuxt"`},
		strong:       true,
	},
	{
		framework:    jsframework.NuxtJS,
		name:         "Nuxt.js (_nuxt/ assets)",
		bodyPatterns: []string{"/_nuxt/"},
		strong:       false,
	},
	// Angular
	{
		framework:    jsframework.Angular,
		name:         "Angular (ng-version)",
		bodyPatterns: []string{`ng-version="`},
		strong:       true,
	},
	{
		framework:    jsframework.Angular,
		name:         "Angular (app-root)",
		bodyPatterns: []string{"<app-root"},
		strong:       false,
	},
	// React CRA
	{
		framework:    jsframework.ReactCRA,
		name:         "React CRA (root + main.js)",
		bodyPatterns: []string{`id="root"`, "/static/js/main."},
		strong:       true,
	},
	// Remix
	{
		framework:    jsframework.Remix,
		name:         "Remix (__remixContext)",
		bodyPatterns: []string{"__remixContext"},
		strong:       true,
	},
	// SvelteKit
	{
		framework:    jsframework.SvelteKit,
		name:         "SvelteKit (__sveltekit)",
		bodyPatterns: []string{"__sveltekit/"},
		strong:       true,
	},
	// Gatsby
	{
		framework:    jsframework.Gatsby,
		name:         "Gatsby (___gatsby)",
		bodyPatterns: []string{"___gatsby"},
		strong:       true,
	},
	{
		framework:    jsframework.Gatsby,
		name:         "Gatsby (webpackCompilationHash)",
		bodyPatterns: []string{"___webpackCompilationHash"},
		strong:       true,
	},
}

// appRouterPattern detects Next.js App Router by looking for app/ chunk references.
var appRouterPattern = regexp.MustCompile(`/_next/static/chunks/app/`)
