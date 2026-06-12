package js_devserver_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-devserver-exposure"
	ModuleName  = "JS Dev Server Exposure"
	ModuleShort = "Detects exposed JavaScript development server endpoints (webpack HMR, Vite, Nuxt)"
)

var (
	ModuleDesc = `**What it means:** A JavaScript build tool's development server endpoint is reachable on a public host. The scanner confirmed one or more dev-only routes (Next.js/webpack/Turbopack HMR, Vite ping, webpack-dev-server SockJS, Vue CLI open-in-editor, Nuxt HMR, Remix, esbuild, or Parcel HMR) by matching the expected status code, Content-Type (such as text/event-stream), or response markers, and ruling out the 404 page and SPA catch-all shell. Dev servers are for local use only and should never run in production.

**How it's exploited:** The exposed surface tells an attacker the framework and build tooling in use and that the deployment is running in development mode, which often means verbose errors, source maps, and unminified code. Some endpoints are abusable: hot-module-replacement and SockJS channels can leak source or accept code into the bundle, and the Vue CLI open-in-editor route has historically allowed reading or opening arbitrary files on the host.

**Fix:** Build and serve the application in production mode so dev servers, HMR, and debug endpoints are disabled, or block these paths at the edge.`

	ModuleConfirmation = "Confirmed when a dev server endpoint responds with expected Content-Type or markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "nuxt", "misconfiguration", "info-disclosure", "light"}
)
