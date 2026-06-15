package js_devserver_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-devserver-exposure"
	ModuleName  = "JS Dev Server Exposure"
	ModuleShort = "Detects exposed JavaScript development server endpoints (webpack HMR, Vite, Nuxt)"
)

var (
	ModuleDesc = `**What it means:** A JavaScript build tool's development server endpoint is reachable on a public host. The scanner confirmed dev-only routes (webpack/Turbopack HMR, Vite ping, SockJS, Vue CLI open-in-editor, Nuxt, Remix, esbuild, Parcel) by status, Content-Type, or markers. Dev servers should never run in production.

**How it's exploited:** The surface reveals the framework and development mode, often meaning verbose errors, source maps, and unminified code. HMR and SockJS channels can leak source, and Vue CLI open-in-editor has allowed reading host files.

**Fix:** Build and serve in production mode so dev servers are disabled, or block these paths at the edge.`

	ModuleConfirmation = "Confirmed when a dev server endpoint responds with expected Content-Type or markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "nuxt", "misconfiguration", "info-disclosure", "light"}
)
