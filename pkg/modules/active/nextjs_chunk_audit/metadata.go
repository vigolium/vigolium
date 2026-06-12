package nextjs_chunk_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-chunk-audit"
	ModuleName  = "Next.js Static Chunk Audit"
	ModuleShort = "Fetches Next.js static JS chunks and extracts routes, domains, and embedded secrets"
)

var (
	ModuleDesc = `**What it means:** This Next.js application ships static JavaScript chunks (and sometimes their source maps) that the scanner fetched and parsed, revealing internal API routes, referenced third-party domains, and in some cases hard-coded secrets baked into the bundle. The route and domain findings are informational attack-surface intel; an embedded secret is a High-severity disclosure because credentials in a public bundle are exposed to anyone who loads the site.
**How it's exploited:** An attacker downloads the same public chunks, harvests the disclosed API endpoints and back-end domains to map otherwise-hidden functionality, and feeds them into further testing. Any leaked API key, token, or secret (AWS, Google, GitHub, Stripe, Slack, or a generic key/secret assignment) can be used directly to authenticate to the corresponding service or pivot deeper.
**Fix:** Keep credentials and secrets out of client-side bundles by injecting them only on the server, rotate any key that was exposed, and disable production source maps so internal structure is not published.`

	ModuleConfirmation = "Confirmed when /_next/static/chunks/<chunk>.js returns 200 with JavaScript content and is successfully parsed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"nextjs", "javascript", "intel", "info-disclosure", "medium"}
)

const (
	MaxChunksPerHost       = 50
	MaxChunkBytes          = int64(5 * 1024 * 1024)
	MaxMapBytes            = int64(10 * 1024 * 1024)
	MaxRoutesPerHost       = 5000
	MaxDomainsPerHost      = 500
	MaxCrossOriginPerChunk = 10
)
