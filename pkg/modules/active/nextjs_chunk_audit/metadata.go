package nextjs_chunk_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-chunk-audit"
	ModuleName  = "Next.js Static Chunk Audit"
	ModuleShort = "Fetches Next.js static JS chunks and extracts routes, domains, and embedded secrets"
)

var (
	ModuleDesc = `**What it means:** This Next.js app ships static JavaScript chunks (and sometimes source maps) that, when parsed, reveal internal API routes, third-party domains, and sometimes hard-coded secrets. Route and domain findings are informational intel; an embedded secret is a High-severity disclosure.

**How it's exploited:** An attacker downloads the same public chunks and harvests disclosed API endpoints and domains to map hidden functionality. Any leaked key or token (AWS, GitHub, Stripe) authenticates to that service or pivots deeper.

**Fix:** Keep credentials out of client-side bundles by injecting them only server-side, rotate exposed keys, and disable production source maps.`

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
