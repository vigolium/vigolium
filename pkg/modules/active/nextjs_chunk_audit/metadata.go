package nextjs_chunk_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-chunk-audit"
	ModuleName  = "Next.js Static Chunk Audit"
	ModuleShort = "Fetches Next.js static JS chunks and extracts routes, domains, and embedded secrets"
)

var (
	ModuleDesc = `## Description
Enumerates Next.js application static chunks (` + "`/_next/static/chunks/*.js`" + `)
referenced by the HTML response, fetches each chunk, and analyses the content
for embedded API routes, third-party domains, and secrets. When source maps
(` + "`.js.map`" + `) are exposed alongside the chunk, those are scanned too.

Discovered relative routes are fed back into the scan pipeline so existing
Next.js scanners (data-leakage, middleware-bypass, etc.) can probe them.
Chunk URLs are also re-emitted via the scan feeder so passive secret
detection (kingfisher batch) gets coverage in addition to the inline
regex-based matcher.

## Notes
- Activates on text/html responses that look like a Next.js app
- Per-host cache prevents re-fetching chunks already seen
- Caps: 50 chunks per host, 5 MB per chunk body, 10 MB per source map
- Cross-origin domains found inside chunks are emitted as Info/Tentative intel
- Secret findings inherit High/Firm; bumped to Certain on multi-pattern matches

## References
- https://nextjs.org/docs/app/building-your-application/optimizing/static-assets
- https://github.com/GerbenJavado/LinkFinder`

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
