package nextjs_chunk_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-chunk-audit"
	ModuleName  = "Next.js Static Chunk Audit"
	ModuleShort = "Fetches Next.js static JS chunks and extracts routes, domains, and embedded secrets"
)

var (
	ModuleDesc = `**What it means:** Anonymous Next.js chunks and source maps contain routes, third-party domains, client identifiers, or private-credential-shaped values. Routes, domains, and intentionally publishable identifiers are observations; unvalidated private formats are candidates.

**How it's exploited:** Attackers download the same chunks for reconnaissance. GitHub, Slack, or secret-key-shaped values may enable access if live, but AWS access-key IDs, Google API keys, and Stripe publishable keys are not secrets by themselves.

**Fix:** Keep private credentials server-side, validate and rotate candidate secrets, restrict publishable keys at the provider, and disable unnecessary production source maps.`

	ModuleConfirmation = "Anonymous chunk must return non-HTML 200 content; private token formats remain candidates until provider validation, while public client identifiers remain observations"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"nextjs", "javascript", "intel", "info-disclosure", "medium", "light"}
)

const (
	MaxChunksPerHost       = 50
	MaxChunkBytes          = int64(5 * 1024 * 1024)
	MaxMapBytes            = int64(10 * 1024 * 1024)
	MaxRoutesPerHost       = 5000
	MaxDomainsPerHost      = 500
	MaxCrossOriginPerChunk = 10
)
