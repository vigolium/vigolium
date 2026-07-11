package cache_data_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-data-leak"
	ModuleName  = "Cache Data Leak"
	ModuleShort = "Detects cache and static generation patterns that may leak user data"
)

var (
	ModuleDesc = `**What it means:** A served source-like JS/TS file contains cache/static-generation syntax and authentication-related syntax. Client build artifacts are excluded, but the detector still establishes only file-level proximity, not connected dataflow.

**How it's exploited:** A real issue requires authenticated data to enter a shared cache key and another principal to receive it. This module performs neither call-graph tracing nor cross-user replay, so results remain candidates.

**Fix:** Mark session-dependent routes dynamic and uncacheable (force-dynamic, no-store, revalidate 0) and scope cache keys to the user.`

	ModuleConfirmation = "Candidate when source-like code contains cache and auth patterns after artifact filtering; confirmation requires connected flow and cross-user replay"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "cache-poisoning", "light"}
)
