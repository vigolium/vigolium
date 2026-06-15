package cpdos

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-poisoned-dos"
	ModuleName  = "Cache-Poisoned Denial of Service (CPDoS)"
	ModuleShort = "Detects CPDoS where a shared cache stores an origin error response and replays it to other users"
)

var (
	ModuleDesc = `**What it means:** A shared cache or CDN in front of this endpoint stores an origin error and replays it to everyone, so one crafted request denies the resource to all users. Two header-only variants force a cacheable error: HMO (method-override header) and HHO (oversized header).

**How it's exploited:** An attacker sends one poisoning request to the real cache key; the cache stores the error and serves it to all later visitors until it expires.

**Fix:** Configure the cache to never store errors, strip headers before the cache key, and align origin and cache on request size and method handling.`

	ModuleConfirmation = "Confirmed only after a multi-round with-payload/without-payload differential on fresh cache keys: each round a clean control request must return the non-error baseline, a separate payload request must produce a cacheable error of a different status, and a clean replay on the poisoned key must be served that cached error (cache HIT). All rounds must pass, and only on endpoints proven cacheable by a baseline 200 hit"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cache-poisoning", "cpdos", "dos", "moderate"}
)
