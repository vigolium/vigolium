package cpdos

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-poisoned-dos"
	ModuleName  = "Cache-Poisoned Denial of Service (CPDoS)"
	ModuleShort = "Detects CPDoS where a shared cache stores an origin error response and replays it to other users"
)

var (
	ModuleDesc = `**What it means:** This endpoint sits behind a shared cache or CDN that will store an origin error response and replay it to every other user who requests the same resource. A single crafted request can therefore turn a working page into a cached error for everyone, causing denial of service. The scanner confirmed two header-only variants: HMO, where a method-override header (such as X-HTTP-Method-Override) carrying an unsupported method makes the origin return a cacheable 4xx; and HHO, where an oversized request header the cache forwards but the origin rejects with a cacheable 400.

**How it's exploited:** An attacker sends one request to the real cache key with the poisoning header. The cache stores the resulting error and serves it to all subsequent legitimate visitors until the entry expires, denying them access to that resource without ever touching the origin again.

**Fix:** Configure the cache to never store error responses, normalize or strip request headers before cache-key computation, and align the origin and cache on request-size and method-override handling.`

	ModuleConfirmation = "Confirmed only after a multi-round with-payload/without-payload differential on fresh cache keys: each round a clean control request must return the non-error baseline, a separate payload request must produce a cacheable error of a different status, and a clean replay on the poisoned key must be served that cached error (cache HIT). All rounds must pass, and only on endpoints proven cacheable by a baseline 200 hit"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cache-poisoning", "cpdos", "dos", "moderate"}
)
