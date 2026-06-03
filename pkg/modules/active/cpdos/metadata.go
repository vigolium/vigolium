package cpdos

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-poisoned-dos"
	ModuleName  = "Cache-Poisoned Denial of Service (CPDoS)"
	ModuleShort = "Detects CPDoS where a shared cache stores an origin error response and replays it to other users"
)

var (
	ModuleDesc = `## Description
Detects Cache-Poisoned Denial of Service (CPDoS). When a request triggers an error at the
origin but the response is stored by a shared cache/CDN, every subsequent user of that cache
key is served the cached error instead of the real resource — a denial of service.

This module tests the two header-only variants reachable with a normal HTTP client:

- **HMO (HTTP Method Override):** a method-override header (X-HTTP-Method-Override and
  variants) carrying a benign, unsupported method token makes the origin return a cacheable
  4xx (404/405/501) without mutating any state.
- **HHO (HTTP Header Oversize):** an oversized request header the cache forwards but the
  origin rejects with a cacheable 400.

## Safety
Every probe carries a unique, single-use cache buster so the test only ever affects the
scanner's own cache key — never a shared resource. The HMO probe uses a non-mutating method
token, so it cannot delete or modify data. The destructive HMC (meta-character) variant,
which requires raw control bytes on the wire, is intentionally not attempted.

## Impact
- Denial of service: legitimate users receive a cached error page for the affected resource.

## References
- https://cpdos.org/
- https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
- CWE-444 / cache key handling`

	ModuleConfirmation = "Confirmed only after a multi-round with-payload/without-payload differential on fresh cache keys: each round a clean control request must return the non-error baseline, a separate payload request must produce a cacheable error of a different status, and a clean replay on the poisoned key must be served that cached error (cache HIT). All rounds must pass, and only on endpoints proven cacheable by a baseline 200 hit"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cache-poisoning", "cpdos", "dos", "moderate"}
)
