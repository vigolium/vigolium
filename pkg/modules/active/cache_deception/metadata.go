package cache_deception

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-deception"
	ModuleName  = "Web Cache Deception"
	ModuleShort = "Detects web cache deception via path confusion with static file extensions"
)

var (
	ModuleDesc = `**What it means:** A static-looking path mutation returned protected content with cache-hit evidence. A same-session hit is a candidate; two separate credential-free replays receiving the protected content form a finding. Unique query keys protect the normal URL.

**How it's exploited:** An attacker primes a cache with a victim's personalized response, then retrieves it without the victim's credentials.

**Fix:** Never cache authenticated dynamic paths, and key caching on the origin's real route and content type.`
	ModuleConfirmation = "Candidate on protected same-session cache hit; confirmed only when two credential-free attacker replays receive the protected cached content"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "auth-bypass", "moderate"}
)
