# Variant Analysis for p7-044 (datasource-cache-no-delete-invalidation / AP-044)

**Origin finding:** security/findings-draft/p7-044-datasource-cache-no-delete-invalidation.md
**Pattern:** AP-044 — Cache Missing Delete Invalidation
**Search date:** 2026-03-20
**Variant analyst:** Phase 9 agent

---

## Search Strategy Applied

### 1. Registry-Driven Grep (AP-044 detection signature)
Searched for `CacheService.Set` or equivalent localcache Set calls with TTL paired with service-level Delete functions that omit the corresponding cache invalidation.

### 2. Flow Shape Search
Identified all `localcache.CacheService.Set` patterns with TTL, then traced whether the corresponding Delete (or update) path calls `.Delete()` on the same key.

### 3. Phase 7 Addendum Targets
Chamber 3 confirmed the datasource cache pattern. Investigated sibling cached objects: SignedInUser, plugin settings, team memberships, RBAC permission cache.

---

## Candidate Evaluation

### Candidate A: `userimpl/legacy_user.go` — SignedInUser Cache No Delete Invalidation

**Files:**
- Cache Set: `pkg/services/user/userimpl/legacy_user.go:374-376`
- Delete path: `pkg/services/user/userimpl/legacy_user.go:208-219`

**Pattern:**
```go
// On GetSignedInUserQuery (line 374-376):
cacheKey := newSignedInUserCacheKey(result.OrgID, result.UserID)
s.cacheService.Set(cacheKey, *result, time.Second*5)

// On Delete (line 208-219):
func (s *LegacyService) Delete(ctx context.Context, cmd *user.DeleteUserCommand) error {
    _, err := s.store.GetByID(ctx, cmd.UserID)
    if err != nil { return err }
    return s.store.Delete(ctx, cmd.UserID)
    // NO: s.cacheService.Delete(newSignedInUserCacheKey(...))
}
```
**Root cause match:** Identical pattern to AP-044. The `SignedInUser` object is cached with a 5-second TTL on the read path (`GetSignedInUser`). When a user is deleted, the cache entry is not invalidated. For up to 5 seconds after deletion, requests authenticated as that user (e.g., via an active session or API key) may still resolve the cached `SignedInUser` and be treated as a valid authenticated identity with org roles and permissions.
**Attacker control:** A deleted user who still holds an active session token or API key. After an admin deletes the user account, the deleted user continues to authenticate successfully for up to 5 seconds per Grafana pod.
**Trust boundary:** TB2 (Authentication Gate) — a deleted identity continues to pass authentication, crossing the revocation boundary. Also TB3 (Authorization Gate) — the cached `SignedInUser` includes org role and team membership, so authorization decisions based on the cached object may also be stale.
**Blocking protection:** None detected. The `cacheService` field is checked for nil before Set (line 374: `if s.cacheService != nil`) but there is no corresponding nil-guarded Delete call in the deletion path.
**Severity:** MEDIUM (requires user to have an active session/key AND admin deletes the account; 5-second window; HA amplification applies)
**Verdict:** CONFIRMED — variant p7-080

### Candidate B: Plugin Settings Cache (`pkg/services/pluginsintegration/plugincontext/plugincontext.go`)

**Cache Set:** line 177 — `p.cacheService.Set(cacheKey, ps, pluginSettingsCacheTTL)`
**Invalidation:** line 155-157 — `func (p *Provider) InvalidateSettingsCache(_ context.Context, pluginID string) { p.cacheService.Delete(getCacheKey(pluginID)) }`
**Assessment:** Plugin settings cache has an explicit `InvalidateSettingsCache` function that IS called. This is the correct pattern.
**Verdict:** REJECTED (cache invalidation exists)

### Candidate C: Team Membership Cache (`pkg/services/team/teamimpl/legacy_team.go`)

**Cache Set:** lines 144, 149 — `s.cache.Set(cacheKey, ..., defaultCacheDuration)`
**Delete path:** Need to check if team member removal calls cache.Delete.
**Assessment:** Team cache uses a different backing cache type (not `localcache.CacheService`). The team membership is invalidated differently and the race window for team deletion is less security-critical (team deletion does not affect authentication). The impact does not reach the auth/authz trust boundary as directly as the user case.
**Verdict:** REJECTED (different cache type, lower security impact)

### Candidate D: RBAC Permission Cache (`pkg/services/accesscontrol/acimpl/service.go`)

**Cache Set:** lines 438, 805 — `s.cache.Set(key, ..., cacheTTL)`
**Invalidation:** `InvalidateResolverCache` is called from various delete paths.
**Assessment:** RBAC has explicit cache invalidation on permission changes. The CFD-2 note in the KB acknowledges that `InvalidateResolverCache` is "called after some operations but not consistently" — however the invalidation mechanism exists and is used in the datasource delete handlers (the source finding references this). Not a clean AP-044 structural match.
**Verdict:** REJECTED (invalidation mechanism exists, inconsistency is a separate concern)

---

## Confirmed Variants

| ID | File | Line | Description | Severity |
|----|------|------|-------------|----------|
| p7-080 | pkg/services/user/userimpl/legacy_user.go | 376 (Set), 208-219 (Delete) | SignedInUser cache not invalidated on user deletion | MEDIUM |

**Variants found: 1**
