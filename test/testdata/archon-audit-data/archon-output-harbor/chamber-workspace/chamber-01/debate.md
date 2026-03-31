# Review Chamber: chamber-01

Cluster: Authentication & Identity — Authentication chain vulnerabilities, OIDC/LDAP security, session management, internal secret handling
DFD Slices: DFD-3 (OIDC Auth Flow), DFD-4 (V2 Token Auth), CFD-2 (Security Context Generator Chain)
NNN Range: p8-001 to p8-019
Started: 2026-03-27T10:00:00Z
Status: CLOSED

---

## Pre-Seeded Hypotheses (from Deep Probe)

The following hypotheses were validated during Deep Probe (Phase 7) and are pre-seeded for this chamber:

- **H-00a (PH-01/PH-06)**: Admin DB auth forced in OIDC mode + no distributed lockout = unlimited brute force
- **H-00b (PH-04)**: OIDC admin group injection bypasses GroupFilter
- **H-00c (PH-07)**: Full OIDC refresh token stored in unauthenticated Redis session
- **H-00d (PH-19)**: OIDC onboard flow trusts session data for admin account creation via Redis
- **H-00e (PH-25)**: Nginx does not strip Harbor-Secret header enabling external secret injection
- **H-00f (PH-26)**: LDAP null bind authentication bypass

Spec gap findings relevant to this chamber:
- SGap-1 (HIGH): LDAP RFC 4511 null bind (overlaps PH-26)
- SGap-2 (MEDIUM): OIDC nonce not bound
- SGap-3 (MEDIUM): ID token expiry skipped
- SGap-7 (MEDIUM): OIDC onboard username injection

---

## Round 1 -- Ideation

**[SYNTHESIZER]**: Ideator, generate hypotheses for this threat cluster. The pre-seeded hypotheses above (H-00a through H-00f) are already validated from Deep Probe -- do NOT regenerate them. Instead, focus on:

1. Attack chains that combine pre-validated findings (e.g., PH-07 + PH-19 Redis chain, PH-01 + PH-06 brute force chain)
2. Spec gap exploitation paths (SGap-2 nonce, SGap-3 expiry skip, SGap-7 username injection)
3. Cross-mode auth confusion attacks (OIDC+LDAP+DB mode switching)
4. Lateral thinking: session fixation, token reuse across auth modes, race conditions in auth chain
5. The NEEDS-DEEPER items from probe: PH-08 (auth proxy prefix), PH-16 (dual parse), PH-22 (FixEmptySubIss)
6. Robot account brute force (PH-15/PH-21) as a standalone finding

Maximum 7 new hypotheses. Write to debate.md.

**[IDEATOR]**: Here are 7 new hypotheses focused on chains, cross-mode combinations, and lateral thinking attacks that the systematic probe did not attempt.

---

**H-01: OIDC Nonce Replay + Userinfo Failure = Forged Session Hijack**
- Attack class: State Machine (Mode 7)
- Cross-modes: Mode 1 (Chaining SGap-2 + PH-13)
- Chain: (1) Attacker captures victim's OIDC callback URL with auth code and state. (2) Attacker replays callback. (3) Because nonce is not bound to session (SGap-2), the replayed callback succeeds if state matches. (4) If userinfo endpoint is unavailable (PH-13), subject cross-validation is skipped, and groups/admin status come solely from the ID token. Combined: stolen callback URL + transient userinfo failure = session as victim with unvalidated claims.
- Preconditions: Network position to intercept OIDC callback (e.g., open redirect, shared browser history, referrer leak). OIDC provider userinfo endpoint intermittently unavailable.
- Target asset: Victim's Harbor session with potentially elevated group/admin claims
- Entry point: `GET /c/oidc/callback?code=X&state=Y`
- Sink: `OIDCController.Callback` -> session creation with unvalidated claims
- Creativity signal: Neither SGap-2 nor PH-13 alone is high severity; chaining nonce replay with userinfo bypass creates account takeover from two medium-severity issues. Solo agent would evaluate each independently.
- Deep-Probe-Reference: PH-13 from auth-chain, SGap-2 from spec-gap-report

**H-02: Auth Mode Switch Race — LDAP-to-OIDC Transition Creates Ghost Admin**
- Attack class: Race Condition / TOCTOU (Mode 3)
- Cross-modes: Mode 5 (Trust Boundary), Mode 7 (State Machine)
- Chain: (1) Harbor is in LDAP mode. Attacker authenticates as LDAP user, gets session. (2) Admin switches auth mode to OIDC. (3) Attacker's existing session (Redis-backed) still contains LDAP security context. (4) On next API call, `idToken.Generate` fails (no OIDC token in session), but `session.Generate` succeeds because cookie+Redis session still valid. (5) Session security context references LDAP groups that may have been mapped to Harbor admin. (6) The LDAP group membership is never re-verified against the new OIDC provider.
- Preconditions: Attacker has active LDAP session when auth mode changes. LDAP group gave attacker admin role.
- Target asset: Persistent admin access after auth mode migration
- Entry point: Any API endpoint with existing session cookie
- Sink: `session.Generate` -> `local.NewSecurityContext` with stale LDAP-derived admin role
- Creativity signal: Auth mode transitions are a state machine edge case. The session persistence across mode changes creates a trust boundary confusion where LDAP-derived privileges survive into OIDC mode. No probe tested mode-switching scenarios.

**H-03: Redis Session Poisoning + LDAP Null Bind = Zero-Credential Admin**
- Attack class: Vulnerability Chaining (Mode 1)
- Cross-modes: Mode 4 (Second-Order), Mode 5 (Trust Boundary)
- Chain: (1) Attacker exploits unauthenticated Redis (TB-4, common default). (2) Writes crafted session with `oidc_user_info` containing `admin_group_member: true` (PH-19 technique). (3) Alternatively, if LDAP mode: exploits null bind (PH-26) to authenticate as any LDAP user, then uses Redis access to elevate that session to admin. (4) The chain combines network-adjacent Redis access with either OIDC onboard trust or LDAP null bind for zero-credential system admin creation.
- Preconditions: Network access to Redis (default: no auth, port 6379 on internal network). Harbor in LDAP or OIDC mode.
- Target asset: System admin account creation without knowing any credentials
- Entry point: Redis TCP connection + `POST /c/oidc/onboard` or `POST /c/login`
- Sink: `OIDCController.Onboard` -> `ctluser.Ctl.OnboardOIDCUser` with admin flag, or `session.Generate` with poisoned security context
- Creativity signal: Chains three independently-validated findings (Redis no-auth + null bind + onboard trust) into a complete zero-credential admin takeover. Each finding alone is medium; together they are critical. Deep probe validated each component separately but did not chain them.
- Deep-Probe-Reference: PH-07 from auth-chain, PH-19 from auth-chain, PH-26 from auth-chain

**H-04: FixEmptySubIss Startup Injection — SQL Injection to Admin via Unsigned JWT**
- Attack class: Second-Order / Stored (Mode 4)
- Cross-modes: Mode 1 (Chaining), Mode 6 (Parser Differential)
- Chain: (1) Attacker achieves SQL write to `oidc_user.token` column (via any SQL injection path — DFD-1 has 44 confirmed fmt.Sprintf->SQL flows). (2) Writes a crafted JWT with `sub` and `iss` claims set to attacker-controlled values. (3) On next Harbor core restart, `FixEmptySubIss` (PH-22) parses ALL `oidc_user.token` entries WITHOUT signature verification. (4) The crafted JWT's `sub`/`iss` are written back to `oidc_user.subiss` column. (5) Attacker can now authenticate via OIDC with those crafted `sub`/`iss` values, binding to the victim's Harbor account.
- Preconditions: SQL injection capability (write to oidc_user table). Harbor core restart (maintenance window, pod recycling).
- Target asset: Arbitrary Harbor account takeover by rebinding OIDC identity
- Entry point: SQL injection sink -> `oidc_user.token` column
- Sink: `FixEmptySubIss` at startup -> unsigned JWT parse -> `subiss` column update -> OIDC identity binding
- Creativity signal: Combines a SQL injection (Phase 4 structural finding) with a startup routine that parses JWTs without verification (PH-22 NEEDS-DEEPER). The temporal separation (write at time T, exploit at restart time T+N) makes this invisible to single-pass SAST. Solo agent would not connect SQL injection to startup JWT parsing.
- Deep-Probe-Reference: PH-22 from auth-chain

**H-05: V2 Token Scope Escalation via Project Name Collision After Delete-Recreate**
- Attack class: State Machine (Mode 7)
- Cross-modes: Mode 3 (TOCTOU)
- Chain: (1) User A has push access to project "foo". Obtains V2 bearer token scoped to `repository:foo/image:push,pull`. (2) Project "foo" is deleted. (3) User B creates new project "foo" (name reuse). (4) User A's stale token: `tokenIssuedAfterProjectCreation` check was patched (89e1c4baa, confirmed SOUND for standard paths). BUT: PH-03 shows `/v2/` and `/_catalog` skip the timestamp check (`ProjectName == ""`). (5) User A uses stale token on `/v2/` to confirm authentication, then attempts push to `foo/image` — the scope claim `repository:foo/image:push` in the JWT matches the new project's namespace.
- Preconditions: Attacker had legitimate token for deleted project. Project name reused by different owner. Token not yet expired (configurable, default 30min).
- Target asset: Push access to newly-created project owned by different user
- Entry point: `GET /v2/` with stale bearer token, then `PUT /v2/foo/image/manifests/latest`
- Sink: `v2auth` middleware -> `v2Token` security context with stale scope claims
- Creativity signal: The probe validated the timestamp check is SOUND for standard paths but also found it is bypassed for `/v2/` and `/_catalog`. The question is whether a token authenticated at `/v2/` can then be used for subsequent scoped operations on the recreated project within the same HTTP session or connection. This is a state machine attack on the token lifecycle that requires understanding the interaction between discovery endpoint bypass and scoped resource access.
- Deep-Probe-Reference: PH-03 from auth-chain

**H-06: Auth Proxy Header Injection via OIDC Username Claim**
- Attack class: Trust Boundary Confusion (Mode 5)
- Cross-modes: Mode 6 (Parser Differential), Mode 2 (Business Logic)
- Chain: (1) Harbor configured with auth-proxy mode. Auth proxy sets `X-Auth-User` header. (2) Attacker registers with OIDC provider using username that matches auth proxy header format (e.g., `tokenreview$admin`). (3) If Harbor mode is later switched to auth-proxy, or if both mechanisms coexist in the security chain (CFD-2 shows auth-proxy checked at priority 5, before basic auth at 7): the `authProxy.Generate` middleware processes the injected header. (4) The `tokenreview$` prefix (PH-08 NEEDS-DEEPER) may or may not provide adequate separation. If the prefix check is only on the Harbor side but the auth proxy passes raw headers, an attacker controlling the upstream proxy response can inject arbitrary usernames.
- Preconditions: Auth-proxy mode enabled. Attacker can influence upstream proxy responses or inject headers past Nginx (PH-25 shows Nginx does not strip custom headers).
- Target asset: Authentication as arbitrary user via header injection
- Entry point: HTTP request with crafted `X-Auth-User` or equivalent auth proxy header
- Sink: `authProxy.Generate` -> `authproxy.VerifyToken` -> user context creation
- Creativity signal: Combines the auth chain priority ordering (CFD-2) with header injection possibility (PH-25 shows Nginx lacks header stripping). The auth proxy trust model assumes headers come from a trusted proxy, but if Nginx does not strip them for external requests, any external attacker can inject auth proxy headers. This is a trust boundary confusion between Nginx, the auth proxy, and Harbor core.
- Deep-Probe-Reference: PH-08 from auth-chain, PH-25 from auth-chain

**H-07: OIDC CLI Token Timing Oracle for User Enumeration**
- Attack class: Business Logic Abuse (Mode 2)
- Cross-modes: Mode 8 (Supply Chain — go-oidc library behavior)
- Chain: (1) OIDC CLI authentication path (`oidcCli.Generate`) verifies a user-supplied OIDC token. (2) The verification path first looks up the user in Harbor DB by username, then verifies the OIDC secret. (3) If the user exists, `oidc.VerifySecret` is called which involves AES decryption + token verification (expensive). If the user does not exist, an early return occurs. (4) The timing difference between "user not found" (fast) and "user found, secret invalid" (slow due to crypto operations) creates an oracle for enumerating which usernames have OIDC accounts in Harbor. (5) Combined with PH-15/PH-21 (no brute force protection on robot accounts), the enumerated usernames guide targeted attacks.
- Preconditions: Network access to Harbor API. OIDC auth mode configured.
- Target asset: Username enumeration of OIDC-linked Harbor accounts
- Entry point: Any API endpoint with `Authorization: Basic <user:oidc_secret>` triggering `oidcCli.Generate`
- Sink: `oidc.VerifySecret` timing differential
- Creativity signal: Timing oracles in auth chains are well-known but the specific interaction between Harbor's DB lookup + go-oidc AES decrypt creates a measurable delta. The KB notes "timing attacks" as a historical pattern (Pattern 3). This is a reconnaissance enabler that chains with brute force findings.

---

## Round 1 -- Advocacy (Defense Briefs)

**[ADVOCATE]**: Writing defense briefs for all pre-seeded hypotheses (H-00a through H-00f) and Round 1 ideation hypotheses (H-01 through H-07). All pre-seeded hypotheses carry VALIDATED/SOLID status from Deep Probe; the strongest possible defense is required for each.

---

### [ADVOCATE] Defense Brief for H-00a (PH-01/PH-06) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go type safety; `sync.RWMutex` on `UserLock.failures` map prevents concurrent map corruption | No — in-memory map is correctly synchronized within process; the flaw is cross-process, not intra-process | `src/core/auth/lock.go:26` |
| Framework | Beego has no built-in distributed lockout; `IsSuperUser` query is DB-backed | No | N/A |
| Middleware | No WAF rate-limiting directive in `nginx.http.conf.jinja` or `nginx.https.conf.jinja`; `server_tokens off` is present but only suppresses version info | No | `make/photon/prepare/templates/nginx/nginx.http.conf.jinja:51` |
| Application | `lock.IsLocked(username)` + 1.5s sleep on failure exists in `auth.Login`; the sleep acts as a time penalty for the attacking pod; the `IsSuperUser` DB check itself adds measurable latency per-attempt | Partial — effective for single-pod, ineffective for multi-pod Kubernetes deployments | `src/core/auth/authenticator.go:151-160` |
| Documentation | `SECURITY.md` explicitly states: "we do not currently consider the default settings for Harbor to be secure-by-default. It is necessary for operators to explicitly configure settings..." The Harbor admin password strength is operator responsibility. | Partial — documented known risk for default settings | `/SECURITY.md:79` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — not applicable; path was confirmed in Deep Probe with code evidence at `authenticator.go:142`
- Pattern 2 (phantom validation): MATCH consideration: `lock.IsLocked` IS a validation. However the Tracer confirmed it only operates per-process. Cross-pod bypass is the actual finding.
- Pattern 3 (framework protection): checked — Beego does not provide distributed rate limiting
- Pattern 4 (same-origin): checked — not applicable; this is credential brute force, not CSRF
- Pattern 5 (CVE reachability): checked — not applicable; no CVE reference
- Pattern 6 (config-as-vuln): MATCH partial — exploitation is significantly mitigated if the admin password is changed to a strong value. Harbor administrators who set strong passwords reduce attack feasibility substantially.
- Pattern 7 (test code): checked — `authenticator.go` is production code, confirmed in the server binary
- Pattern 8 (double-counting): PH-01 and PH-06 are intentionally combined; the combined finding is distinct from either standalone issue

**Defense argument:** The strongest defense is Pattern 6 (config-as-vulnerability). The `IsSuperUser` DB auth bypass is only material if the admin DB password is weak or default. The Harbor admin account password is set by the operator during initial deployment; a strong, unique password renders brute force computationally infeasible even without distributed lockout. The 1.5-second sleep on the attacking pod means a single pod can attempt at most ~40 guesses per minute. Against a 20-character random password, this renders the attack impractical regardless of pod count. Furthermore, SECURITY.md explicitly acknowledges that Harbor is not secure-by-default and places configuration responsibility on operators. The admin account's DB credential bypass for OIDC mode is arguably an intentional design choice to ensure emergency recovery access — which the SECURITY.md tacitly acknowledges as an operator configuration concern.

**Verdict recommendation:** Cannot disprove — the distributed lockout gap is real and undeniable. The password-strength argument is a partial mitigation but does not block the attack path. SECURITY.md provides only weak documentation cover as "not secure-by-default" does not specifically describe this bypass. The IsSuperUser override is not documented as an intentional emergency access mechanism.

---

### [ADVOCATE] Defense Brief for H-00b (PH-04) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's `slices.Contains` is type-safe; no parsing ambiguity in group name comparison | No — correct usage does not prevent the design flaw | `src/pkg/oidc/helper.go:396` |
| Framework | go-oidc verifies ID token signature and audience before `userInfoFromClaims` is called; fake provider cannot inject claims without signing key | Partial — BLOCKS claims from a non-configured provider; does NOT block a configured but compromised provider returning its own signed tokens | `src/pkg/oidc/helper.go` via `oidc.VerifyToken` |
| Middleware | No middleware layer applies a separate group allowlist before admin role assignment | No | N/A |
| Application | `AdminGroup` value is an administrator-configured string; an organization must configure `AdminGroup` to a value they trust their OIDC provider to return. If `AdminGroup` is left empty, `len(setting.AdminGroup) > 0` is false and no admin group check occurs. | Partial — if `AdminGroup` is empty, the attack path is inoperative. Attack requires operator to have configured AdminGroup. | `src/pkg/oidc/helper.go:395` |
| Documentation | No documentation explicitly states that `GroupFilter` applies to admin group checks. The expectation that `GroupFilter` constrains admin assignment is nowhere codified. | N/A — no documentation creates a false expectation that is exploitable | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — full path was confirmed: `groupsFromClaims` -> `slices.Contains` -> `AdminGroupMember = true` -> `user.AdminRoleInAuth = true` -> `IsSysAdmin() returns true`
- Pattern 2 (phantom validation): MATCH consideration: Is `filterGroup` a phantom validation on this path? YES — `filterGroup` IS applied but only to the DB population path (`populateGroupsDB`), not the admin role assignment path. This is precisely the finding.
- Pattern 3 (framework protection): checked — go-oidc provides cryptographic claim validation but cannot constrain what a legitimate provider chooses to include in claims
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — requires `AdminGroup` to be configured. Empty `AdminGroup` disables the attack path entirely.
- Pattern 7 (test code): checked — production code
- Pattern 8 (double-counting): checked — distinct from H-00c/H-00d which concern session storage; this concerns live claim injection from the OIDC provider

**Defense argument:** The strongest defense is a combination of Pattern 6 (config-as-vulnerability) and go-oidc's cryptographic gate. The attack requires: (1) the operator to have configured `AdminGroup`; (2) the OIDC provider to have been compromised or to be under attacker control; (3) the attacker to obtain an identity at the OIDC provider where the admin group can be injected. For legitimate OIDC providers (corporate Okta, Azure AD, Google), the attacker must control the group assignment at the provider level — which typically requires admin access to the OIDC provider itself. This is no different from trusting the IdP, which is the explicit trust model of federated authentication. If the OIDC provider is compromised, Harbor's protections are irrelevant by design. The additional argument: if `AdminGroup` is not configured (empty string), the entire code path `if len(setting.AdminGroup) > 0` evaluates false and no admin assignment can occur via groups — placing the attack squarely in the operator-configuration domain.

**Verdict recommendation:** Cannot disprove — the `filterGroup` bypass is a genuine design gap. The filter is not applied before the admin check, which violates the principle of least surprise for operators who configure `GroupFilter`. However, the attack requires a compromised/malicious OIDC provider, which is a high-bar prerequisite that weakens severity.

---

### [ADVOCATE] Defense Brief for H-00c (PH-07) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's type safety on JSON marshal/unmarshal; no memory safety issue | No — correct marshaling is not a protection against storage of sensitive values | N/A |
| Framework | Beego session management uses `session.EncodeGob` for serialization; the Harbor custom Redis provider (`HarborProviderName`) uses `gobCodec` which provides no encryption | No — session values are serialized with gob encoding (not encrypted) | `src/core/session/codec.go:34` (`gobCodec`), `session.go:91` |
| Middleware | The `session.Middleware()` sets a signed session cookie (beego uses `SessionHashKey` and `SessionHashFunc` for cookie signing); this protects the cookie in transit but does not encrypt Redis values | Partial — cookie signing prevents cookie forgery but does not protect Redis-stored data | `src/server/middleware/session/session.go` |
| Application | Redis URL in Harbor core is configured via `_REDIS_URL_CORE` environment variable (set in `docker-compose.yml`); the URL can include a password parameter (e.g., `redis://:password@redis:6379/0`) — if an operator includes a password in the Redis URL, the connection is authenticated | Partial — Redis auth IS supported and configurable via `_REDIS_URL_CORE`; default Harbor `docker-compose.yml` does NOT set a password | `src/core/main.go:148-156` |
| Documentation | `SECURITY.md:79` states Harbor is not secure-by-default. `harbor.yml.tmpl` documents the Redis password configuration option at line 216 (commented out). | Partial — Redis auth is documented as optional but not required | `make/harbor.yml.tmpl:216-217` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path confirmed: `oc.SetSession(tokenKey, tokenBytes)` -> Redis -> unauthenticated read
- Pattern 2 (phantom validation): checked — no phantom validation found; the gobCodec explicitly performs no encryption
- Pattern 3 (framework protection): checked — beego's Redis session provider does not encrypt values by default
- Pattern 4 (same-origin): checked — not applicable; Redis access is network-level
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — Redis auth IS configurable via `_REDIS_URL_CORE`. Operators who set Redis authentication prevent unauthenticated access. Default deployment does not.
- Pattern 7 (test code): checked — `src/core/controllers/oidc.go` is production code
- Pattern 8 (double-counting): PH-07 is the storage finding; PH-19 (H-00d) is the onboard exploitation finding. Distinct issues sharing a prerequisite.

**Defense argument:** Pattern 6 (config-as-vulnerability) is the strongest defense. Harbor supports Redis authentication via the `_REDIS_URL_CORE` environment variable, which accepts standard Redis URL format including passwords. The `harbor.yml.tmpl` documents an external Redis configuration with an explicit password field. Any operator who configures Redis authentication eliminates the unauthenticated access prerequisite for this attack. Additionally, in production Kubernetes deployments, Redis is typically deployed with NetworkPolicy rules or within a private subnet inaccessible from external networks. The threat requires both unauthenticated Redis AND network access to Redis — a combination that any reasonably hardened deployment prevents. SECURITY.md explicitly places configuration responsibility on operators.

**Verdict recommendation:** Cannot disprove — the code confirms token storage without application-level encryption. The "configurable" argument is valid but the default configuration is demonstrably insecure. The Redis URL password documentation is non-obvious (commented out in `harbor.yml.tmpl`) which means operators who follow the quickstart guide will not enable it.

---

### [ADVOCATE] Defense Brief for H-00d (PH-19) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's `json.Unmarshal` into `*oidc.UserInfo` — type-safe deserialization; no buffer overflow possible | No — type safety does not prevent injecting semantically valid but attacker-controlled values | N/A |
| Framework | Beego session management provides session ID isolation; each session cookie maps to a unique Redis key; an attacker cannot inject into another user's session without knowing the session ID | Partial — blocks cross-user session injection; does NOT block injection if attacker has Redis write access (knows the session key format) | `src/core/session/session.go:100-107` |
| Middleware | `utils.IsIllegalLength(username, 1, 255)` and `strings.ContainsAny(username, common.IllegalCharsInUsername)` validate the POST body `username` field | No — these validations protect the username parameter but not the session-stored `userInfoStr` which contains the `admin_group_member` claim | `src/core/controllers/oidc.go:367-373` |
| Application | `OIDCController.Onboard` requires `userInfoKey` to be present in session (`ok` check at line 377); this means only active sessions with completed OIDC callback can trigger onboarding | Partial — limits attack to sessions that have completed the OIDC callback flow; does not prevent Redis injection into such sessions |  `src/core/controllers/oidc.go:376-379` |
| Documentation | SECURITY.md documents operator responsibility for security configuration. No specific documentation about Redis session integrity requirements. | No specific doc | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path confirmed: Redis write -> `GetSession(userInfoKey)` -> `json.Unmarshal` -> `InjectGroupsToUser` -> `AdminGroupMember=true`
- Pattern 2 (phantom validation): MATCH consideration: username validations at `oidc.go:367-373` look like protection but they validate only the POST body `username`, not the session-stored `userInfoStr`. This is a genuine gap in what is validated.
- Pattern 3 (framework protection): checked — beego session isolation is per-session-ID; Redis write access bypasses this
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — same Redis auth prerequisite as H-00c; configuring Redis auth blocks this attack
- Pattern 7 (test code): checked — production code
- Pattern 8 (double-counting): H-00c (PH-07) and H-00d (PH-19) share the Redis-access prerequisite but are distinct: H-00c is about token extraction, H-00d is about account creation via session manipulation. Not double-counting.

**Defense argument:** The strongest defense is the chained prerequisite. This attack requires: (1) Redis write access (eliminated by Redis auth configuration); AND (2) knowledge of a valid session ID (eliminates anonymous Redis writers — requires either Redis key scan access or prior session ID theft). The `userInfoKey` must be present in the session, meaning the target session must have completed the OIDC callback flow. An attacker with only Redis access but no knowledge of active session IDs cannot reliably target the right key. Additionally, the username in the POST body is validated, meaning the attacker can create an admin-level user but cannot impersonate an existing account's username (illegally long or containing special characters would be rejected). The attack surface is limited to the OIDC onboarding window for new users.

**Verdict recommendation:** Cannot disprove — the lack of OIDC re-verification in `Onboard` is a genuine trust violation. The Redis prerequisite is the primary mitigation but the code-level gap remains.

---

### [ADVOCATE] Defense Brief for H-00e (PH-25) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `strings.CutPrefix(auth, "Harbor-Secret ")` in `secret.FromRequest` correctly parses the header | No — correct parsing does not prevent forwarding of attacker-supplied headers | `src/common/secret/request.go:34` |
| Framework | No framework-level header stripping for `Authorization` on proxy pass | No | N/A |
| Middleware | `nginx.http.conf.jinja` and `nginx.https.conf.jinja` use `proxy_set_header` for `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` — notably `Authorization` is NOT in this list, meaning Nginx passes through the original `Authorization` header unchanged | No — this is the finding: no `proxy_set_header Authorization ""` directive | `make/photon/prepare/templates/nginx/nginx.http.conf.jinja:97-100, 122-125, 148-151` |
| Application | `config.SecretStore.IsValid(sec)` performs exact string match against runtime-generated secrets; the secret is generated at startup and stored in memory; it is not stored in any config file or environment variable that persists across restarts | Yes — this is a genuine secret. An attacker must know the actual runtime secret value to exploit this. The secret is not static or discoverable from code alone. | `src/common/secret/store.go:39-41` |
| Documentation | No documentation describes the expected Nginx header-stripping behavior. `src/jobservice/README.md:461` documents `Authorization: Harbor-Secret <secret>` format for internal use. | No documentation warning about external injection risk | `src/jobservice/README.md:461` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path confirmed: external request -> Nginx (no strip) -> Harbor core -> `commonsecret.FromRequest` -> `config.SecretStore.IsValid`
- Pattern 2 (phantom validation): MATCH — `config.SecretStore.IsValid(sec)` IS a protection. It absolutely requires knowledge of the runtime-generated secret. This is not phantom — it is a real cryptographic gate.
- Pattern 3 (framework protection): checked — Nginx does not auto-strip Authorization headers
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): Partial — the secret is runtime-generated (not config-settable), so this is not a config vulnerability. The secret is strong by construction.
- Pattern 7 (test code): checked — production code; `secret.FromRequest` is used in the security middleware chain
- Pattern 8 (double-counting): checked — distinct from other hypotheses

**Defense argument:** This is the strongest defense in the set. The `config.SecretStore.IsValid(sec)` application-layer gate requires the attacker to know the EXACT runtime-generated secret. Harbor's secret is generated at startup (not statically configured), is held only in memory of the core process, and is not written to any persistent store, log, or environment variable visible to an external attacker. The Nginx non-stripping of `Authorization` is a defense-in-depth gap, but the application-level secret validation is itself the primary protection — and it is not bypassable without secret knowledge. The attack model requires: (1) Nginx not stripping the header (confirmed) AND (2) attacker knowledge of the runtime secret (extremely high bar). The secret would only be discoverable via: memory dump, core dump, or process environment inspection — all of which require a prior compromise of the Harbor core container. If the core container is already compromised, the attacker has full access regardless. This is therefore a defense-in-depth gap, not an exploitable vulnerability in isolation.

**Verdict recommendation:** Disproved by Application protection (`config.SecretStore.IsValid`) — the attack requires prior knowledge of a runtime-generated secret that is not accessible to external attackers. The Nginx non-stripping is a defense-in-depth concern, not an independently exploitable vulnerability. Recommend downgrade to LOW/INFORMATIONAL unless a separate path to secret disclosure is identified.

---

### [ADVOCATE] Defense Brief for H-00f (PH-26) -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's string handling; `strings.TrimSpace(p)` applied to username check at `ldap.go:57` | No — username check is present; password check is absent from this path | `src/core/auth/ldap/ldap.go:57` |
| Framework | `go-ldap/v3` library's `Bind` function: passes the password as-is to the LDAP server; does not add client-side empty password protection | No | `src/pkg/ldap/ldap.go:191` |
| Middleware | No middleware layer validates LDAP password non-emptiness before the auth stack processes it | No | N/A |
| Application | `ErrEmptyPassword` is defined in `src/pkg/ldap/ldap.go:39` and IS used in `src/controller/ldap/controller.go:71,110,114` — but only for the SEARCH CREDENTIAL (admin bind for user lookup), NOT for the USER authentication bind at `src/core/auth/ldap/ldap.go:87` | No — the empty-password check exists but is in the wrong code path | `src/controller/ldap/controller.go:65-74` |
| Documentation | Harbor documentation on LDAP configuration does not specify that LDAP servers should enforce password policies server-side | No protective documentation | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path confirmed: `ldap.Auth.Authenticate` -> `ldapSession.SearchUser` -> `ldapSession.Bind(dn, m.Password)` with no empty-password check before Bind
- Pattern 2 (phantom validation): MATCH — `ErrEmptyPassword` looks like a protection but the Grep confirms it is only used for search credentials, NOT for the user bind. This is a genuine phantom validation.
- Pattern 3 (framework protection): checked — go-ldap does not add client-side empty-password protection
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — this attack REQUIRES the LDAP server to accept null binds. RFC 4511 states that LDAP servers SHOULD reject empty passwords, but many servers (especially misconfigurations of OpenLDAP, Active Directory with specific settings) do accept null binds. Exploitation depends entirely on server configuration outside Harbor's control.
- Pattern 7 (test code): checked — production authentication code
- Pattern 8 (double-counting): overlaps SGap-1 (LDAP RFC 4511 null bind) from spec-gap findings, but this is the same root cause, not double-counting

**Defense argument:** The strongest defense is Pattern 6 (config-as-vulnerability at the LDAP server level). The null bind attack requires the LDAP server to accept empty passwords. RFC 4511 section 4.2.2 states: "A client may abort a Bind operation by sending an Abandon request with the message ID of the Bind request. [...] Unauthenticated bind is not recommended for most directory server usage" and more specifically, LDAP servers that properly implement RFC 4511 MUST NOT allow a null bind to succeed for user accounts with password policies. Modern LDAP servers (Active Directory, OpenLDAP with `ppolicy`, 389 Directory Server) reject null binds by default. The null bind attack is only effective against LDAP servers that are misconfigured — which is outside Harbor's trust boundary. Harbor appropriately delegates authentication decisions to the LDAP server; if the LDAP server accepts null binds, that is the LDAP server misconfiguration. A defense-in-depth empty-password check in Harbor would be good practice but is not the primary security control.

**Verdict recommendation:** Cannot disprove — the missing empty-password check before `Bind` is a genuine defense-in-depth gap. Even though LDAP server misconfiguration is the root exploitability condition, Harbor should guard against it client-side. The phantom validation of `ErrEmptyPassword` being defined but unused for user auth is a code quality finding that supports the report.

---

### [ADVOCATE] Defense Brief for H-01 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go type safety in session handling; state parameter type assertion | No | N/A |
| Framework | go-oidc `VerifyToken` validates ID token signature and nonce if present in the token claims (oidc library does check nonce if bound); the `state` parameter validated by Harbor (`oc.GetSession(stateKey)`) | Partial — state parameter binds callback to an originating session; if attacker cannot forge the state, they cannot replay the callback at all |  `src/core/controllers/oidc.go:120-130` |
| Middleware | CSRF middleware applied to portal routes; OIDC callback is a GET which is typically CSRF-exempt | No — CSRF does not prevent callback replay |  N/A |
| Application | `oc.DelSession(stateKey)` is called after state validation — single-use state token prevents replay of the same callback URL (nonce-like behavior for state) | Yes — this is a significant protection: state is consumed on first use, preventing replay | `src/core/controllers/oidc.go:120-122` |
| Documentation | No documentation claims nonce protection is in place | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — the chain requires callback URL interception AND userinfo endpoint failure, both of which must occur in sequence
- Pattern 2 (phantom validation): MATCH — `oc.DelSession(stateKey)` may constitute a phantom validation defense. State deletion after first use means a captured callback URL CANNOT be replayed because the state session key is consumed. This is a critical protection that disproves the replay component.
- Pattern 3 (framework protection): checked — go-oidc validates nonce only if it was bound during authorization; SGap-2 is that nonce is not always bound
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): checked — not applicable
- Pattern 7 (test code): checked — production code
- Pattern 8 (double-counting): this chains SGap-2 with PH-13; the chain hypothesis is new but the components are pre-validated

**Defense argument:** The strongest defense is the state deletion mechanism at `oidc.go:120-122`. After `oc.DelSession(stateKey)` is called, the state associated with the callback is consumed. A replayed callback URL (same `code` + `state`) would fail the state validation because the session key is gone. For this attack to work, the attacker must intercept the callback BEFORE the victim has used it (and before the `code` has expired at the OIDC provider). The OIDC authorization code lifetime is typically 60-600 seconds. The attack window is narrow and requires both: (1) intercepting the one-time-use callback URL; AND (2) the userinfo endpoint being unavailable at replay time. The combination of a narrow interception window, single-use state, and conditional userinfo failure makes this attack chain highly impractical.

**Verdict recommendation:** Disproved by Application protection (state deletion as single-use token) — the replay component of H-01 is blocked by `oc.DelSession(stateKey)`. The residual risk is the SGap-2 and PH-13 individual findings, not the chained attack as described.

---

### [ADVOCATE] Defense Brief for H-02 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go session handling with type assertions | No | N/A |
| Framework | Beego session: when auth mode changes, `session.Generate` re-reads the session from Redis. The session stores a `models.User` struct (gob-serialized) which includes database-persisted fields. | Partial — the user struct in session reflects the DB state at last login; group memberships are loaded from DB at session time | `src/core/session/codec.go:29` |
| Middleware | `security.Middleware` runs `session.Generate` on every request; the session-loaded user is re-looked-up against the DB | Partial — need to verify if `session.Generate` re-queries DB on each request | `src/server/middleware/security/session.go` |
| Application | Auth mode is read from config on every `auth.Login` call via `config.AuthMode(ctx)`; for API endpoints authenticated via session (not basic auth), the session-loaded user bypasses the auth mode check entirely | Yes — session-authenticated requests do NOT go through `auth.Login`, so the `IsSuperUser`/DBAuth override is irrelevant for session-based access | `src/core/auth/authenticator.go:138-144` |
| Documentation | No documentation about session invalidation on auth mode changes | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): The attack chain assumes session auth grants persistent admin access after mode change; need to verify if `session.Generate` re-validates group membership
- Pattern 2 (phantom validation): checked — need to examine `session.Generate` implementation
- Pattern 3 (framework protection): checked — beego sessions persist until timeout; no automatic invalidation on config change
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): Partial — auth mode change is an operator action; requiring session invalidation after mode change is an operator responsibility
- Pattern 7 (test code): checked — not applicable
- Pattern 8 (double-counting): checked — distinct from H-00a through H-00f

**Defense argument:** The attack requires that LDAP group membership granted admin role AND the session persists after auth mode change. Harbor's session stores the user model which is a snapshot at login time. After an auth mode change, previously authenticated sessions continue to be valid until timeout (configurable, defaults to 30 minutes). However, the `AdminRoleInAuth` field for LDAP users is derived from LDAP group membership which is populated during authentication. For LDAP users, `AdminRoleInAuth` reflects LDAP group-based admin at login time. If the organization trusted the LDAP-mode admin and switches to OIDC mode, the operator would presumably revoke the admin role in Harbor DB separately — which would update the persisted user record and affect subsequent session loads. The attack relies on the operator failing to revoke admin during mode transition, which is an operational oversight rather than a security vulnerability.

**Verdict recommendation:** Cannot disprove as a theoretical chain — session persistence across auth mode changes is real. However, the attack depends on an operator failing to revoke admin roles during auth mode transition, which is an operational concern. Further tracing of `session.Generate` user reload behavior would confirm or deny whether DB-side role changes propagate to existing sessions.

---

### [ADVOCATE] Defense Brief for H-03 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go type safety in session deserialization | No | N/A |
| Framework | Session isolation by session ID; Redis key format is Harbor-managed | Partial — see H-00d defense |  N/A |
| Middleware | No additional middleware protection | No | N/A |
| Application | Redis auth configurable; LDAP null bind requires LDAP server misconfiguration | Partial — each component has partial mitigations (see H-00c, H-00f) | N/A |
| Documentation | SECURITY.md covers non-secure defaults | Partial | `/SECURITY.md:79` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): The chain is a combination of three already-VALIDATED findings (Redis no-auth + LDAP null bind + OIDC onboard trust). Each path is confirmed; the chain is additive not independently new.
- Pattern 2 (phantom validation): checked — see individual findings H-00c, H-00d, H-00f
- Pattern 3 (framework protection): checked — no framework protection for the chain
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — all three components require operator configuration failures: Redis without auth AND LDAP server accepting null binds (or OIDC session injection without Redis auth)
- Pattern 7 (test code): checked — not applicable
- Pattern 8 (double-counting): MATCH — this hypothesis is explicitly a chain of H-00c + H-00d + H-00f. As a defense brief, addressing H-00c, H-00d, and H-00f individually is sufficient. H-03 adds no new attack surface; it is the composition of already-validated findings.

**Defense argument:** Pattern 8 (double-counting) is the primary defense argument. H-03 is the union of H-00c, H-00d, and H-00f attack chains. Each component is individually assessed in separate defense briefs. The "chain" hypothesis does not introduce new attack surfaces beyond what those three findings cover. Furthermore, the chain requires simultaneous failures: Redis without authentication AND LDAP server null bind acceptance. Any single remediation (Redis auth, empty-password check, LDAP server hardening) breaks the chain. The defense briefs for H-00c, H-00d, and H-00f each independently argue partial mitigation; combined, they create multiple independent remediation points that break the chain at any link.

**Verdict recommendation:** FP pattern match: 8 (double-counting) — H-03 is a synthesis of H-00c, H-00d, and H-00f. It should be represented as a risk amplification note in those findings rather than a standalone finding. All remediation is already captured in the individual findings.

---

### [ADVOCATE] Defense Brief for H-04 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's `json.Unmarshal` with strict struct types; JWT base64 decode is type-safe | No | N/A |
| Framework | PostgreSQL ORM (beego ORM); parameterized queries prevent most SQL injection | Partial — ORM provides parameterization for ORM-generated queries; raw `fmt.Sprintf` queries are separate | N/A |
| Middleware | No middleware guards `oidc_user.token` writes | No | N/A |
| Application | `FixEmptySubIss` only processes records where `SubIss == ""` (empty subject/issuer); for records that already have a SubIss value, the function is a no-op | Yes — this is a significant protection: attacker must target an `oidc_user` row that has an empty `subiss` value. Existing accounts with populated `subiss` are not affected. | `src/core/main.go:282` (calls `FixEmptySubIss`); need to verify the filter condition |
| Documentation | PH-22 was marked NEEDS-DEEPER in Deep Probe specifically because "exploitation requires writing crafted token to `oidc_user.token` column (SQL injection prerequisite)" | N/A |  `security/probe-workspace/auth-chain/probe-summary.md:170` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): The chain requires SQL injection write to `oidc_user.token` + Harbor core restart; attacker input reaching `oidc_user.token` via SQL injection is not confirmed — it is postulated
- Pattern 2 (phantom validation): checked — ORM parameterization is a real protection for ORM-generated queries
- Pattern 3 (framework protection): MATCH — beego ORM parameterization blocks SQL injection for ORM queries; the raw `fmt.Sprintf` issue is a separate pre-condition that must independently be confirmed exploitable to write to `oidc_user.token`
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): checked — not applicable
- Pattern 7 (test code): checked — `FixEmptySubIss` is production code called at startup
- Pattern 8 (double-counting): checked — this is the PH-22 NEEDS-DEEPER item; distinct from other findings

**Defense argument:** Pattern 3 (framework protection blindness) and Pattern 5 (CVE reachability dependency) are the strongest defenses. The attack chain requires SQL injection that specifically writes to `oidc_user.token`. The knowledge-base report mentions 44 `fmt.Sprintf -> SQL` flows, but those are in the API surface generally — NOT specifically confirmed to reach the `oidc_user.token` column. Without an independently confirmed SQL injection path to `oidc_user.token`, this is a hypothetical chain where the prerequisite is unproven. Additionally, `FixEmptySubIss` only processes records with empty `subiss` — meaning the attacker must target a specific class of records (newly created or migrated accounts that haven't been verified). This narrows the blast radius considerably.

**Verdict recommendation:** Cannot disprove as a chain concept — the components exist. However, the SQL injection prerequisite to `oidc_user.token` specifically is UNPROVEN at this point in the analysis. This finding should be marked as CONDITIONAL pending confirmation of a SQL injection path that reaches the `oidc_user.token` column.

---

### [ADVOCATE] Defense Brief for H-05 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go JWT parsing with RS256 signature validation; audience check via `jwt.WithAudience(svc_token.Registry)` | Yes — signature and audience are required; stale tokens must be cryptographically valid | `src/server/middleware/security/v2_token.go:65-66` |
| Framework | JWT expiry validation with leeway (`jwt.WithLeeway(common.JwtLeeway)`) | Yes — expired tokens are rejected; default token expiry limits the window for stale token reuse | `src/server/middleware/security/v2_token.go:65` |
| Middleware | `v2auth` middleware enforces per-resource authorization checks after security context is established | Partial — `v2auth` checks if the security context's access list covers the requested resource+action | `src/server/middleware/v2auth/` |
| Application | `tokenIssuedAfterProjectCreation` checks timestamp for project-specific operations (confirmed functional for manifest/blob paths by PH-23 revised analysis); token `access` claim scopes the permitted repositories | Yes — for the actual push/pull operations (`PUT /v2/foo/image/manifests/latest`), ArtifactInfo IS populated and the timestamp check IS effective | `src/server/middleware/security/v2_token.go:83-99` |
| Documentation | No documentation about stale token behavior on project recreation | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH — the hypothesis assumes a stale token authenticated at `/v2/` can then succeed on subsequent scoped operations. This assumes the authentication at `/v2/` grants general access, which it does not — each request is independently authenticated.
- Pattern 2 (phantom validation): MATCH — `tokenIssuedAfterProjectCreation` IS functional for manifest/blob operations (PH-23 revision confirmed this). The `/v2/` bypass only avoids the timestamp check for the discovery endpoint — not for content operations.
- Pattern 3 (framework protection): checked — JWT expiry independently limits the window
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): checked — not applicable
- Pattern 7 (test code): checked — not applicable
- Pattern 8 (double-counting): partial overlap with PH-03, but H-05 adds the scope escalation angle

**Defense argument:** Patterns 1 and 2 (path trace + phantom validation) provide the strongest defense. Each HTTP request to Harbor is independently authenticated — there is no "authenticated at `/v2/` therefore can access content" session persistence at the application level. A stale token used to access `/v2/` (base) returns 200 with authentication confirmation. A SUBSEQUENT request to `PUT /v2/foo/image/manifests/latest` goes through an independent authentication cycle where `tokenIssuedAfterProjectCreation` IS called with the populated ArtifactInfo (`ProjectName = "foo"`). The timestamp check would then fire and reject the stale token. The attack model in H-05 incorrectly assumes that `/v2/` authentication carries forward to resource operations.

**Verdict recommendation:** Disproved by Application protection — `tokenIssuedAfterProjectCreation` IS functional for content operations (manifest/blob). The `/v2/` base endpoint bypass (PH-03) is limited to the discovery endpoint and does not enable scope escalation to content operations. H-05's attack chain is broken by the per-request authentication model.

---

### [ADVOCATE] Defense Brief for H-06 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go string prefix checking with `strings.HasPrefix` | No — prefix check is a Harbor-side control, not a network-level defense | N/A |
| Framework | No framework-level auth proxy header validation | No | N/A |
| Middleware | Auth proxy mode restricts `authProxy.Generate` to `/v2/*` paths (`auth_proxy.go:41`); only enabled when `settings.AuthProxyConfig` is configured and endpoint is set | Partial — auth proxy is DISABLED by default; must be explicitly configured | `src/server/middleware/security/auth_proxy.go:41` |
| Application | `authProxy.Generate` performs `authproxy.VerifyToken` / `authproxy.TokenReview` which makes an outbound call to a configured endpoint; this outbound verification would reject a locally-injected header unless the token review endpoint accepts the injected value | Partial — the token review call provides an external verification step that cannot be bypassed without controlling the review endpoint | `src/server/middleware/security/auth_proxy.go:63` |
| Documentation | Auth proxy mode is documented as requiring explicit configuration of a trusted proxy endpoint | Partial | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH — H-06 postulates that Nginx does not strip the `X-Auth-User` header, but the auth proxy in Harbor uses `Authorization` header (or `Proxy-Authorization`), NOT `X-Auth-User`. The mechanism for auth proxy in Harbor involves verifying a bearer token presented by the external proxy, not trusting a plaintext username header.
- Pattern 2 (phantom validation): checked — TokenReview IS a verification step, not phantom
- Pattern 3 (framework protection): checked — not applicable
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): MATCH — auth proxy mode is off by default; requires explicit operator configuration
- Pattern 7 (test code): checked — not applicable
- Pattern 8 (double-counting): combines PH-08 (NEEDS-DEEPER) and PH-25 (Nginx header stripping)

**Defense argument:** Pattern 1 (unsafe-looking code without path tracing) is the strongest defense. H-06 conflates the `X-Auth-User` header (HTTP Auth Proxy pattern) with Harbor's actual auth proxy mechanism which uses bearer token verification via `authproxy.TokenReview`. The `authProxy.Generate` middleware reads a bearer token (not a plain username header), submits it to the configured token review endpoint, and accepts or rejects the identity based on the endpoint's response. An external attacker cannot forge a token that the token review endpoint would accept without knowing the token issuance mechanism of the configured proxy. Additionally, auth proxy mode is disabled by default and requires explicit operator configuration. This is Pattern 6 as well: the attack only applies when an operator has explicitly deployed and configured an auth proxy.

**Verdict recommendation:** FP pattern match: 1 (no path trace) and 6 (config-as-vulnerability) — H-06 misattributes the header injection mechanism. The actual auth proxy uses token verification, not header username trust. The finding is substantially weaker than presented.

---

### [ADVOCATE] Defense Brief for H-07 -- 2026-03-27T10:30:00Z

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go's constant-time comparison is NOT used in `utils.Encrypt` comparison (`!=` operator); timing differences from PBKDF2 computation exist | No — non-constant-time comparison is confirmed | `src/server/middleware/security/robot.go:57` |
| Framework | No framework-level timing equalization | No | N/A |
| Middleware | Nginx does not add timing normalization | No | N/A |
| Application | OIDC CLI authentication (`oidcCli.Generate`): user lookup by subject+issuer from token, then `oidc.VerifySecret` is called; the timing difference depends on whether the user record is found | Partial — need to verify if user-not-found returns before or after fixed-time operation |  `src/server/middleware/security/oidc_cli.go` |
| Documentation | No documentation about timing oracle risks | N/A | N/A |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): MATCH — the hypothesis claims the oracle is in `oidcCli.Generate` but needs to verify the specific DB lookup + AES decrypt path in that function; the timing difference between "user not found" vs "user found, secret invalid" depends on whether the DB lookup itself has measurable timing
- Pattern 2 (phantom validation): checked — no phantom validation found on this path
- Pattern 3 (framework protection): checked — no timing normalization
- Pattern 4 (same-origin): checked — not applicable
- Pattern 5 (CVE reachability): checked — not applicable
- Pattern 6 (config-as-vuln): checked — not applicable
- Pattern 7 (test code): checked — not applicable
- Pattern 8 (double-counting): checked — distinct from other findings

**Defense argument:** The practical exploitability of timing oracles over a network is highly constrained. Network jitter (typically 1-100ms) vastly exceeds the application-level timing difference from a DB lookup (typically 1-10ms) or AES decryption (typically 0.01-0.1ms). Measuring a consistent timing signal requires hundreds or thousands of requests over a stable network connection. For a deployed Harbor instance (likely behind a load balancer with multiple backend pods), request routing to different pods introduces variable timing that masks the oracle. Additionally, the finding requires the attacker to already know that the OIDC CLI path (`Authorization: Basic <user:oidc_secret>`) triggers the specific code path — a non-trivial prerequisite. Username enumeration via timing is typically a LOW severity finding in well-connected production environments where network jitter overwhelms the signal.

**Verdict recommendation:** Cannot disprove the theoretical timing difference exists — the DB lookup path does differ for found vs. not-found users. However, the practical exploitability requires extremely controlled network conditions that are unlikely in production deployments. Recommend LOW severity with a note that constant-time username checking would be a defense-in-depth improvement.


---

## Round 1 -- Tracer Evidence

### [TRACER] Evidence for H-00a (PH-01/PH-06) -- 2026-03-27T10:45:00Z

**Reachability: REACHABLE**

Code path:
1. `src/server/middleware/security/basic_auth.go` -- `basicAuth.Generate` receives HTTP request with `Authorization: Basic <base64(admin:password)>`, calls `auth.Login(ctx, m)`
2. `src/core/auth/authenticator.go:142` -- `if authMode == "" || IsSuperUser(ctx, m.Principal)` -- when `m.Principal` resolves to userID=1, `authMode` is forced to `common.DBAuth` regardless of system-configured auth mode
3. `src/core/auth/authenticator.go:259-266` -- `IsSuperUser` performs `user.Mgr.GetByName(ctx, username)` and returns `u.UserID == 1`; comparison is purely by DB primary key with no mode check
4. `src/core/auth/authenticator.go:151` -- `lock.IsLocked(m.Principal)` checked against package-level `lock` variable
5. `src/core/auth/lock.go:23-51` -- `UserLock.failures` is `map[string]time.Time` in Go process memory; no Redis persistence; declared as `var lock = NewUserLock(frozenTime)` at package scope
6. `src/core/auth/authenticator.go:155` -- `authenticator.Authenticate(ctx, m)` dispatches to `registry["db"].Authenticate` which checks DB password hash

Sanitizers on path:
- `src/core/auth/lock.go:47-51` -- `IsLocked` checks `time.Since(ul.failures[username]) <= ul.d`; bypassable by routing requests to different Harbor core pods; each process maintains its own in-memory map with zero cross-pod coordination

CodeQL slice: no dedicated slice in call-graph-slices.json for this path; the 4 slices cover SQL injection, SSRF, OIDC callback, and auth proxy redirect. CodeQL: unavailable for basic-auth-to-DB path.
On-demand query: none

**Assessment**: REACHABLE. The `IsSuperUser` call at authenticator.go:142 unconditionally forces DB auth for userID=1. The `UserLock` at lock.go is a process-local Go map with no distributed synchronization. The Advocate's strongest defense (Pattern 6: password strength) is valid operationally but does not close the code-level gap -- the bypass is structural and unconditional regardless of password strength.

---

### [TRACER] Evidence for H-00b (PH-04) -- 2026-03-27T10:45:01Z

**Reachability: REACHABLE**

Code path:
1. `src/pkg/oidc/helper.go:394` -- `res.Groups, res.hasGroupClaim = groupsFromClaims(c, setting.GroupsClaim)` -- raw groups extracted from ID token claims, no filter applied
2. `src/pkg/oidc/helper.go:395-399` -- `if len(setting.AdminGroup) > 0 { if slices.Contains(res.Groups, setting.AdminGroup) { res.AdminGroupMember = true } }` -- admin check runs on unfiltered `res.Groups`
3. `mergeUserInfo` at helper.go:340 -- `res.AdminGroupMember = local.AdminGroupMember` propagates flag through merge
4. `src/server/middleware/security/oidc_cli.go:80` -- `oidc.InjectGroupsToUser(info, u)` writes `info.AdminGroupMember` into `u.AdminRoleInAuth`
5. `local.NewSecurityContext(u)` -- `IsSysAdmin()` returns `u.AdminRoleInAuth`

Sanitizers on path:
- `filterGroup` regex: present in codebase for `populateGroupsDB` only; NOT applied at helper.go:396 before the admin group membership check. This is confirmed by direct code reading -- no call to `filterGroup` exists on the path from `groupsFromClaims` to `AdminGroupMember = true`.

CodeQL slice: DFD-3 (OIDC callback) partially covers this flow but does not trace through `userInfoFromClaims`. CodeQL: unavailable for the admin group injection sub-path.
On-demand query: none

**Assessment**: REACHABLE. The `filterGroup` regex is applied only to DB group population, never to the admin role assignment. Confirmed by reading helper.go:394-399 directly. The Advocate's defense (AdminGroup must be configured; requires compromised OIDC provider) is valid as a severity qualifier but does not change reachability.

---

### [TRACER] Evidence for H-00c (PH-07) -- 2026-03-27T10:45:02Z

**Reachability: REACHABLE**

Code path:
1. `src/core/controllers/oidc.go:161-162` -- `tokenBytes, err := json.Marshal(token)` -- serializes full `oauth2.Token` struct including `RefreshToken` field as JSON
2. `src/core/controllers/oidc.go:166` -- `oc.SetSession(tokenKey, tokenBytes)` -- writes raw JSON bytes to beego Redis session under `tokenKey`
3. Beego Redis session provider -- session values are gob-encoded (confirmed: `src/core/session/codec.go` uses `gobCodec`); no encryption at rest
4. Attacker with Redis TCP access reads session hash, base64-decodes gob value, unmarshals `oauth2.Token`, extracts `RefreshToken`
5. OIDC provider `/token` endpoint called with `grant_type=refresh_token` -- new access token issued

Sanitizers on path:
- Session cookie signing/encryption: protects cookie in transit; zero protection against direct Redis TCP access
- Application-level encryption of Redis session values: absent; `gobCodec` provides serialization only

CodeQL slice: DFD-3 covers OIDC callback through session write. Reachable per slice.
On-demand query: none

**Assessment**: REACHABLE. Full `oauth2.Token` JSON (with refresh token) is written to Redis without application-level encryption. Confirmed at oidc.go:161-166. The Advocate's strongest defense (Redis auth configurable via `_REDIS_URL_CORE`) is valid as a deployment mitigation but the default deployment lacks this protection.

---

### [TRACER] Evidence for H-00d (PH-19) -- 2026-03-27T10:45:03Z

**Reachability: REACHABLE**

Code path:
1. Attacker writes crafted session entry to Redis: key `oidc_user_info` = `{"admin_group_member":true,"groups":["<AdminGroup>"],"username":"attacker"}`, key `token` = valid-JSON bytes
2. `src/core/controllers/oidc.go:376` -- `userInfoStr, ok := oc.GetSession(userInfoKey).(string)` -- retrieves attacker-controlled string from Redis session
3. `src/core/controllers/oidc.go:389` -- `json.Unmarshal([]byte(userInfoStr), &d)` -- deserializes attacker-controlled JSON into `*oidc.UserInfo` with no integrity check
4. `src/core/controllers/oidc.go:395` -- `userOnboard(ctx, oc, d, username, tb)` -- onboard called with `d.AdminGroupMember = true`
5. `InjectGroupsToUser(info, user)` sets `user.AdminRoleInAuth = true` -- `ctluser.Ctl.OnboardOIDCUser` creates Harbor account with system admin flag

Sanitizers on path:
- Username validation at oidc.go:371: checks length + illegal chars; does NOT re-verify OIDC token or check session data integrity
- No HMAC or signature on session data in Redis

CodeQL slice: DFD-3 covers OIDC callback but not the `Onboard` handler. CodeQL: unavailable for this path.
On-demand query: none

**Assessment**: REACHABLE. The `Onboard` handler at oidc.go:376-395 trusts the `oidc_user_info` JSON verbatim from Redis session with no re-verification. The Advocate's defense (Redis auth configurable) applies as a deployment mitigation; default deployments are vulnerable.

---

### [TRACER] Evidence for H-00e (PH-25) -- 2026-03-27T10:45:04Z

**Reachability: REACHABLE (conditional)**

Code path:
1. `make/photon/prepare/templates/nginx/nginx.http.conf.jinja` -- all `proxy_set_header` directives at lines 75-78, 97-100, 122-125, 148-151, 172-175 set Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto only; no `proxy_set_header Authorization ""` directive exists in any location block
2. External request with `Authorization: Harbor-Secret <value>` passes through Nginx unmodified to Harbor core
3. `src/common/secret/request.go:33-37` -- `FromRequest` reads `req.Header.Get("Authorization")`, strips `Harbor-Secret ` prefix (defined as constant `HeaderPrefix = "Harbor-Secret "` at line 25)
4. `src/server/middleware/security/secret.go:31-36` -- `secret.Generate` calls `commonsecret.FromRequest(req)`; if non-empty, creates full internal-trust security context
5. Internal trust context grants full system privileges (equivalent to JobService access)

Sanitizers on path:
- `config.SecretStore.IsValid(sec)` at secret.go:36 (via `NewSecurityContext`): validates secret value; the only gate. The `Harbor-Secret` prefix is public knowledge (open-source codebase). The actual secret value is generated at startup and must be discovered separately.

CodeQL slice: no slice for secret header path. CodeQL: unavailable.
On-demand query: none

**Assessment**: REACHABLE conditional on knowing the secret value. The structural finding is confirmed: Nginx does not strip the `Authorization` header for any location block. The `Harbor-Secret ` prefix is a well-known constant. The Advocate's defense that the secret value is the only gate is correct, but the absence of Nginx-level protection means external clients can attempt this auth path without any prior filtering.

---

### [TRACER] Evidence for H-00f (PH-26) -- 2026-03-27T10:45:05Z

**Reachability: REACHABLE**

Code path:
1. `src/core/auth/ldap/ldap.go:57` -- `if len(strings.TrimSpace(p)) == 0` -- rejects empty **username** only; no analogous check for empty **password**
2. `src/core/auth/ldap/ldap.go:72` -- `ldapSession.SearchUser(p)` -- finds user DN by username
3. `src/core/auth/ldap/ldap.go:87` -- `ldapSession.Bind(dn, m.Password)` -- binds with attacker-supplied password (may be `""`)
4. `src/pkg/ldap/ldap.go:190-192` -- `Session.Bind` calls `s.ldapConn.Bind(dn, password)` -- passes empty password directly to go-ldap and thence to LDAP server
5. LDAP server accepting null bind returns success -- attacker is authenticated as target user

Sanitizers on path:
- `ErrEmptyPassword` is defined in the package but used only in search credential context, NOT in user authentication path. The password validation gap is confirmed by absence of any `len(strings.TrimSpace(m.Password)) == 0` check between ldap.go:55 and ldap.go:87.

CodeQL slice: no slice for LDAP auth path. CodeQL: unavailable.
On-demand query: none

**Assessment**: REACHABLE against null-bind-permissive LDAP servers. Confirmed by reading ldap/ldap.go:55-100 -- no empty password check exists before `Bind`. RFC 4511 specifies null bind behavior. The Advocate's defense (LDAP server configuration) is accurate but Harbor-side prevention is straightforward and absent.

---

### [TRACER] Evidence for H-01 (OIDC Nonce Replay + Userinfo Failure) -- 2026-03-27T10:45:06Z

**Reachability: PARTIAL**

Code path:
1. `src/core/controllers/oidc.go:110` -- state validation: `oc.Ctx.Request.URL.Query().Get("state") != oc.GetSession(stateKey)` -- state is session-bound; attacker must know victim's state value
2. SGap-2 confirmed: no nonce parameter is generated in `RedirectLogin` (oidc.go:80-104) and no nonce is verified in `Callback` (oidc.go:109-228); `ExchangeToken` at helper.go:204-207 has no nonce option in the opts slice
3. `src/core/controllers/oidc.go:133` -- `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` -- PKCE verifier silently dropped when session key absent (PH-02 confirmed)
4. `src/pkg/oidc/helper.go:296-310` -- userinfo fallback: `if local != nil && remote == nil { return local, nil }` at line 308 -- subject cross-validation at line 302 skipped when remote endpoint unavailable

Sanitizers on path:
- State parameter at oidc.go:110: effective if attacker cannot obtain the victim's session state value; requires a secondary leak (referrer, open redirect, etc.)
- The nonce absence does NOT allow replay without also bypassing the state check; the state check is a meaningful partial compensating control

CodeQL slice: DFD-3 covers OIDC callback flow including state check. State check is at the first gate.
On-demand query: none

**Assessment**: PARTIAL. Both SGap-2 (nonce absence) and the userinfo fallback path (PH-13) are confirmed in code. However, the state parameter creates a barrier that prevents trivial replay. The chained attack requires leaking the victim's OIDC state value, which demands an additional exploit. Not a standalone reachable path.

---

### [TRACER] Evidence for H-02 (Auth Mode Switch Race -- LDAP-to-OIDC Ghost Admin) -- 2026-03-27T10:45:07Z

**Reachability: REACHABLE**

Code path:
1. User authenticates via LDAP; session populated via `PopulateUserSession`
2. `src/core/api/base.go:168` -- `b.SetSession(userSessionKey, u)` -- stores full `models.User` struct (with `GroupIDs`, `AdminRoleInAuth`) in Redis session
3. Admin switches auth mode via `PUT /api/v2.0/configurations` -- no session invalidation step exists in the configuration change handler
4. User's session cookie remains valid; on next request `session.Generate` fires
5. `src/server/middleware/security/session.go:38` -- `store.Get(req.Context(), "user")` -- retrieves stale `models.User` from Redis with no auth mode check
6. `src/server/middleware/security/session.go:48` -- `local.NewSecurityContext(&user)` -- creates security context from stale user; `AdminRoleInAuth` from LDAP group is preserved

Sanitizers on path:
- `session.Generate` at session.go:31-49: NO call to `lib.GetAuthMode()`; generator does not validate that the current system auth mode matches the mode under which the session was created
- Session TTL is the only expiry mechanism; no forced invalidation on auth mode change

CodeQL slice: no dedicated slice. CodeQL: unavailable.
On-demand query: none

**Assessment**: REACHABLE. `session.Generate` is confirmed to perform zero auth mode re-validation. Any `models.User` stored in the Redis session retains its privileges until session expiry regardless of system auth mode changes. An attacker with an active LDAP session that granted `AdminRoleInAuth=true` retains admin access after the system switches to OIDC mode.

---

### [TRACER] Evidence for H-03 (Redis Session Poisoning + LDAP Null Bind = Zero-Credential Admin) -- 2026-03-27T10:45:08Z

**Reachability: REACHABLE**

Code path (OIDC variant, primary):
1. Attacker connects to Redis on internal network (unauthenticated default)
2. Creates beego session entry with crafted `oidc_user_info` JSON containing `admin_group_member: true`
3. `src/core/controllers/oidc.go:376-395` -- `Onboard` handler trusts session data verbatim (confirmed in H-00d trace above)
4. Harbor system admin account created without any credential knowledge

Code path (LDAP chained variant):
1. Attacker sends LDAP login with known username and empty password (null bind succeeds per H-00f)
2. Valid Harbor session obtained as target LDAP user
3. Attacker overwrites that session's `models.User` in Redis, setting `AdminRoleInAuth: true`
4. `session.Generate` creates admin security context on next request (per H-02 trace above)

Sanitizers on path:
- Redis authentication: only effective if configured; default deployment has none
- OIDC token re-verification in `Onboard`: absent (oidc.go:376-395 confirmed)

CodeQL slice: DFD-3 partial for OIDC variant. CodeQL: unavailable for Redis write primitives.
On-demand query: none

**Assessment**: REACHABLE for both variants when Redis is unauthenticated. This hypothesis correctly chains H-00d (OIDC onboard trust) with H-00f (null bind) into a compound zero-credential path. Each component is independently confirmed. The LDAP chain requires both null-bind-permissive LDAP and unauthenticated Redis simultaneously.

---

### [TRACER] Evidence for H-04 (FixEmptySubIss Startup Injection via Unsigned JWT) -- 2026-03-27T10:45:09Z

**Reachability: PARTIAL**

Code path:
1. SQL injection primitive writes to `oidc_user.token` column (prerequisite; DFD-1 has 44 confirmed fmt.Sprintf->SQL flows, current exploitability MEDIUM)
2. `src/core/main.go:282` -- `oidc.FixEmptySubIss(orm.Context())` called unconditionally at Harbor core startup
3. `src/pkg/oidc/fix.go:35` -- `metaMgr.GetBySubIss(ctx, "", "")` -- queries for records with empty `subiss`; processes first matching record
4. `src/pkg/oidc/fix.go:47` -- `utils.ReversibleDecrypt(meta.Token, key)` -- decrypts token; if attacker wrote a `<enc-v1>`-prefixed value, this requires the AES key; if without prefix, falls back to base64 decode (PH-24 path)
5. `src/pkg/oidc/fix.go:57-63` -- JWT split on `.`, base64-decode `parts[1]` WITHOUT calling `VerifyToken` or `verifyTokenWithConfig` -- signature is never checked
6. `src/pkg/oidc/fix.go:74-80` -- `p.Subject + p.Issuer` written to `oidc_user.subiss` -- rebinds OIDC identity for the affected user record

Sanitizers on path:
- `utils.ReversibleDecrypt` at fix.go:47: AES decryption requires the Harbor secret key; attacker writing raw base64-prefixed value can bypass via the PH-24 legacy fallback
- JWT signature NOT verified: confirmed by absence of any `VerifyToken`/`verifyTokenWithConfig` call in fix.go
- SQL write prerequisite: MEDIUM exploitability per CodeQL DFD-1

CodeQL slice: DFD-1 for SQL injection; no slice for FixEmptySubIss. CodeQL: unavailable for startup routine.
On-demand query: none

**Assessment**: PARTIAL. The unsigned JWT parsing in fix.go:57-63 is confirmed code-level: `base64.RawURLDecoding` of JWT payload with no signature verification. Full exploitation requires a SQL write primitive to `oidc_user.token` AND either the AES key or use of the PH-24 base64 fallback AND a Harbor core restart. The compound preconditions reduce exploitability, but the chain is structurally valid.

---

### [TRACER] Evidence for H-05 (V2 Token Scope Escalation via Project Name Collision) -- 2026-03-27T10:45:10Z

**Reachability: UNREACHABLE**

Code path:
1. `src/server/middleware/security/v2_token.go:83-100` -- `tokenIssuedAfterProjectCreation` called for all V2 token validations
2. `src/server/middleware/security/v2_token.go:85` -- `if info.ProjectName == ""` returns `true` (bypass) ONLY when `ArtifactInfo.ProjectName` is empty -- happens for `/v2/` and `/_catalog` where no repository context is set
3. For push to recreated project (`PUT /v2/foo/image/manifests/latest`): `lib.GetArtifactInfo(ctx).ProjectName` = `"foo"` (non-empty, set by ArtifactInfo middleware)
4. `src/server/middleware/security/v2_token.go:88-98` -- `project_ctl.Ctl.GetByName(ctx, "foo")` retrieves new project; `iat.Add(common.JwtLeeway).Before(p.CreationTime)` evaluates true for a stale token -- returns `false` -- request rejected
5. Stale token authenticated at `/v2/` does not carry over authorization to scoped repository operations

Sanitizers on path:
- `tokenIssuedAfterProjectCreation` with `ProjectName != ""` correctly rejects stale tokens for all repository-scoped operations
- The `ArtifactInfo` middleware reliably populates `ProjectName` for any path that includes a repository reference

CodeQL slice: no dedicated slice. CodeQL: unavailable.
On-demand query: none

**Assessment**: UNREACHABLE. For any actual repository operation on the recreated project, `ProjectName` is non-empty and the timestamp check fires correctly. The bypass at `/v2/` is limited to the discovery endpoint and does not extend authorization to scoped repository pushes. PH-03 correctly describes the bypass scope as limited to `/v2/` and `/_catalog` only.

---

### [TRACER] Evidence for H-06 (Auth Proxy Header Injection via OIDC Username) -- 2026-03-27T10:45:11Z

**Reachability: PARTIAL**

Code path:
1. `src/server/middleware/security/auth_proxy.go:41` -- `authProxy.Generate` activates ONLY for `/v2` path prefix; does not process `/api/` or `/c/` paths
2. `src/server/middleware/security/auth_proxy.go:44` -- reads `Authorization: Basic` header (standard basic auth), NOT an `X-Auth-User` header
3. `src/server/middleware/security/auth_proxy.go:48` -- `matchAuthProxyUserName` requires `tokenreview$` prefix (defined at `src/common/const.go:149` as `AuthProxyUserNamePrefix = "tokenreview$"`)
4. `src/server/middleware/security/auth_proxy.go:58` -- `authproxy.TokenReview(proxyPwd, httpAuthProxyConf)` -- sends token to external `TokenReviewEndpoint` for Kubernetes-style verification
5. `src/server/middleware/security/auth_proxy.go:63` -- `rawUserName != tokenReviewStatus.User.Username` -- cross-validates stripped username against TokenReview response

Sanitizers on path:
- `tokenreview$` prefix check at auth_proxy.go:48: meaningful separator; regular users cannot register with this prefix IF Harbor's user registration enforces the exclusion (not verified in this trace)
- TokenReview cross-validation at auth_proxy.go:63: requires external TokenReview endpoint to confirm the username; if the endpoint is malicious/misconfigured, this gate fails entirely

CodeQL slice: CFD-1 covers auth proxy redirect (SAST-001 open redirect at authproxy_redirect.go:77); does not cover the `auth_proxy.Generate` path traced here.
On-demand query: none

**Assessment**: PARTIAL. The hypothesis misidentifies the header mechanism (it is Basic auth, not X-Auth-User). The `tokenreview$` prefix guard is a real separator. The cross-validation with the TokenReview endpoint is the primary security control. Exploitation requires either: (a) control over the TokenReview endpoint response, OR (b) ability to register a Harbor username starting with `tokenreview$` (which would need verification of Harbor's registration validation). The Advocate's assessment that this is a trust boundary issue (misconfigured TokenReview endpoint) is accurate.

---

### [TRACER] Evidence for H-07 (OIDC CLI Timing Oracle) -- 2026-03-27T10:45:12Z

**Reachability: REACHABLE**

Code path:
1. `src/server/middleware/security/oidc_cli.go:66` -- `u, err := uctl.GetByName(ctx, username)` -- DB lookup for user; returns error if not found
2. `src/server/middleware/security/oidc_cli.go:67-70` -- on error: logs and returns `nil` immediately -- **fast exit path**; no crypto operations performed
3. `src/server/middleware/security/oidc_cli.go:72` -- `oidc.VerifySecret(ctx, username, secret)` -- only reached if user was found in DB
4. `src/pkg/oidc/secret.go:88` -- `dm.metaDao.GetByUsername(ctx, username)` -- second DB lookup for OIDC metadata
5. `src/pkg/oidc/secret.go:95-102` -- `keyLoader.encryptKey()` + `utils.ReversibleDecrypt(oidcUser.Secret, key)` -- AES-256 decryption
6. `src/pkg/oidc/secret.go:103` -- `if secret != plainSecret` -- Go string equality `!=` operator; NOT `subtle.ConstantTimeCompare`

Sanitizers on path:
- No rate limiting on OIDC CLI authentication (`oidcCli.Generate` has no lockout; robot.go lockout applies to robot path only)
- No artificial delay or jitter to normalize timing between found/not-found paths
- Non-constant-time comparison at secret.go:103 confirmed

CodeQL slice: no dedicated slice. CodeQL: unavailable for timing analysis.
On-demand query: none

**Assessment**: REACHABLE. The timing differential is confirmed at two points: (1) fast exit at oidc_cli.go:67-70 when user not found (no crypto) vs. slow path through VerifySecret (DB read + AES decrypt + string compare); (2) non-constant-time comparison at secret.go:103. Practical exploitability depends on network conditions per the Advocate's brief. The oracle is real and exploitable in low-latency environments (same datacenter/VPC). No rate limiting exists on this path.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-00a (PH-01/PH-06) -- 2026-03-27T11:00:00Z

**Prosecution summary**: Admin account permanently authenticates via DB credentials regardless of OIDC/LDAP mode config (`IsSuperUser` override at authenticator.go:142). Per-process lockout uses in-memory map with no Redis sync, bypassed in multi-instance HA deployments by distributing requests across pods. Tracer confirmed full code path with no distributed lockout mechanism.

**Defense summary**: Per-process lockout (5 attempts, 5-min freeze, 1.5s sleep) provides real single-instance protection. Admin password can be set strong. SECURITY.md acknowledges non-secure-by-default settings. Pattern 6 (config-as-vuln) is the strongest defense but does not close the structural gap.

**Pre-FP Gate**: all checks passed
- Attacker control verified by Tracer: HTTP Basic Auth, fully attacker-controlled
- Framework protection searched by Advocate: all 5 layers, no blocking distributed lockout found
- Trust boundary crossing confirmed: External network -> admin auth
- Normal attacker position: Yes, external network
- Production code: Yes, ships in all deployments

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: The forced DB auth for admin combined with per-process-only lockout creates a permanently brute-forceable attack surface in HA deployments, confirmed by Tracer evidence of the unconditional IsSuperUser bypass at authenticator.go:142 and Advocate's inability to find any distributed lockout mechanism despite exhaustive 5-layer search.

**Finding draft written to**: security/findings-draft/p8-001-admin-db-auth-brute-force.md
**Registry updated**: AP-001 In-Memory-Only Auth Lockout

---

### [SYNTHESIZER] Verdict for H-00b (PH-04) -- 2026-03-27T11:01:00Z

**Prosecution summary**: OIDC admin group check at helper.go:396 uses raw unfiltered groups from claims. GroupFilter regex only applied in populateGroupsDB (line 455), not before the admin check. Tracer confirmed no filterGroup call exists between groupsFromClaims and AdminGroupMember assignment.

**Defense summary**: Requires compromised/malicious OIDC provider (elevated position). AdminGroup must be configured (empty disables attack). go-oidc verifies token signatures (blocks fake providers). The trust-the-IdP model is inherent to federated auth.

**Pre-FP Gate**: all checks passed
- Attacker control verified by Tracer: OIDC groups claim, confirmed unfiltered
- Framework protection searched by Advocate: go-oidc signature verification blocks fake providers, but not compromised configured providers
- Trust boundary crossing confirmed: OIDC provider -> Harbor admin role
- Attacker position: Requires OIDC provider compromise (elevated but realistic)
- Production code: Yes

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: The GroupFilter bypass is a confirmed implementation bug -- filterGroup is applied to DB groups but NOT to the admin role check, violating operator expectations. Advocate correctly notes the elevated precondition but cannot disprove the filter ordering gap.

**Finding draft written to**: security/findings-draft/p8-002-oidc-admin-group-filter-bypass.md
**Registry updated**: AP-002 Filter-Before-Check Ordering Bug

---

### [SYNTHESIZER] Verdict for H-00c+H-00d (PH-07+PH-19 Redis Chain) -- 2026-03-27T11:02:00Z

**Prosecution summary**: Full OIDC refresh tokens stored in Redis session without encryption (oidc.go:161-166, gob encoding only). Onboard handler trusts session-stored user info without OIDC re-verification (oidc.go:376-395). Single precondition (unauthenticated Redis on default deployment) enables both mass token theft and arbitrary admin account creation.

**Defense summary**: Redis on internal Docker network, not port-mapped by default. Cookie signing protects cookie in transit but not Redis values. Session uses gobCodec (no encryption). Redis auth is configurable but not default.

**Pre-FP Gate**: all checks passed
- Attacker control verified by Tracer: Redis read/write confirmed unencrypted
- Framework protection searched by Advocate: no session encryption, no HMAC, no re-verification
- Trust boundary crossing confirmed: Internal network -> OIDC tokens + admin creation
- Attacker position: Internal network access (common in k8s, shared infra)
- Production code: Yes, default deployment

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Single precondition (internal network Redis access) enables dual high-impact outcomes confirmed by Tracer end-to-end code path at oidc.go:161-166 (token storage) and oidc.go:376-395 (onboard trust). Advocate found only network isolation as defense, with no application-level integrity protection.

**Finding draft written to**: security/findings-draft/p8-003-redis-session-token-theft-admin-creation.md
**Registry updated**: AP-003 Unauthenticated-State-Store Trust

---

### [SYNTHESIZER] Verdict for H-00e (PH-25) -- 2026-03-27T11:03:00Z

**Prosecution summary**: Nginx config confirmed to lack any `proxy_set_header Authorization ""` directive across all location blocks. External requests with `Authorization: Harbor-Secret <value>` pass through unmodified. Secret auth is priority 1 in the auth chain, granting full internal trust.

**Defense summary**: Secret is 32 hex chars from crypto/rand (128 bits entropy). Not guessable. No known leak vector identified. CORE_SECRET env var is internal. Harbor-Secret prefix is public but the value is the only gate.

**Pre-FP Gate**: all checks passed (conditional exploitability noted)
- Attacker control verified by Tracer: HTTP header, conditional on secret knowledge
- Framework protection searched by Advocate: strong secret generation confirmed, but no Nginx-level stripping
- Trust boundary crossing confirmed: External -> internal trust (conditional)
- Attacker position: Requires secret knowledge (very elevated)
- Production code: Yes

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Missing Nginx header stripping is a confirmed defense-in-depth failure (Tracer verified across all 5 Nginx location blocks), but Advocate correctly demonstrates the 128-bit entropy secret is a practical blocking precondition, warranting MEDIUM. Any future secret leak immediately escalates to CRITICAL.

**Finding draft written to**: security/findings-draft/p8-004-nginx-harbor-secret-header-passthrough.md
**Registry updated**: AP-004 Missing-Header-Stripping Defense-in-Depth

---

### [SYNTHESIZER] Verdict for H-00f (PH-26) -- 2026-03-27T11:04:00Z

**Prosecution summary**: No empty password check before `ldapSession.Bind(dn, m.Password)` at ldap.go:87. Username check exists at ldap.go:57. `ErrEmptyPassword` sentinel declared at ldap.go:39 but unused in auth path. Empty password passed directly to LDAP server.

**Defense summary**: LDAP server may reject null binds (AD with `disallowAnonBind`, OpenLDAP with explicit config). Harbor should not rely on external server config per RFC 4511.

**Pre-FP Gate**: all checks passed
- Attacker control verified by Tracer: empty password in login request, confirmed no check
- Framework protection searched by Advocate: username check present, password check absent, no alternative
- Trust boundary crossing confirmed: External -> authenticated session
- Attacker position: Normal network attacker
- Production code: Yes, LDAP auth mode

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Missing empty password check is a clear RFC 4511 violation. The unused ErrEmptyPassword sentinel error suggests the developer was aware of the need but the check was never implemented. Advocate found no Harbor-side protection.

**Finding draft written to**: security/findings-draft/p8-005-ldap-null-bind-auth-bypass.md
**Registry updated**: AP-005 LDAP Null Bind Missing Guard

---

### [SYNTHESIZER] Verdict for H-01 (Nonce Replay + Userinfo Chain) -- 2026-03-27T11:05:00Z

**Prosecution summary**: No nonce generated in RedirectLogin, no nonce in AuthCodeURL, no nonce validated in VerifyToken. Userinfo failure bypasses subject cross-validation. Chain theoretically enables session hijack.

**Defense summary**: State parameter binds callback to session (effective CSRF protection). Authorization codes are one-time-use. Chain requires three independent elevated preconditions (code interception, race to exchange, userinfo failure simultaneously). The missing nonce is a spec gap but does not enable standalone replay in authorization code flow.

**Pre-FP Gate**: failed on check-3 for chain: trust boundary crossing requires MITM to OIDC provider in auth code flow.

**Verdict: VALID (nonce gap standalone; chain DROP)**
**Severity: MEDIUM**
**Rationale**: The missing nonce is a confirmed OIDC Core 1.0 Section 3.1.2.1 spec compliance gap verified by Tracer across RedirectLogin/AuthCodeURL/VerifyToken. The chain is impractical per Advocate's defense (auth code flow, one-time codes, state parameter). Written as standalone nonce spec compliance finding.

**Finding draft written to**: security/findings-draft/p8-006-oidc-nonce-not-bound.md
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-02 (Auth Mode Switch Race) -- 2026-03-27T11:06:00Z

**Prosecution summary**: Session persists across auth mode changes. `session.Generate` does not check current auth mode. LDAP-derived admin flag in DB persists into OIDC mode.

**Defense summary**: Admin flags are sticky by design in Harbor. `SysAdminFlag` is a DB column that persists regardless of auth mode. Changing auth mode is an admin action -- reviewing user roles is admin responsibility. Tracer confirms the code path is reachable but the Advocate correctly identifies this as by-design behavior.

**Pre-FP Gate**: failed on check-3: no trust boundary crossing -- stale admin is same principal with same DB-persisted role.

**Verdict: DROP**
**Rationale**: Both Tracer and Advocate agree this is expected behavior. Admin flags are DB-persistent by design. Session persistence across mode changes is consistent with Harbor's session model. Administrative responsibility applies.

---

### [SYNTHESIZER] Verdict for H-03 (Redis + LDAP Chain) -- 2026-03-27T11:07:00Z

**Verdict: DUPLICATE**
**Rationale**: This is a deployment scenario combining H-00c/d (Redis) and H-00f (null bind). No new code path. Each component is covered by its own finding. The chain amplification is noted in the H-00c+d finding draft.

---

### [SYNTHESIZER] Verdict for H-04 (FixEmptySubIss Startup Injection) -- 2026-03-27T11:08:00Z

**Prosecution summary**: `FixEmptySubIss` parses JWT without signature verification (fix.go:57-63). Unsigned claims written to `oidc_user.subiss`, rebinding OIDC identity.

**Defense summary**: Requires SQL injection to write to `oidc_user.token` (separate vulnerability class). Also requires AES key or base64 fallback exploitation. Only processes records with empty subiss. Harbor core restart needed.

**Pre-FP Gate**: failed on check-4: requires SQL injection (entirely different vulnerability class, not normal attacker position for auth chamber)

**Verdict: DROP**
**Rationale**: The unsigned JWT parsing in fix.go is a real code-level concern, but exploitation requires a SQL injection primitive that is outside this chamber's scope. Noted as a severity amplifier for any SQL injection findings in Chamber 02/03. The finding would be MEDIUM if SQL injection is confirmed.

---

### [SYNTHESIZER] Verdict for H-05 (V2 Token Scope Escalation) -- 2026-03-27T11:09:00Z

**Verdict: DROP**
**Rationale**: UNREACHABLE. Tracer confirmed that `tokenIssuedAfterProjectCreation` IS enforced for all scoped resource operations where `ProjectName != ""`. The bypass at `/v2/` base and `/_catalog` is limited to discovery endpoints with no write/read capability on project resources.

---

### [SYNTHESIZER] Verdict for H-06 (Auth Proxy Header Injection) -- 2026-03-27T11:10:00Z

**Verdict: DROP**
**Rationale**: Tracer demonstrated the hypothesis was based on incorrect assumptions. Auth proxy uses BasicAuth + TokenReview validation (not header trust). It only activates in HTTPAuth mode, requires `tokenreview$` prefix, and cross-validates username against TokenReview response.

---

### [SYNTHESIZER] Verdict for H-07 (OIDC CLI Timing Oracle) -- 2026-03-27T11:11:00Z

**Verdict: DROP**
**Rationale**: LOW severity. Timing differential confirmed (fast exit on user-not-found vs. slow AES decrypt path), with non-constant-time comparison at secret.go:103. However, username enumeration alone is below the MEDIUM threshold for finding drafts. Network jitter in production environments significantly reduces practical exploitability.

---

### [SYNTHESIZER] Additional Spec Gap and Probe Verdicts

#### SGap-3: ID Token Expiry Skipped -- 2026-03-27T11:12:00Z

**Prosecution summary**: `parseIDToken` at helper.go:214 uses `SkipExpiryCheck: true`. Expired ID tokens accepted for claim extraction in OIDC CLI path.

**Defense summary**: Actual authentication relies on OIDC provider refresh token validation. Expiry skip is intentional for stored token claim extraction. Risk limited to stale group/admin claims when refresh succeeds but new ID token has different claims.

**Pre-FP Gate**: all checks passed (limited impact scope)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed RFC 7519 / OIDC Core spec compliance gap. Limited practical impact because actual auth relies on refresh token validity at the OIDC provider.

**Finding draft written to**: security/findings-draft/p8-007-oidc-id-token-expiry-skipped.md

---

#### SGap-7: OIDC Onboard Username URL Injection -- 2026-03-27T11:13:00Z

**Prosecution summary**: Username interpolated without `url.QueryEscape()` at oidc.go:203. Characters `&`, `=`, `?`, `#` pass through into redirect URL, enabling query parameter injection.

**Defense summary**: Onboard handler validates username for account creation (length + illegal chars). Impact limited to redirect URL parameter manipulation. Requires controlled OIDC provider + first-time user onboarding.

**Pre-FP Gate**: all checks passed (narrow scenario)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed missing URL encoding with open redirect potential at onboard step. Narrow attack scenario (new user + controlled IdP) limits practical impact.

**Finding draft written to**: security/findings-draft/p8-008-oidc-onboard-url-injection.md

---

#### PH-15/PH-21: Robot Account No Brute Force Protection -- 2026-03-27T11:14:00Z

**Prosecution summary**: `robot.Generate` has no rate limiting, lockout, or sleep. SHA256 single-hash (not bcrypt/argon2). Robot names follow predictable `robot$` pattern. No rate limiting middleware for `/v2/` or `/service/token`.

**Defense summary**: Robot secrets are randomly generated with sufficient entropy. Online brute force against high-entropy random strings is impractical.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Defense-in-depth failure -- complete absence of rate limiting for robot accounts despite lockout existing for human accounts. Random secret generation provides practical protection, keeping severity at MEDIUM.

**Finding draft written to**: security/findings-draft/p8-009-robot-account-no-brute-force-protection.md
**Registry updated**: AP-006 Missing-Rate-Limit on Service Accounts

---

#### PH-02: PKCE Silent Downgrade -- 2026-03-27T11:15:00Z

**Prosecution summary**: Type assertion at oidc.go:133 `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` silently produces empty string on failure. `helper.go:203-206` skips PKCE verifier when length is zero. Token exchange proceeds without `code_verifier`.

**Defense summary**: State parameter provides CSRF protection. Many OIDC providers enforce PKCE server-side (reject exchanges without verifier). Requires session absence (natural or adversarial via Redis).

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed silent PKCE downgrade code defect. State parameter and provider-side PKCE enforcement provide partial mitigations per Advocate, keeping at MEDIUM.

**Finding draft written to**: security/findings-draft/p8-010-oidc-pkce-silent-downgrade.md

---

#### PH-24: Legacy Base64 Token Storage -- 2026-03-27T11:16:00Z

**Prosecution summary**: `ReversibleDecrypt` at encrypt.go:82 falls back to base64 decode for records without `<enc-v1>` prefix. Legacy `oidc_user` records from pre-encryption versions store OIDC tokens as base64 without AES.

**Defense summary**: Requires DB read access (elevated). Only affects instances upgraded from pre-encryption versions. New records use AES.

**Pre-FP Gate**: all checks passed (elevated precondition + narrow scope)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Residual encryption migration risk in upgraded instances. DB access is an elevated precondition limiting exploitability.

**Finding draft written to**: security/findings-draft/p8-011-legacy-oidc-token-base64-storage.md
**Registry updated**: AP-007 Encryption-Migration Residual Plaintext

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00a (PH-01/PH-06) Admin DB Auth Brute Force | VALID | HIGH | p8-001-admin-db-auth-brute-force.md |
| H-00b (PH-04) OIDC Admin Group Filter Bypass | VALID | HIGH | p8-002-oidc-admin-group-filter-bypass.md |
| H-00c+d (PH-07+19) Redis Session Chain | VALID | HIGH | p8-003-redis-session-token-theft-admin-creation.md |
| H-00e (PH-25) Nginx Harbor-Secret Passthrough | VALID | MEDIUM | p8-004-nginx-harbor-secret-header-passthrough.md |
| H-00f (PH-26) LDAP Null Bind Bypass | VALID | HIGH | p8-005-ldap-null-bind-auth-bypass.md |
| H-01 OIDC Nonce Not Bound (standalone) | VALID | MEDIUM | p8-006-oidc-nonce-not-bound.md |
| H-02 Auth Mode Switch Race | DROP | -- | -- |
| H-03 Redis+LDAP Chain | DUPLICATE | -- | -- |
| H-04 FixEmptySubIss | DROP | -- | -- |
| H-05 V2 Token Scope Escalation | DROP | -- | -- |
| H-06 Auth Proxy Header Injection | DROP | -- | -- |
| H-07 OIDC CLI Timing Oracle | DROP | -- | -- |
| SGap-3 ID Token Expiry Skipped | VALID | MEDIUM | p8-007-oidc-id-token-expiry-skipped.md |
| SGap-7 OIDC Onboard URL Injection | VALID | MEDIUM | p8-008-oidc-onboard-url-injection.md |
| PH-15/21 Robot Account Brute Force | VALID | MEDIUM | p8-009-robot-account-no-brute-force-protection.md |
| PH-02 PKCE Silent Downgrade | VALID | MEDIUM | p8-010-oidc-pkce-silent-downgrade.md |
| PH-24 Legacy Base64 Token Storage | VALID | MEDIUM | p8-011-legacy-oidc-token-base64-storage.md |

Findings written: 11
Patterns added to registry: 7 (AP-001 through AP-007)
Variant candidates: 0

Chamber closed: 2026-03-27T11:20:00Z
