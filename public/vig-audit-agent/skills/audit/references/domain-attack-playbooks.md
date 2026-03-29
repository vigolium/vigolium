# Domain-Specific Attack Playbooks

Reference for Mode C of Phase 3 Domain Attack Research. Provides per-domain attack patterns,
research signals, and mapping to testing skills.

---

## Domain Identification Signals

Trigger Mode C when any of the following are detected during Phase 3 Steps 1-2:

| Signal | Where to look | Example trigger |
|--------|--------------|-----------------|
| Protocol/format keyword in project name or description | README, package.json, go.mod, Cargo.toml | "saml", "oauth", "jwt", "grpc", "graphql", "mqtt" |
| RFC/spec listed in `## Specs and RFCs Implemented` | Phase 3 Step 2 output | RFC 6749, RFC 7519, RFC 9110 |
| Security-sensitive library in dependencies | manifests, lockfiles | xmlsec, python-jose, openssl, bouncycastle, pyyaml, pickle |
| Transport, storage, or compute type in architecture inventory | Phase 3 Step 2 | WebSocket, gRPC, Kafka, Redis, S3, Lambda, Docker |
| Project type is `protocol`, `library`, `plugin`, `CI action` | Step 1 classification | OIDC provider, SAML SP, image processor, template renderer |
| Auth/crypto/parsing/rendering in component names | DFD slices | `SAMLValidator`, `OAuthHandler`, `TemplateEngine`, `PDFRenderer` |
| Keyword in source files | grep across codebase | `subprocess`, `eval`, `pickle.loads`, `Template(`, `innerHTML` |
| Cloud provider SDK import | imports, dependencies | boto3, google-cloud, azure-sdk, @aws-sdk |
| AI/ML framework import | imports, dependencies | openai, anthropic, transformers, langchain, torch |

Produce a list of identified domains at the top of the `## Domain Attack Research` section.

---

## Research Action Sequence

For each identified domain, perform in order:

1. **Web search** — search for `"<domain> known attacks"`, `"<domain> security vulnerabilities"`,
   `"<domain> CVE analysis"`, `"<domain> implementation pitfalls"`. Use `WebSearch` and `WebFetch`.

2. **`last30days` skill** — invoke with query `"<domain> security vulnerability attack bypass"` to
   surface recent CVE discussions, bypass technique posts, and new attack research.

3. **`wooyun-legacy` skill** (conditional) — invoke only when the domain intersects with web
   application security (HTTP, auth, session, XML, file handling). See per-domain mapping below.

4. **MCP tools** (best-effort) — use `mcp__docker-gateway__perplexity_research`,
   `mcp__docker-gateway__tavily_research`, or `mcp__docker-gateway__brave_web_search` for deeper
   technical research when available. Fall back to `WebSearch` if MCP tools are unavailable.

5. **Build attack taxonomy** — classify each discovered attack by: attack class, prerequisites,
   detection strategy, SAST detectability (yes/no/partial), and relevance to this project's
   implementation.

---

## Output Format

The `## Domain Attack Research` section in `security/knowledge-base-report.md` must include,
for each identified domain, the following subsection:

```markdown
### Domain: <name>

**Identified via:** <signal — e.g., "RFC 7519 listed in Specs, go-jose dependency">

**Known attack classes:**

| Attack | Description | Detection strategy | Relevance |
|--------|-------------|-------------------|-----------|
| <name> | <brief> | <how to detect in code> | High/Med/Low |

**Custom SAST targets:**

| Attack pattern | Rule type | Source/sink or pattern | Priority |
|---------------|-----------|----------------------|----------|
| <name> | CodeQL / Semgrep | <what to model> | High/Med/Low |

**Manual review checklist:**
- [ ] <concrete check tied to this project's implementation>

**Research sources used:** last30days, wooyun-legacy (<checklist>), web search, MCP
```

---

## Per-Domain Templates

---

### Authentication & Authorization Protocols

---

#### SAML

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `xxe-checklist.md`
**Key search terms:** `SAML XML signature wrapping`, `SAML assertion forgery`, `SAML comment injection`, `SAML roundtrip`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| XML Signature Wrapping (XSW) | Signed element moved; unsigned clone used | Assertion extraction happens on the same node as sig verification | Partial |
| Comment injection | XML comment splits identity (`admin<!---->.evil`) | Username extraction strips XML comments | Yes |
| SAML roundtrip | Parse→serialize→re-parse yields different assertion | No re-parse after serialization in auth flow | No |
| Unsigned assertion acceptance | SP accepts assertions without valid signature | Every code path verifying an assertion requires valid sig | Yes |
| InResponseTo bypass | Response replayed by spoofing/omitting InResponseTo | SP tracks issued IDs and validates InResponseTo | Yes |
| XML External Entity (XXE) | DTD-based SSRF or file read via XML parser | Parser disables external entity resolution | Yes |
| Destination validation bypass | SP accepts assertion intended for another SP | Destination attribute validated against known SP URLs | Yes |

**Manual review checklist:**
- [ ] Signature verification uses the same node reference that assertion extraction uses
- [ ] Parser entity resolution disabled; DTD processing disabled
- [ ] InResponseTo bound to request ID and checked for replay
- [ ] Destination and Recipient attributes validated against known values
- [ ] NameID extracted after signature validation, not before
- [ ] SubjectConfirmationData NotOnOrAfter enforced

---

#### OAuth 2.0 / OIDC

**Wooyun-legacy:** `csrf-checklist.md`, `logic-flaws-checklist.md`, `ssrf-checklist.md`
**Key search terms:** `OAuth redirect_uri bypass`, `OAuth mix-up attack`, `PKCE downgrade`, `OIDC nonce bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| redirect_uri bypass | Prefix match, subdomain, open redirect | Exact match or strict per-client allowlist | Yes |
| State CSRF | Missing/non-validated `state` on callback | State generated, stored server-side, verified on callback | Yes |
| Mix-up attack | Attacker substitutes a different AS's code | `iss` claim validated; AS metadata bound to session | No |
| PKCE downgrade | Server accepts code without PKCE when client sent challenge | Server enforces PKCE when challenge was registered | Yes |
| Token leakage via referrer | Token in URL ends up in Referer | Tokens not in URL query strings | Yes |
| Scope escalation | Scope not re-validated at resource access | Scope recorded at issuance and re-validated | Yes |
| OIDC nonce bypass | Nonce not validated in ID token | Nonce bound to request and verified in ID token | Yes |
| Authorization code replay | Code used more than once | One-time code invalidated after first exchange | Yes |

**Manual review checklist:**
- [ ] redirect_uri exact-match against per-client allowlist (no prefix/regex)
- [ ] state is cryptographically random, stored server-side, verified on callback
- [ ] PKCE enforced for public clients (S256 required)
- [ ] Token endpoint authenticates client before issuing tokens
- [ ] Authorization codes invalidated after first use

---

#### JWT / JWS / JWE

**Wooyun-legacy:** `unauthorized-access-checklist.md`
**Key search terms:** `JWT algorithm confusion`, `alg none attack`, `JWT kid injection`, `JKU substitution`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Algorithm confusion RS256→HS256 | Public key used as HMAC secret | Algorithm allowlisted, not taken from header | Yes |
| `alg: none` acceptance | Unsigned tokens accepted | `none` rejected unconditionally | Yes |
| `kid` header injection | `kid` used in SQL/path query unsanitized | `kid` lookup uses allowlist or constant key store | Yes |
| `jku`/`x5u` substitution | Attacker-supplied URL for key retrieval | Key URL validated against allowlist | Yes |
| Claim validation bypass | `exp`, `nbf`, `iss`, `aud` not validated | All mandatory claims validated before use | Yes |
| Embedded `jwk` attack | Server uses attacker-supplied `jwk` header | `jwk` header ignored; only pre-configured keys | Yes |
| Cross-service token reuse | Token for service A accepted by service B | `aud` validated and service-specific | Yes |

**Manual review checklist:**
- [ ] Algorithm validated against explicit allowlist; `none` never accepted
- [ ] `jku`, `x5u`, `jwk` headers ignored or validated against strict allowlist
- [ ] `kid` only indexes a pre-configured key store; never used in dynamic queries
- [ ] `exp`, `nbf`, `iss`, `aud` all validated on every token

---

#### Session Management

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `logic-flaws-checklist.md`
**Key search terms:** `session fixation attack`, `session riding`, `concurrent session confusion`, `insecure session storage`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Session fixation | Attacker sets a known session ID pre-auth | Session ID regenerated on privilege elevation | Yes |
| Insufficient session ID entropy | Short or guessable session IDs | Session ID is cryptographically random (≥128 bits) | Yes |
| Session not invalidated on logout | Server-side session survives logout | Session record deleted/invalidated on logout | Yes |
| Concurrent session not bounded | Unlimited parallel sessions per user | Concurrent session limit enforced | No |
| Session ID in URL | Session ID leaks via Referer/logs | Session ID only in cookie, never in URL | Yes |
| Missing Secure/HttpOnly/SameSite | Cookie flags absent | All session cookies have Secure, HttpOnly, SameSite=Lax/Strict | Yes |
| Absolute timeout missing | Sessions valid indefinitely | Absolute session lifetime enforced server-side | Yes |

**Manual review checklist:**
- [ ] Session ID regenerated on login, privilege change, and role switch
- [ ] Session invalidated server-side on logout (not just cookie deleted client-side)
- [ ] Session cookie has Secure, HttpOnly, SameSite attributes
- [ ] Absolute timeout (e.g., 8-24h) enforced regardless of activity

---

#### TOTP / MFA / OTP

**Wooyun-legacy:** `logic-flaws-checklist.md`
**Key search terms:** `TOTP bypass`, `OTP brute force`, `MFA fatigue attack`, `backup code security`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| OTP brute force | No rate limit on OTP submission | Rate limit and lockout on OTP attempts | Yes |
| OTP replay | Same OTP reused within validity window | Used OTPs invalidated immediately | Yes |
| Time window too large | TOTP accepted 10+ steps before/after | Window limited to ±1 step (30s) | Yes |
| Backup code exhaustion | Unlimited backup code attempts | Backup codes rate-limited and one-time | Yes |
| MFA fatigue (push) | Flood push notifications until accepted | Push notifications throttled and confirmable only once | No |
| TOTP secret in logs | Secret logged during QR code generation | TOTP secret never appears in logs | Yes |
| MFA bypass via account recovery | Recovery flow skips MFA | MFA re-enrolled after recovery | No |

**Manual review checklist:**
- [ ] OTP submissions rate-limited (e.g., 5 attempts then lockout)
- [ ] Used OTPs invalidated immediately; not reusable within validity window
- [ ] TOTP window is ±1 step (30s) maximum
- [ ] Backup codes are one-time and stored hashed

---

#### Password Hashing

**Wooyun-legacy:** `weak-password-checklist.md`
**Key search terms:** `bcrypt max length truncation`, `timing attack password verification`, `password hashing bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Weak algorithm | MD5/SHA1/SHA256 used directly | bcrypt/scrypt/argon2/PBKDF2 required | Yes |
| bcrypt 72-byte truncation | bcrypt silently truncates at 72 bytes | Pre-hash with SHA-512 or use argon2 | Yes |
| Timing side-channel | Non-constant-time comparison | `hmac.compare_digest` or equivalent | Yes |
| Insufficient work factor | Cost parameter too low (bcrypt < 10) | Work factor validated at startup | Yes |
| Plaintext password in logs | Password logged during auth failure | Password field never logged | Yes |
| Password not rehashed on login | Old weak hash not upgraded | Hash upgraded on successful login | Yes |

**Manual review checklist:**
- [ ] Password hashed with bcrypt (cost≥12), argon2id, or scrypt
- [ ] Comparison uses constant-time function
- [ ] Password never appears in logs, error messages, or serialized objects
- [ ] Hash work factor is configurable and validated at startup

---

### Web Technologies

---

#### Template Engines (Server-Side Template Injection)

**Wooyun-legacy:** `rce-checklist.md`, `xss-checklist.md`
**Key search terms:** `server-side template injection SSTI`, `Jinja2 SSTI`, `Twig SSTI`, `Handlebars template injection`, `Freemarker injection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| SSTI to RCE | User input rendered as template expression | User input never passed to template constructor or `render()` | Yes |
| Template sandbox escape | Sandbox bypassed via `__class__` chains | Sandbox configuration audited; object traversal blocked | No |
| Partial template injection | User controls only part of template string | Even partial user input in template source is dangerous | Yes |
| Client-side template injection | Angular/Vue/React expression evaluation | `ng-bind-html`, `v-html`, `dangerouslySetInnerHTML` audited | Yes |
| Template file path traversal | User controls which template file is loaded | Template loader restricts to safe directory | Yes |

**Manual review checklist:**
- [ ] User input is never passed to template constructors (`Template(user_input)`, `env.from_string(user_input)`)
- [ ] User input is only passed as template variables, not as template source
- [ ] Template file selection is from a fixed allowlist, not user-controlled paths
- [ ] Client-side template bindings (`v-html`, `dangerouslySetInnerHTML`) audited for user input

---

#### URL Parsing Differentials

**Wooyun-legacy:** `ssrf-checklist.md`, `path-traversal-checklist.md`
**Key search terms:** `URL parser differential bypass`, `open redirect bypass`, `SSRF filter bypass URL`, `URL confusion attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Parser differential | Security check uses parser A; fetch uses parser B | Single authoritative parser used for both | No |
| Scheme confusion | `javascript:`, `data:`, `vbscript:` bypass URL checks | Scheme validated against explicit allowlist | Yes |
| IPv6/IPv4 confusion | `http://[::1]` bypasses `127.0.0.1` blocklist | Both IPv4 and IPv6 loopback/private ranges blocked | Yes |
| URL shortener / redirect | Allowed URL redirects to blocked target | SSRF check follows redirects | No |
| Double encoding | `%252F` bypasses single-decode check | URL decoded once before security check | Yes |
| Host@authority confusion | `http://evil@trusted.com` | Userinfo stripped before allowlist check | Yes |
| Embedded newline / null byte | `host\nX-Header:` splits request | Headers stripped of `\r\n` and `\x00` | Yes |

**Manual review checklist:**
- [ ] URL scheme validated against explicit allowlist before any fetch
- [ ] Security check and fetch operation use the same URL parser
- [ ] Private/loopback IP ranges blocked for both IPv4 and IPv6
- [ ] Redirects followed and destination re-validated for SSRF

---

#### File Upload / Multipart Parsing

**Wooyun-legacy:** `file-upload-checklist.md`, `path-traversal-checklist.md`
**Key search terms:** `file upload bypass`, `polyglot file attack`, `multipart parsing confusion`, `MIME type bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Extension bypass | `.php.jpg` or null byte in filename | Extension validated after last dot; null bytes rejected | Yes |
| MIME confusion | Content-Type header spoofed | File content validated by magic bytes, not MIME header | Yes |
| Polyglot file | File valid in two formats simultaneously | Both format-specific checks applied | No |
| Path traversal in filename | `../../etc/passwd` in Content-Disposition | Filename sanitized; no path components allowed | Yes |
| Zip slip via upload | Archive entry escapes target directory | Extracted paths canonicalized and confined | Yes |
| Decompression bomb | Tiny upload expands to fill disk | Decompressed size bounded before extraction | Yes |
| Multipart boundary injection | Crafted boundary confuses parser | Framework-level multipart parser used; not custom | No |
| Web shell via upload | Executable file uploaded and served | Uploaded files served from non-executable storage | Yes |

**Manual review checklist:**
- [ ] File extension validated against allowlist (not blocklist) after last `.`
- [ ] File content validated by magic bytes or library, not Content-Type header
- [ ] Filenames stripped of path components and sanitized before storage
- [ ] Uploaded files stored outside webroot or served with `Content-Disposition: attachment`
- [ ] File size and decompressed size bounded

---

#### Image Processing

**Wooyun-legacy:** `ssrf-checklist.md`, `command-execution-checklist.md`
**Key search terms:** `ImageMagick vulnerability`, `PIL/Pillow security`, `image processing SSRF`, `ghostscript injection`, `libvips security`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| ImageMagick shell injection (CVE-2016-3714) | `|` or `https://` MSL commands in image | ImageMagick policy.xml restricts dangerous coders | Yes |
| SSRF via image fetch | Image URL fetched server-side | URL validated against SSRF allowlist before fetch | Yes |
| SVG/XML external entity | SVG parsed with XXE-vulnerable parser | SVG processing disabled or sandboxed | Yes |
| Pixel flood DoS | Malformed header claims 100k×100k image | Dimension limits enforced before decode | Yes |
| Format confusion | File reported as JPEG but parsed as PostScript | Format detection by magic bytes, not file extension | Yes |
| Ghostscript command injection | Postscript/PDF processed by Ghostscript | Ghostscript disabled in ImageMagick policy | Yes |
| Metadata exfiltration | EXIF/IPTC data returned to user unstripped | Metadata stripped before serving user-uploaded images | Yes |

**Manual review checklist:**
- [ ] ImageMagick `policy.xml` disables dangerous coders: PS, EPS, PDF, MSL, MVG, SVG, URL
- [ ] Image dimensions validated before allocation
- [ ] SVG rendering sandboxed or disabled
- [ ] User-uploaded images processed in a separate, network-isolated process

---

#### PDF Generation

**Wooyun-legacy:** `ssrf-checklist.md`, `xss-checklist.md`
**Key search terms:** `wkhtmltopdf SSRF`, `headless Chrome PDF injection`, `PDF generation XSS`, `iText injection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| SSRF via HTML renderer | `<iframe src="http://169.254.169.254/">` in user content | User content sanitized before PDF rendering; network disabled | Yes |
| Local file read | `<iframe src="file:///etc/passwd">` | `file://` protocol disabled in renderer | Yes |
| HTML/JS injection → PDF | User content rendered as HTML; JS executed | HTML sanitized; JS execution disabled in renderer | Yes |
| Redirect to internal resource | External HTML redirects to internal URL | Redirects disabled in renderer; URL allowlisted | No |
| CSS injection → data exfiltration | CSS `@import` fetches attacker URL | External resource loading disabled | Yes |

**Manual review checklist:**
- [ ] User-controlled content sanitized with strict HTML allowlist before PDF render
- [ ] PDF renderer network access disabled or allowlisted
- [ ] `file://` protocol disabled in renderer configuration
- [ ] JavaScript execution disabled in renderer

---

#### Markdown / Rich Text Parsers

**Wooyun-legacy:** `xss-checklist.md`
**Key search terms:** `Markdown XSS bypass`, `mXSS mutation XSS`, `CommonMark XSS`, `rich text sanitizer bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Raw HTML in Markdown | `<script>` or `<img onerror=...>` in Markdown source | Raw HTML disabled or sanitized after rendering | Yes |
| Mutation XSS (mXSS) | Sanitized HTML mutated by browser re-parse | Sanitizer applied after Markdown→HTML, not before | No |
| Link/image URL injection | `[text](javascript:alert(1))` | Link/image URL validated against scheme allowlist | Yes |
| LaTeX injection | `\input{}` or `\write18{}` in math blocks | LaTeX rendering sandboxed; dangerous commands blocked | No |
| Mention/link expansion | Auto-linked URLs trigger SSRF on preview | Server-side link expansion uses SSRF-safe fetch | Yes |

**Manual review checklist:**
- [ ] Raw HTML disabled in Markdown renderer or sanitized strictly after rendering
- [ ] Link/image URLs validated against scheme allowlist (no `javascript:`, `data:`, `vbscript:`)
- [ ] HTML sanitizer applied to final rendered output, not to raw Markdown input

---

#### Caching / Cache Poisoning

**Wooyun-legacy:** `misconfig-checklist.md`
**Key search terms:** `web cache poisoning`, `cache deception attack`, `cache key confusion`, `CDN cache poisoning`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Web cache poisoning | Unkeyed input (header/cookie) poisons cached response | Cache key includes all security-relevant inputs | No |
| Cache deception | Attacker tricks victim into caching their response at attacker URL | Sensitive responses marked `Cache-Control: no-store` | Yes |
| Cache key confusion | `X-Forwarded-Host` used in response but not cache key | Unkeyed headers stripped at CDN/proxy | No |
| Stored DOM XSS via cache | Attacker-controlled value persisted in cached JS/HTML | User content never stored in CDN-cached responses | No |
| Race condition in cache write | Two concurrent requests write conflicting values | Cache writes atomic; TTL enforced | No |

**Manual review checklist:**
- [ ] Cache-Control headers reviewed: sensitive responses set `no-store`
- [ ] CDN/proxy cache key includes all headers/cookies that affect response content
- [ ] `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server` not trusted to override cache key
- [ ] Authenticated responses not cached at CDN layer

---

#### Regular Expressions (ReDoS)

**Wooyun-legacy:** (none directly applicable)
**Key search terms:** `ReDoS regular expression denial of service`, `catastrophic backtracking`, `redos vulnerability detection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Catastrophic backtracking | Nested quantifiers with overlap cause exponential time | Regex static analysis (safe-regex, vuln-regex-detector) | Partial |
| ReDoS via nested groups | `(a+)+`, `(a|a)+`, `(.*a){n}` patterns | No nested quantifiers on overlapping character classes | Yes |
| Email/URL regex bomb | Complex validation regex on user input | Replace hand-rolled validators with proven libraries | Yes |
| Regex injection | User input passed as regex pattern | User input never used as regex pattern | Yes |

**Manual review checklist:**
- [ ] No regex with nested quantifiers applied to user-controlled input
- [ ] Email/URL validation uses a proven library, not a hand-rolled regex
- [ ] User input never used as a regex pattern

---

### Data Storage & Messaging

---

#### SQL / ORM Query Building

**Wooyun-legacy:** `sql-injection-checklist.md`
**Key search terms:** `ORM SQL injection`, `raw query injection`, `second-order SQL injection`, `SQL injection via ORM`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Raw query with string concat | `db.query("SELECT * WHERE id=" + id)` | No string concatenation into SQL; parameterized only | Yes |
| ORM raw() / execute() injection | ORM raw query escape hatch used with user input | `raw()`, `execute()`, `annotate()` flagged for user input | Yes |
| Second-order injection | Data stored safely, later used unsafely in query | Stored values also parameterized when re-queried | No |
| ORDER BY / LIMIT injection | User-controlled sort column interpolated | Column names validated against allowlist | Yes |
| Mass assignment | ORM model updated directly from request body | `fillable`/`guarded` or explicit field binding enforced | Yes |
| Blind injection via timing | Time-based blind injection via slow query | Rate limiting and query timeout enforced | No |

**Manual review checklist:**
- [ ] All queries use parameterized queries or ORM-level parameter binding
- [ ] `ORDER BY` column names validated against allowlist; never user-interpolated
- [ ] `raw()`, `execute()`, `annotate(rawsql)` occurrences audited for user input
- [ ] Mass assignment protection enabled (allowlist of fillable fields)

---

#### NoSQL (MongoDB, Redis, Elasticsearch, DynamoDB)

**Wooyun-legacy:** `unauthorized-access-checklist.md`
**Key search terms:** `MongoDB injection`, `NoSQL injection`, `Elasticsearch injection`, `Redis command injection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| MongoDB operator injection | `{ "$where": "..." }` or `{ "$gt": "" }` from user input | User input never merged directly into query object | Yes |
| Redis command injection | User input reaches `EVAL` or command string | `EVAL` with user input blocked; commands use parameterized clients | Yes |
| Elasticsearch query injection | User input in `query_string` with wildcard abuse | Query type restricted; user input in `match` (analyzed) not `query_string` | Yes |
| DynamoDB filter expression injection | User input in filter expression | Filter expressions use `:placeholder` substitution | Yes |
| Unauthenticated service exposure | Redis/Elasticsearch bound to 0.0.0.0 without auth | Datastores bound to localhost or require auth | No |
| Key enumeration | Predictable key patterns allow data extraction | Keys include user-specific entropy; SCAN disabled | Yes |

**Manual review checklist:**
- [ ] MongoDB queries use typed operators; user input never merged into query object with `Object.assign` or `...spread`
- [ ] Redis `EVAL` and `KEYS` / `SCAN` commands not accessible with user-supplied arguments
- [ ] Elasticsearch `query_string` queries not used with user input; use `match` or `term`

---

#### Message Queues / Event Streaming (Kafka, RabbitMQ, SQS, Pub/Sub, NATS)

**Wooyun-legacy:** (none directly)
**Key search terms:** `Kafka deserialization vulnerability`, `message queue injection`, `event sourcing security`, `AMQP security`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Deserialization via queue | Java/Python deserialization in consumer | Deserializer type-constrained; no Java native deserialization | Yes |
| Topic/queue injection | User input used as topic name | Topic names validated against allowlist | Yes |
| Message replay | Old messages re-delivered without idempotency guard | Consumer is idempotent; deduplication ID used | No |
| Consumer group privilege escalation | Consumer joins privileged group by name | Consumer group membership validated | No |
| Dead letter queue exposure | DLQ contains sensitive unprocessed messages | DLQ access controlled; messages encrypted | No |
| Schema evolution confusion | Producer schema changes break consumer validation | Schema registry enforced; consumers reject unknown versions | No |
| SSRF via webhook delivery | Broker delivers messages to user-controlled URLs | Webhook URL validated against SSRF allowlist | Yes |

**Manual review checklist:**
- [ ] Message deserializer is schema-constrained (protobuf/Avro/JSON with schema); no native Java/Python serialization
- [ ] Topic names used in routing are from allowlist, not user-constructed
- [ ] Webhook delivery URLs validated against SSRF allowlist before fetch
- [ ] DLQ access is restricted and audited

---

#### Caching Layers (Memcached, Redis as cache, CDN)

**Wooyun-legacy:** `unauthorized-access-checklist.md`
**Key search terms:** `cache key injection`, `Memcached injection`, `cache poisoning`, `cache timing attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Memcached injection | Newline in key name injects additional commands | Keys sanitized; no `\r\n` in cache keys | Yes |
| Cache key collision | Two different inputs produce same cache key | Cache key uniquely encodes all variable inputs | No |
| Sensitive data in cache | Tokens, passwords, or PII stored in shared cache | Sensitive data excluded from cache or encrypted | Yes |
| Cache-based timing oracle | Timing difference reveals cache hit/miss | Responses normalized to avoid timing leakage | No |
| Unauthenticated cache access | Redis/Memcached accessible without auth | Cache bound to localhost or requires auth | No |

**Manual review checklist:**
- [ ] Cache keys include all inputs that affect the response (user ID, locale, permissions)
- [ ] Sensitive data (auth tokens, PII) excluded from cache or encrypted at rest
- [ ] Cache service bound to localhost or protected by auth and firewall

---

### Infrastructure & Cloud

---

#### Containers / Docker

**Wooyun-legacy:** `command-execution-checklist.md`
**Key search terms:** `Docker container escape`, `privileged container escape`, `container breakout`, `Docker socket exposure`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Privileged container escape | `--privileged` mounts all host devices | No privileged containers; seccomp/AppArmor enforced | Yes |
| Docker socket mount | `/var/run/docker.sock` mounted inside container | Docker socket not mounted in containers | Yes |
| Host PID/network namespace | `--pid=host` or `--network=host` shared | Host namespaces not shared | Yes |
| Writable host filesystem | Host path mounted writable | Host mounts read-only; sensitive paths excluded | Yes |
| Capability abuse | `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` etc. granted | Only required capabilities granted; `cap_drop=ALL` as default | Yes |
| Image with root user | Container runs as root by default | `USER` directive sets non-root user; `runAsNonRoot: true` | Yes |
| Secrets in image layers | Secrets in `RUN` commands or ENV | Multi-stage builds; secrets via vault/env injection, not image | Yes |

**Manual review checklist:**
- [ ] No containers run with `--privileged` or `--pid=host`
- [ ] Docker socket not mounted inside containers
- [ ] `USER` set to non-root in Dockerfile
- [ ] Secrets not present in image layers (multi-stage builds used)
- [ ] `cap_drop: ALL` with explicit `cap_add` for required capabilities only

---

#### Kubernetes

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `misconfig-checklist.md`
**Key search terms:** `Kubernetes RBAC privilege escalation`, `Kubernetes secrets exposure`, `pod security policy bypass`, `etcd exposure`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| RBAC privilege escalation | Overpermissive ClusterRole or `*` verbs | Roles use least privilege; no `*` on resources/verbs | Yes |
| Service account token auto-mount | Default SA token mounted unnecessarily | `automountServiceAccountToken: false` for pods that don't need it | Yes |
| Secrets in environment variables | K8s secrets exposed as env vars in plain text | Secrets referenced as volume mounts; external vault used | Yes |
| etcd access without TLS | etcd accessible on port 2379 without auth | etcd peer/client TLS and auth enforced | No |
| Admission controller bypass | Mutating webhook not enforced | Admission webhooks cover all namespaces | No |
| Node escape via hostPath | `hostPath` volume mounts sensitive paths | `hostPath` restricted via admission policy | Yes |
| Namespace boundary bypass | Pod with cluster-admin escalates across namespaces | Cross-namespace service account bindings audited | Yes |

**Manual review checklist:**
- [ ] All RBAC roles audited for `*` verbs and overpermissive resource access
- [ ] `automountServiceAccountToken: false` on pods that don't call K8s API
- [ ] Secrets stored in external vault, not K8s Secrets directly where possible
- [ ] `hostPath` volumes restricted or prohibited by admission policy

---

#### Cloud Metadata / IMDS (AWS, GCP, Azure)

**Wooyun-legacy:** `ssrf-checklist.md`
**Key search terms:** `SSRF cloud metadata`, `AWS IMDSv1 SSRF`, `GCP metadata server SSRF`, `cloud credential theft via SSRF`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| IMDSv1 credential theft | `http://169.254.169.254/` returns IAM credentials | IMDSv2 enforced (PUT-required token); IMDSv1 disabled | No |
| GCP metadata server | `http://metadata.google.internal/` fetches SA tokens | SSRF blocklist includes GCP metadata IP and hostname | No |
| Azure IMDS | `http://169.254.169.254/metadata/identity` | SSRF blocklist includes Azure metadata IP | No |
| Link-local range bypass | `http://0251.0254.0254.0254/` bypasses IP check | All link-local ranges blocked including octal/hex variants | No |
| Metadata via DNS rebinding | Attacker hostname resolves to 169.254.169.254 | DNS resolution results validated against SSRF blocklist | No |

**Manual review checklist:**
- [ ] SSRF blocklist includes `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, and Azure IMDS IP
- [ ] All IP variants (octal, hex, IPv6-mapped) blocked in SSRF protection
- [ ] IMDSv2 enforced on all EC2 instances (IMDSv1 disabled at instance metadata level)

---

#### Serverless / Lambda / FaaS

**Wooyun-legacy:** `command-execution-checklist.md`, `ssrf-checklist.md`
**Key search terms:** `Lambda injection attack`, `serverless security`, `function event injection`, `cold start timing attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Event data injection | Lambda event fields used as shell/SQL input | Event fields treated as untrusted user input | Yes |
| Environment variable secret exposure | Secrets in function env vars unencrypted | Secrets fetched from Secrets Manager at runtime, not env vars | Yes |
| Over-permissive execution role | Lambda role has `*` on S3/DDB/etc. | Execution role scoped to specific resources and actions | No |
| Function URL without auth | Lambda Function URL allows unauthenticated access | Function URL uses `AuthType: AWS_IAM` or proxy auth | Yes |
| Dependency in `/tmp` exploitation | Shared `/tmp` between warm invocations | `/tmp` state validated or cleaned between invocations | No |
| Zip bomb in payload | Large payload causes OOM before processing | Payload size validated before deserialization | Yes |

**Manual review checklist:**
- [ ] All event fields treated as untrusted input (validated before use in queries/commands)
- [ ] Secrets fetched from Secrets Manager/Parameter Store, not env vars
- [ ] Execution role uses least-privilege (specific resources and actions)
- [ ] Function URLs require authentication or are behind a proxy with auth

---

#### CI/CD Pipelines (GitHub Actions, Jenkins, CircleCI, GitLab CI)

**Wooyun-legacy:** (none directly; see `agentic-actions-auditor` for GitHub Actions)
**Key search terms:** `CI/CD pipeline injection`, `GitHub Actions injection`, `Jenkins script injection`, `pipeline secret exposure`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Expression injection | `${{ github.event.issue.title }}` in `run:` step | Untrusted input only via env vars, never directly in `run:` | Yes |
| Secrets in logs | `echo $SECRET` in pipeline scripts | Secrets passed as masked env vars; not echoed | Yes |
| Pull request poisoning | Malicious PR changes CI config to exfiltrate secrets | Secrets restricted to base repo; `pull_request_target` audited | Yes |
| Artifact tampering | Build artifacts fetched without integrity check | Artifacts verified with hash/signature before use | No |
| Dependency cache poisoning | Cache restored from untrusted key | Cache keys include lockfile hash; restored cache verified | No |
| Overpermissive `GITHUB_TOKEN` | Token has write permissions it doesn't need | `permissions:` set to minimum required in each workflow | Yes |
| Self-hosted runner code execution | Malicious PR runs on self-hosted runner | Self-hosted runners isolated; not used for untrusted PRs | No |

**Manual review checklist:**
- [ ] No untrusted event data (issue title, PR body, committer name) directly in `run:` shell steps
- [ ] `permissions:` specified and minimal in all workflow files
- [ ] `pull_request_target` workflows do not check out or execute untrusted PR code
- [ ] Self-hosted runners not used for workflows triggered by external PRs

---

#### Supply Chain / Package Managers

**Wooyun-legacy:** (none directly)
**Key search terms:** `dependency confusion attack`, `typosquatting npm`, `malicious package`, `lockfile integrity`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Dependency confusion | Internal package name published to public registry | Private registry scope enforced; public name squatted | No |
| Typosquatting | Misspelled package name installs malicious code | Dependency names audited; lockfile committed and pinned | No |
| Lockfile tampering | Lockfile modified to point to malicious version | Lockfile integrity verified in CI (hash/signature) | No |
| Postinstall script execution | `postinstall` in dependency runs arbitrary code | `ignore-scripts` flag used; scripts audited before use | Yes |
| Unpinned dependencies | `^1.0.0` allows unexpected minor/patch upgrades | Dependencies pinned to exact versions in lockfile | Yes |
| Subdependency compromise | Transitive dependency hijacked | Dependency tree audited; SBOM generated | No |

**Manual review checklist:**
- [ ] Lockfile committed and verified in CI
- [ ] Dependencies pinned to exact versions or hashes
- [ ] `npm install --ignore-scripts` or equivalent used in CI
- [ ] Internal package names squatted on public registries

---

### Process & Native Execution

---

#### Command / Process Execution

**Wooyun-legacy:** `command-execution-checklist.md`, `rce-checklist.md`
**Key search terms:** `command injection`, `subprocess injection`, `shell injection bypass`, `argument injection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Shell metacharacter injection | `;`, `|`, `&&`, `` ` `` in user input reach shell | `shell=False` (Python), array args (Node), no shell string | Yes |
| Argument injection | User controls argument that changes program behavior | Argument validated; `--` separator used | Yes |
| Path injection | User controls executable path | Executable paths hardcoded or validated against allowlist | Yes |
| Environment variable injection | User controls `PATH` or other env affecting execution | Sanitized environment passed to subprocess | Yes |
| TOCTOU on executable | Path checked then different binary executed | Execute directly without re-resolving path | No |

**Manual review checklist:**
- [ ] All subprocess calls use array/list arguments, not shell strings with user input
- [ ] `shell=True` / `sh -c` with user input flagged and removed
- [ ] Executable paths not constructed from user input

---

#### Deserialization (Java, Python, Ruby, PHP, .NET)

**Wooyun-legacy:** `rce-checklist.md`
**Key search terms:** `Java deserialization gadget chain`, `Python pickle RCE`, `PHP unserialize`, `.NET BinaryFormatter`, `Ruby Marshal`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Java native deserialization | `ObjectInputStream` with untrusted data | `ObjectInputStream` not used with untrusted data | Yes |
| Python pickle/marshal | `pickle.loads` / `marshal.loads` on user input | `pickle`/`marshal` not used with user-supplied data | Yes |
| PHP `unserialize()` | PHP unserialize on user input | `unserialize()` not used with user input; JSON used instead | Yes |
| .NET BinaryFormatter | BinaryFormatter on untrusted data | BinaryFormatter disabled; `System.Text.Json` or protobuf used | Yes |
| YAML unsafe load | `yaml.load()` without `Loader=SafeLoader` | `yaml.safe_load()` used everywhere | Yes |
| Ruby `Marshal.load` | Marshal on untrusted data | `Marshal.load` not used with user data | Yes |

**Manual review checklist:**
- [ ] `pickle.loads`, `marshal.loads`, `yaml.load` (without SafeLoader) not called with user data
- [ ] Java `ObjectInputStream` not used with untrusted data
- [ ] PHP `unserialize()` not called with user input
- [ ] YAML parsing uses safe loader everywhere

---

#### FFI / Native Bindings / Memory Safety

**Wooyun-legacy:** `rce-checklist.md`
**Key search terms:** `FFI buffer overflow`, `use-after-free FFI`, `unsafe Rust`, `CGo security`, `ctypes vulnerability`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Buffer overflow via FFI | Caller passes too-large input to native function | Length validated before passing to native code | Partial |
| Use-after-free | Native reference used after Rust/C GC | Ownership/lifetime enforced; no raw pointer aliasing | Partial |
| Integer overflow in size calculation | `len * 4` overflows into small allocation | Checked arithmetic used for size calculations | Yes |
| Unsafe Rust block misuse | `unsafe {}` used unnecessarily or unsafely | `unsafe` blocks audited and minimized | Yes |
| Null pointer dereference | Null passed to non-nullable native parameter | Null checks before FFI calls | Yes |

**Manual review checklist:**
- [ ] All FFI calls validate buffer lengths before passing to native code
- [ ] `unsafe` Rust blocks documented with safety invariants
- [ ] CGo pointers obey CGo rules (no Go pointer in C-allocated memory)

---

### AI / ML Systems

---

#### LLM / AI Integration (Prompt Injection)

**Wooyun-legacy:** (none directly)
**Key search terms:** `prompt injection attack`, `indirect prompt injection`, `LLM jailbreak`, `AI agent tool call injection`, `system prompt extraction`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Direct prompt injection | User input overrides system prompt | User input separated from system prompt; role distinction enforced | No |
| Indirect prompt injection | LLM reads attacker-controlled external content that injects instructions | External content treated as data, not instructions; structured output enforced | No |
| Tool call injection | Injected instruction triggers unintended tool/action | Tool calls validated against expected schema; user confirmation for sensitive actions | No |
| System prompt extraction | User extracts system prompt via clever prompting | System prompt not referenced in context; input/output filtering | No |
| Insecure output handling | LLM output rendered directly as HTML/code | LLM output sanitized before rendering; not passed to `eval` | Yes |
| Training data extraction | PII or secrets recoverable from model outputs | Sensitive data excluded from training; output filtering | No |
| Excessive agency | Agent takes irreversible actions without confirmation | Human-in-the-loop for sensitive operations; action scope limited | No |

**Manual review checklist:**
- [ ] User-supplied content never concatenated directly into system prompt
- [ ] LLM output never passed to `eval`, `exec`, shell, or rendered as raw HTML
- [ ] Tool calls with destructive/irreversible effects require explicit confirmation
- [ ] External content (web pages, documents, emails) processed in a restricted context that cannot override system instructions

---

#### ML Model Loading (Pickle, ONNX, TensorFlow SavedModel)

**Wooyun-legacy:** `rce-checklist.md`
**Key search terms:** `pickle model RCE`, `ONNX model injection`, `TensorFlow SavedModel security`, `Hugging Face model security`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Pickle-based model RCE | `torch.load`, `joblib.load` execute arbitrary code | `weights_only=True` (PyTorch 2.0+); safe format used | Yes |
| ONNX custom op injection | ONNX model loads attacker-controlled custom operator | Models validated against allowlist before loading | No |
| TensorFlow lambda injection | `tf.keras.models.load_model` with lambda layers | `safe_mode=True` enforced; lambda layers disabled | Yes |
| Model from untrusted source | Model downloaded without integrity check | Model hash/signature verified before load | No |
| Hugging Face model execution | `from_pretrained` loads untrusted model with `trust_remote_code=True` | `trust_remote_code=False` (default); model source verified | Yes |

**Manual review checklist:**
- [ ] `torch.load` uses `weights_only=True` for all user-supplied model files
- [ ] `trust_remote_code=False` for all Hugging Face `from_pretrained` calls
- [ ] Model files from external sources verified by hash before loading
- [ ] `tf.keras.models.load_model` uses `safe_mode=True`

---

### Protocol-Level

---

#### HTTP Client / Server

**Wooyun-legacy:** `ssrf-checklist.md`, `misconfig-checklist.md`, `path-traversal-checklist.md`
**Key search terms:** `HTTP request smuggling CL.TE`, `CRLF injection HTTP`, `hop-by-hop header abuse`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| CL.TE / TE.CL request smuggling | Proxy and backend disagree on body framing | Server rejects requests with both CL and TE; proxy/backend agree | No |
| CRLF injection | `\r\n` in header value enables response splitting | Header values stripped of CR/LF before writing | Yes |
| Host header injection | Host used in redirect/URL construction without validation | Host validated against allowlist before use | Yes |
| Hop-by-hop header abuse | `Connection` header removes security headers at proxy | Security headers not removable via hop-by-hop | No |
| HTTP/2 desync | H2 pseudo-headers mapped to H1 inconsistently | H2-to-H1 downgrade strips or validates pseudo-headers | No |
| HTTP method override | `_method` or `X-HTTP-Method-Override` bypasses restrictions | Method override headers disabled or restricted | Yes |

**Manual review checklist:**
- [ ] Header values with user input stripped of `\r\n`
- [ ] Server rejects ambiguous requests with both Content-Length and Transfer-Encoding
- [ ] Host header validated before use in redirects or URL construction
- [ ] `X-HTTP-Method-Override` disabled or restricted to trusted clients

---

#### gRPC

**Wooyun-legacy:** `unauthorized-access-checklist.md`
**Key search terms:** `gRPC metadata injection`, `gRPC reflection abuse`, `gRPC channel security`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Metadata injection | Attacker-controlled metadata forwarded downstream | Metadata sanitized or allowlisted before forwarding | Partial |
| Unauthenticated reflection | Schema exposed to unauthenticated callers | Reflection disabled or authenticated | Yes |
| Insecure channel | gRPC channel configured without TLS | TLS credentials required; `insecure.NewCredentials()` flagged | Yes |
| Missing per-RPC auth | Channel-level auth skips per-call validation | Every RPC handler validates caller identity | Yes |

**Manual review checklist:**
- [ ] gRPC reflection disabled in production or behind authentication
- [ ] All channels use TLS credentials
- [ ] Per-call metadata sanitized before forwarding

---

#### GraphQL

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `ssrf-checklist.md`
**Key search terms:** `GraphQL introspection abuse`, `GraphQL batching attack`, `GraphQL field authorization bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Introspection leakage | Full schema exposed unauthenticated | Introspection disabled in production | Yes |
| Nested query DoS | Deeply nested queries cause exponential load | Query depth and complexity limits enforced | Yes |
| Field-level authorization bypass | Root resolver auth but no field-level check | Every field resolver validates permissions | No |
| Batching / alias rate limit evasion | Multiple ops in one request bypass rate limiting | Per-operation rate limiting; alias count bounded | No |
| SSRF via URL inputs | Mutations accept URL arguments fetched server-side | URL inputs validated against SSRF allowlist | Yes |

**Manual review checklist:**
- [ ] Introspection disabled in production (or behind authentication)
- [ ] Query depth limit (≤10) and complexity budget enforced
- [ ] Every field resolver validates caller authorization

---

#### WebSocket

**Wooyun-legacy:** `csrf-checklist.md`, `unauthorized-access-checklist.md`
**Key search terms:** `WebSocket CSWSH cross-site hijacking`, `WebSocket origin validation`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Cross-Site WebSocket Hijacking | Browser sends cookies; no CSRF protection on upgrade | `Origin` header validated against allowlist on upgrade | Yes |
| Unauthenticated first message | Connection accepted before auth validated | First message validated for auth token | Yes |
| Message injection | User-controlled data injected into WS frame stream | Input validated before broadcast | Yes |

**Manual review checklist:**
- [ ] `Origin` header validated against explicit allowlist on every WebSocket upgrade
- [ ] Authentication validated within first message after upgrade
- [ ] Message size limits enforced

---

#### XML / SOAP

**Wooyun-legacy:** `xxe-checklist.md`, `ssrf-checklist.md`
**Key search terms:** `XXE external entity`, `XML billion laughs`, `XPath injection`, `SOAP action spoofing`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| XML External Entity (XXE) | DTD external entity for SSRF or file read | Parser disables external entities and DTD | Yes |
| Billion laughs | Recursive entity expansion causes DoS | Entity expansion bounded; SAX parser used | Yes |
| XPath injection | User input concatenated into XPath | Parameterized XPath or allowlist used | Yes |
| SOAP action spoofing | SOAPAction header overrides operation | SOAPAction validated against allowed list | Yes |

**Manual review checklist:**
- [ ] XML parser has external entity resolution disabled
- [ ] DTD processing disabled
- [ ] XPath expressions use parameterized queries

---

#### TLS / mTLS

**Wooyun-legacy:** `misconfig-checklist.md`
**Key search terms:** `TLS certificate validation bypass`, `hostname verification disabled`, `mTLS bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Hostname verification disabled | `InsecureSkipVerify: true` | Hostname verification never disabled | Yes |
| mTLS auth bypass | Client cert required in config but not checked in handler | Handler verifies `VerifiedChains` non-empty | Yes |
| Protocol downgrade | TLS 1.0/1.1/SSLv3 accepted | Minimum TLS 1.2 or 1.3 enforced | Yes |
| Weak cipher suite | RC4, DES, 3DES, export ciphers accepted | Cipher suite explicitly restricted | Yes |

**Manual review checklist:**
- [ ] `InsecureSkipVerify` never set to `true`
- [ ] TLS minimum version is 1.2 or 1.3
- [ ] mTLS handlers verify `VerifiedChains` is non-empty

---

#### SAML

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `xxe-checklist.md`
**Key search terms:** `SAML XML signature wrapping`, `SAML assertion forgery`, `SAML roundtrip attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| XML Signature Wrapping (XSW) | Signed element moved; unsigned clone used | Assertion extraction on same node as sig verification | Partial |
| Comment injection | XML comment splits identity | Username extraction strips XML comments | Yes |
| Unsigned assertion acceptance | SP accepts without valid signature | Every code path requires valid sig | Yes |
| InResponseTo bypass | Response replayed by omitting InResponseTo | SP validates InResponseTo against issued IDs | Yes |
| XXE via SAML parser | DTD-based SSRF via XML parser | Parser entity resolution disabled | Yes |

**Manual review checklist:**
- [ ] Assertion extraction uses same node reference as signature verification
- [ ] InResponseTo validated and tracked for replay prevention
- [ ] Parser entity resolution and DTD processing disabled
- [ ] NameID extracted after signature validation

---

#### DNS

**Wooyun-legacy:** `ssrf-checklist.md`
**Key search terms:** `DNS rebinding attack`, `DNS TOCTOU`, `SSRF via DNS`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| DNS rebinding | Hostname resolves to internal IP on re-lookup | Resolved IP validated against SSRF blocklist at connection time | No |
| TOCTOU DNS | IP changes between check and connection | IP pinned at lookup time; no re-resolve | No |

**Manual review checklist:**
- [ ] IPs from user-controlled hostnames validated against SSRF blocklist at connection time
- [ ] DNS results not re-resolved between security check and connection

---

#### SMTP / Email

**Wooyun-legacy:** `ssrf-checklist.md`, `xss-checklist.md`
**Key search terms:** `email header injection`, `SMTP CRLF injection`, `open mail relay`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Header injection | User input in To/Subject with CRLF | Header values stripped of `\r\n` | Yes |
| Open relay | Server forwards for arbitrary recipients | Relay restricted to authenticated senders | Yes |
| HTML email XSS | HTML email with unescaped user content | HTML sanitized in email templates | Yes |

**Manual review checklist:**
- [ ] All email header values stripped of `\r\n`
- [ ] Email relay restricted to authenticated users and known domains
- [ ] HTML email content sanitized with allowlist sanitizer

---

#### LDAP

**Wooyun-legacy:** `sql-injection-checklist.md`, `unauthorized-access-checklist.md`
**Key search terms:** `LDAP injection`, `LDAP null bind`, `LDAP authentication bypass`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| LDAP injection | User input in filter without RFC 4515 escaping | LDAP filter values properly escaped | Yes |
| Null/anonymous bind | Empty password accepted by LDAP server | Empty credential rejected before bind | Yes |
| DN injection | User input in distinguished name construction | DN components escaped per RFC 4514 | Yes |

**Manual review checklist:**
- [ ] LDAP filter special characters escaped per RFC 4515
- [ ] Empty passwords rejected application-side before bind attempt

---

#### SSH

**Wooyun-legacy:** `misconfig-checklist.md`, `unauthorized-access-checklist.md`
**Key search terms:** `SSH host key verification bypass`, `SSH agent forwarding abuse`, `weak SSH key`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Host key verification disabled | `StrictHostKeyChecking no` | Verification always enabled | Yes |
| Agent forwarding abuse | Lateral movement via forwarded agent | Agent forwarding disabled by default | Yes |
| Weak key algorithm | RSA-1024 or DSA keys | Ed25519 or RSA ≥ 3072 required | Yes |

**Manual review checklist:**
- [ ] Host key verification always enabled
- [ ] Agent forwarding disabled by default
- [ ] Key algorithms restricted to Ed25519 or RSA ≥ 3072

---

#### MQTT / IoT Protocols (MQTT, CoAP, AMQP, Modbus)

**Wooyun-legacy:** `unauthorized-access-checklist.md`, `misconfig-checklist.md`
**Key search terms:** `MQTT security`, `MQTT topic injection`, `CoAP security`, `Modbus unauthorized access`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| MQTT anonymous access | Broker allows connections without credentials | Authentication required; anonymous access disabled | No |
| Topic wildcard injection | User controls topic containing `#` or `+` wildcards | Topic names validated; wildcards disallowed in user input | Yes |
| MQTT topic ACL bypass | Client subscribes to topics outside its authorization | Per-client ACL enforced by broker | No |
| Unauthenticated CoAP | CoAP endpoints without DTLS | DTLS required for all CoAP connections | No |
| Modbus unauthorized write | Modbus coil/register write without auth | Write access restricted by device configuration | No |
| Firmware update without verification | OTA update accepted without signature check | Update packages verified with signature before installation | No |

**Manual review checklist:**
- [ ] MQTT broker requires authentication; anonymous access disabled
- [ ] Topic names from user input validated; wildcards (`#`, `+`) blocked
- [ ] OTA firmware updates verified with signature before installation
- [ ] DTLS enforced for CoAP endpoints

---

### Cryptography

---

#### Cryptographic Primitives

**Wooyun-legacy:** `misconfig-checklist.md`
**Key search terms:** `nonce reuse IV attack`, `ECB mode attack`, `padding oracle`, `timing side-channel`, `weak PRNG`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| IV/nonce reuse | Same nonce with AES-GCM or stream cipher | Nonce random or counter-based; never reused | Yes |
| ECB mode | ECB leaks block patterns | ECB never used for confidentiality | Yes |
| Padding oracle | CBC padding error reveals plaintext | AEAD mode used; padding errors indistinguishable | Yes |
| Hardcoded key | Encryption key in source | Keys loaded from secret store | Yes |
| Weak PRNG | `Math.random()` / `rand()` for security values | `crypto/rand` or CSPRNG used | Yes |
| Non-constant-time comparison | Timing attack on secret comparison | `hmac.Equal()` / `crypto/subtle.ConstantTimeCompare()` | Yes |
| Short key length | RSA < 2048, ECDSA < 256, AES < 128 | Key lengths validated at initialization | Yes |

**Manual review checklist:**
- [ ] AES-GCM or ChaCha20-Poly1305 used (not ECB, CBC without MAC)
- [ ] Nonces generated with CSPRNG and never reused
- [ ] Secret comparisons use constant-time functions
- [ ] Keys loaded from secret store, never hardcoded
- [ ] Weak PRNG never used for tokens, nonces, or IDs

---

#### Key Management

**Wooyun-legacy:** `misconfig-checklist.md`
**Key search terms:** `key rotation bypass`, `key wrapping attack`, `HSM bypass`, `KMS misuse`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Key material in source code | Private keys committed to repo | Keys loaded from vault/KMS; never hardcoded | Yes |
| Missing key rotation | Long-lived keys never rotated | Key rotation schedule enforced; old key versions disabled | No |
| Overpermissive KMS policy | Any principal can decrypt with CMK | KMS key policy restricts to specific principals and actions | No |
| Key derivation without salt | PBKDF without per-key salt allows rainbow tables | Unique salt per key derivation | Yes |
| Envelope encryption bypass | Data key cached in plaintext indefinitely | Data key TTL enforced; cached key re-encrypted periodically | No |

**Manual review checklist:**
- [ ] No private keys or secrets committed to source repository
- [ ] KMS key policies restricted to minimum required principals
- [ ] PBKDF uses unique per-derivation salt

---

### Serialization & Formats

---

#### Serialization Formats (protobuf, msgpack, CBOR, Avro, Thrift)

**Wooyun-legacy:** `rce-checklist.md`
**Key search terms:** `protobuf deserialization vulnerability`, `msgpack type confusion`, `CBOR parsing attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Schema evolution confusion | Old/new schema version parse same bytes differently | Schema version enforced; unknown fields rejected | No |
| Type confusion | Integer vs string triggers unexpected path | Strict type validation after deserialization | Yes |
| Integer overflow in length field | Malformed length triggers buffer overread | Length field bounds-checked before allocation | Yes |
| Deep nesting DoS | Stack overflow via nested messages | Recursion/nesting depth limited | Partial |

**Manual review checklist:**
- [ ] Unknown fields rejected or ignored (not passed through)
- [ ] Nesting/recursion depth bounded
- [ ] Message size bounded before deserialization begins

---

#### Compression (zip, gzip, zlib, brotli)

**Wooyun-legacy:** `path-traversal-checklist.md`, `ssrf-checklist.md`
**Key search terms:** `zip bomb`, `zip slip path traversal`, `decompression bomb`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Zip slip | Archive entry path traverses outside target directory | Extracted path confined to target directory | Yes |
| Decompression bomb | Tiny input expands to gigabytes | Decompressed size bounded before reading | Yes |
| Zip entry name injection | Entry name contains null bytes or special chars | Entry names sanitized before use in file ops | Yes |

**Manual review checklist:**
- [ ] Extracted file paths normalized and confined to target directory
- [ ] Decompressed size bounded (ratio check and absolute limit)
- [ ] Archive entry count bounded

---

### Mobile & Browser

---

#### Browser Extensions / Content Scripts

**Wooyun-legacy:** `xss-checklist.md`
**Key search terms:** `browser extension security`, `content script XSS`, `chrome extension privilege escalation`, `postMessage injection`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| `postMessage` injection | Content script trusts messages from any origin | `event.origin` validated before processing postMessage | Yes |
| Content script XSS | Content script injects unsanitized DOM content | Content script never uses `innerHTML` with page data | Yes |
| Manifest permission over-request | Extension requests `<all_urls>` unnecessarily | Permissions minimized in manifest; no `*` host permissions | Yes |
| Background page CSRF | Extension background page acts on any cross-origin message | Message source validated; sensitive actions require explicit permission | Yes |
| Content Security Policy bypass | Extension weakens CSP with `unsafe-eval` | `unsafe-eval` not in extension CSP | Yes |

**Manual review checklist:**
- [ ] `postMessage` handlers validate `event.origin` before processing
- [ ] Content scripts never use `innerHTML`, `outerHTML`, `document.write` with untrusted data
- [ ] Extension manifest requests minimum required permissions
- [ ] `unsafe-eval` absent from extension Content Security Policy

---

#### Mobile Deep Links / URL Schemes (Android, iOS)

**Wooyun-legacy:** `unauthorized-access-checklist.md`
**Key search terms:** `Android deep link hijacking`, `iOS URL scheme hijacking`, `Universal Links bypass`, `intent scheme attack`

| Attack | Description | Detection strategy | SAST |
|--------|-------------|-------------------|------|
| Deep link hijacking | Malicious app registers same custom URL scheme | Universal Links (iOS) / App Links (Android) used; custom schemes avoided | No |
| Intent data injection | Deep link intent data used in sensitive operations | Intent data validated before use in queries/navigation | Yes |
| OAuth redirect via deep link | OAuth callback routed to custom scheme | App Link / Universal Link used for OAuth callbacks | No |
| WebView deep link bypass | Deep link opens untrusted URL in WebView | URL allowlisted before opening in WebView | Yes |
| Fragment injection | URI fragment used in authentication state | Fragment data validated and sanitized | Yes |

**Manual review checklist:**
- [ ] Custom URL schemes not used for OAuth callbacks; App Links / Universal Links used instead
- [ ] All deep link intent data validated before use in navigation or queries
- [ ] WebView URL allowlisted before loading deep link destinations

---

## Notes for knowledge-base-builder

- Run Mode C in parallel with Mode A and Mode B when they overlap. Do not skip Mode A/B because
  Mode C is being run.
- **Token budget**: bound each domain research to one `last30days` call, one `wooyun-legacy` read,
  and 3-5 web searches. Do not research more than 5 domains in depth in a single session without
  explicit user instruction. Prioritize by relevance to high-risk DFD/CFD slices.
- When MCP tools are unavailable, `WebSearch` + `WebFetch` of top 2-3 results is sufficient.
- The attack taxonomy produced here is the primary input for Phase 4 custom SAST rule generation
  and Phase 6 spec gap analysis. Quality over quantity — a focused 5-item checklist is more useful
  than an exhaustive 30-item generic list.
- Record which research sources were used in the `## Domain Attack Research` section for auditability.
- **Domain identification is exhaustive, not exclusive**: a single project may trigger 5+ domains.
  Triage by DFD slice criticality — research domains that appear in high-risk flows first.
