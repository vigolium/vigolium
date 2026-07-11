# Creative Attack Generation Modes

Eight structured thinking modes for the Attack Ideator agent. Cycle through all 8 modes for each
threat cluster, generating at least one hypothesis per applicable mode. Hypotheses that span
multiple modes (e.g., chaining + race condition) are the most valuable and should be prioritized.

## Mode 1: Vulnerability Chaining

Chain individually-low-severity issues into high-severity exploit paths. No single issue may
qualify as a finding alone, but the combination crosses a trust boundary.

**Thinking prompts:**
- "If IDOR gives read access to user metadata, and metadata contains session tokens, then
  IDOR + token reuse = account takeover"
- "If SSRF is limited to internal DNS resolution, and internal DNS resolves to metadata endpoints,
  then SSRF + cloud metadata = credential theft"
- "This CVE was patched, but the patch only covers the HTTP path. The WebSocket path uses the same
  parser without the fix"
- "Advisory intelligence + a spec gap: can a known CVE's patch be bypassed through a protocol
  compliance gap?"
- "Low-severity information disclosure + low-severity injection = high-severity authenticated RCE"

**Cross-reference inputs:**
- Advisory intelligence (known CVEs, patch commits)
- Spec-compliance analysis (protocol gaps)
- SAST enrichment notes (individually-dropped low-severity findings)
- Domain attack research (known attack chains per domain)

## Mode 2: Business Logic Abuse

Think about what the application is *designed* to do and how that design can be abused.
Business logic bugs are invisible to SAST tools.

**Thinking prompts:**
- "Can I refund more than I paid? Process a negative quantity?"
- "Can I invite myself to a higher-privilege role?"
- "Can I skip step 2 and go directly from step 1 to step 3?"
- "Can I exhaust another tenant's quota by manipulating the accounting?"
- "Can I register the same resource twice and exploit the race between checks?"
- "Can I abuse a legitimate feature (export, share, webhook) as an exfiltration channel?"
- "Can I manipulate the order of operations to bypass a check that assumes sequential execution?"
- "Can I abuse an undo/rollback mechanism to restore a revoked privilege?"

**Focus areas:**
- Multi-step workflows (payment, registration, approval, provisioning)
- Quota and rate systems (credits, API limits, storage)
- Invitation and delegation systems
- State machines with transitions (draft -> published -> archived)

## Mode 3: Race Conditions and TOCTOU

Identify state-dependent operations and ask "what if the state changes between check and use?"
Race conditions are notoriously difficult to find through static analysis.

**Thinking prompts:**
- "The balance check and deduction are not atomic — double-spend?"
- "Role is checked, then 100ms later the privileged action executes. Can I change my role between?"
- "Symlink substitution between stat() and open()?"
- "Database isolation level is READ COMMITTED — phantom reads in this multi-query operation?"
- "The session is validated, then the request body is parsed. Can I invalidate the session mid-parse?"
- "Two concurrent requests to the same endpoint — does the second see the first's uncommitted state?"
- "The file is written, then permissions are set. Is there a window where the file is world-readable?"

**Detection strategy:**
- Look for check-then-act patterns without locking or atomic transactions
- Identify shared mutable state accessed by concurrent handlers
- Find operations that span multiple I/O calls (DB, file, network)
- Check for non-atomic read-modify-write sequences

## Mode 4: Second-Order and Stored Attacks

Look for inputs that are stored before being used in a dangerous context. The storage creates
temporal and spatial separation that hides the attack from simple source-to-sink analysis.

**Thinking prompts:**
- "User input stored in profile field, later rendered unescaped in admin dashboard (stored XSS)"
- "Username stored in table A, later concatenated into query when joining table B (second-order SQLi)"
- "Webhook URL stored in config, later fetched by background job (stored SSRF)"
- "Template variable stored in database, later rendered by email templating engine (stored SSTI)"
- "Filename stored during upload, later used in a shell command during processing (stored command injection)"
- "JSON payload stored in event queue, later deserialized by a consumer with different trust level"

**Detection strategy:**
- Identify all write paths (user input -> database/file/cache/queue)
- For each stored value, trace all read paths and their consumption contexts
- Check if the read context applies different (weaker) sanitization than the write context
- Pay special attention to cross-service data flows where the consuming service trusts stored data

## Mode 5: Trust Boundary Confusion

Identify where identity, authorization, or trust assumptions change across component boundaries.

**Thinking prompts:**
- "Microservice A trusts microservice B's claims without re-verification"
- "Frontend validation assumed to be present by backend"
- "Internal API endpoints exposed through a public reverse proxy with no re-auth"
- "Plugin/extension code running with host-level privileges"
- "The auth middleware checks tokens, but this endpoint is registered before the middleware in the
  route chain"
- "The API gateway validates JWT, but the downstream service accepts any request from the gateway IP"
- "Admin panel is 'internal only' but shares the same origin as the public app (CORS, cookies)"
- "The CLI tool runs with user privileges but shells out to a helper that runs as root"

**Detection strategy:**
- Map all trust boundaries from the current threat model
- For each boundary, check: does crossing it require re-authentication? Re-authorization?
- Identify implicit trust assumptions (IP-based trust, shared-origin trust, process-level trust)
- Check middleware ordering: are security checks applied before or after route registration?
- Look for "internal" APIs accessible from external networks

## Mode 6: Parser and Protocol Differentials

Look for places where two components interpret the same input differently. Parser differentials
are high-severity because they bypass controls that appear correct in isolation.

**Thinking prompts:**
- "HTTP request smuggling between proxy and backend (CL vs TE)"
- "JSON parser differential (duplicate keys — which value wins?)"
- "URL parser differential (authority parsing, percent-encoding, backslash handling)"
- "Content-Type mismatch between what the validator checks and what the processor consumes"
- "XML namespace-aware vs namespace-unaware parser (SAML signature wrapping)"
- "Multipart boundary parsing difference between framework and application code"
- "Header folding: proxy treats continuation line as part of previous header, backend treats it as new"
- "Path normalization: security check uses one library, router uses another"

**Cross-reference inputs:**
- Spec-compliance analysis (RFC gaps in parsers)
- Domain attack research Mode C (protocol-specific attack patterns)
- `deep-analysis.md` Section 6 (parsing/normalization/sanitization discrepancies)

**Detection strategy:**
- Identify every parser in the system (URL, JSON, XML, multipart, headers, cookies, query strings)
- For each parser, check: is the same parser used by both the security check and the consumer?
- Look for double-encoding, normalization order issues, and spec-non-compliant behavior
- Check for polyglot inputs that are valid in multiple formats

## Mode 7: State Machine Attacks

Analyze multi-step protocols and state machines for out-of-order, replay, or missing-transition
attacks.

**Thinking prompts:**
- "Can I replay step 3 of the OAuth flow to get a second access token?"
- "Can I send the password reset link to a different email by modifying the request between steps?"
- "What happens if I send an API request during the 'pending deletion' grace period?"
- "The session invalidation is async — there is a window where the old session still works"
- "Can I reuse a one-time code (TOTP, email verification, invite link) by racing the invalidation?"
- "Can I transition from 'suspended' back to 'active' by calling an endpoint that assumes 'pending'?"
- "Can I bypass the email verification step by directly calling the post-verification endpoint?"
- "The payment flow assumes state A -> B -> C, but can I go A -> C directly?"

**Detection strategy:**
- Map all state machines (user lifecycle, order lifecycle, auth flow, payment flow)
- For each transition, verify: is the previous state checked? Is the check atomic?
- Look for state stored in client-side tokens (JWT, cookies) that can be replayed
- Check for async state updates where the old state remains valid during propagation
- Identify one-time tokens and verify they are actually invalidated after use

## Mode 8: Supply Chain and Dependency Interaction

Use dependency intelligence to generate hypotheses about how dependencies interact
with application code.

**Thinking prompts:**
- "This dependency has a known deserialization gadget. Does the application ever deserialize
  user-controlled data with this library?"
- "This transitive dependency is 3 years out of date. What security fixes happened since then?"
- "The application monkey-patches this library's validation function. Does the patch weaken security?"
- "The library provides a safe API and an unsafe API. Which one does the application use?"
- "The library's default configuration is insecure. Does the application override the defaults?"
- "Two dependencies implement the same protocol differently. Does the application use both on the
  same data path?"
- "The dependency was designed for server-side use. The application uses it in a browser context."
- "The library's error handling returns sensitive information. Does the application expose these errors?"

**Cross-reference inputs:**
- Advisory intelligence (CVEs, GHSAs, patch commits)
- Domain attack research Mode A (library-as-target) and Mode B (library-as-consumer)
- `supply-chain-risk-auditor` skill output
- `sharp-edges` and `insecure-defaults` skill outputs

**Detection strategy:**
- For each security-relevant dependency, trace how the application uses it
- Check if the application uses the dependency's safe or unsafe API surface
- Verify default configurations are overridden appropriately
- Look for version pinning issues and dependency confusion opportunities

## Applying Multiple Modes

The most creative and impactful hypotheses combine multiple modes. When generating a hypothesis
batch, explicitly attempt at least 2 cross-mode combinations:

**Examples:**
- Mode 1 (chaining) + Mode 3 (TOCTOU): "Chain a race condition in the payment check with an IDOR
  to achieve unauthorized fund transfer"
- Mode 4 (stored) + Mode 5 (trust boundary): "Store a payload via the low-trust user API that gets
  executed by the high-trust admin renderer"
- Mode 6 (parser differential) + Mode 7 (state machine): "Use a URL parser differential to bypass
  the OAuth redirect_uri check, then replay the authorization code"
- Mode 2 (business logic) + Mode 8 (supply chain): "The caching library serves stale responses.
  Abuse this to serve a revoked user's data to a new user inheriting the same cache key"

## Ideator Output Format

Each hypothesis must include ALL of these fields:

```markdown
**H-<NN>: <hypothesis title>**
- Attack class: <primary mode used>
- Cross-modes: <secondary modes if applicable, or "none">
- Chain: <multi-step chain description, or "single-step">
- Preconditions: <attacker starting position and required capabilities>
- Target asset: <what the attacker gains>
- Entry point: <suspected entry point in the code>
- Sink: <suspected sensitive operation>
- Creativity signal: <why a solo agent would miss this — what makes it non-obvious>
```

The "creativity signal" field is mandatory. If the hypothesis is obvious (e.g., "SQL injection in
a query that concatenates user input"), it does not need the Ideator — the SAST tools already
found it. The Ideator's value is in hypotheses that require human-like lateral thinking.
