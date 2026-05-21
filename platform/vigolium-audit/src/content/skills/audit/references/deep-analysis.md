# Deep Analysis Methods

Purpose: define **how** to investigate security controls deeply.  
Out of scope: severity scoring, prerequisite thresholds, and report formatting.

## 1) Build a System Model

Capture the project model before testing hypotheses:

- Components and trust boundaries
- Exposed interfaces (HTTP, CLI, files, IPC, queues, plugins, tool invocation, control planes)
- Security-critical assets and operations
- Deployment assumptions (internet-facing, internal, desktop, CI)
- Compact DFD slices for high-risk attacker-controlled flows
- Compact CFD slices for high-risk authn/authz, policy, orchestration, and privilege-transition paths

## 2) Trace Trust-Boundary Data Flows

For each entry point, map:

- Input source
- Transformations (parse/validate/normalize/encode)
- Security decision points
- Sensitive sinks (authz, DB, file, exec, SSRF, crypto, deserialization)

Record full path segments so each hypothesis maps to concrete code.
Use the DFD slices to choose the most security-relevant paths first rather than sampling code uniformly.

## 2.5) Trace Control and Decision Flows

For each high-risk CFD slice, map:

- Entry condition
- Security gate or policy check
- Alternate path, fallback, or retry path
- Privileged action
- Evidence that the gate applies to every reachable path

This catches bugs where data flow looks benign in isolation but control flow enables a bypass.

## 2.6) Query CodeQL Structural Artifacts

Before manual code tracing for a DFD slice, check what CodeQL already computed. This does not
replace manual tracing — CodeQL's models are incomplete for custom wrappers and non-standard
frameworks. But it eliminates redundant work on paths where machine analysis is conclusive,
and flags exactly where CodeQL stopped tracking (the most interesting spots for manual review).

### A. Load the call graph slice

Open `vigolium-results/codeql-artifacts/call-graph-slices.json` and find the entry for the slice.

- **`reachable: true`**: CodeQL found a path. Read the shortest path array to get the concrete
  file:line chain. Start the manual trace at the first hop rather than re-deriving the entry point.
  Manually verify each intermediate node is correctly modeled.

- **`reachable: false`**: Not a guarantee of safety. Check: (a) is the source in `entry-points.json`?
  If absent, the built-in model lacks coverage — custom modeling required before the machine result
  is meaningful. (b) Is the sink in `sinks.json`? Same logic. If both are present and still no path,
  CodeQL found no connecting path — investigate whether this reflects genuine architectural isolation,
  or an unmodeled wrapper, type conversion, or async hop.

### B. Read informational nodes on the path

Open `vigolium-results/codeql-artifacts/flow-paths-all-severities.md`. Filter to rules and file paths
relevant to the slice. Informational results on a flow path mark nodes where CodeQL applied a
sanitizer model, type narrowing, or path termination. These are the exact locations to scrutinize:

- Sanitizer call site is conditional — only runs for certain input shapes
- Validation function appears once but the validated value is later unwrapped or re-encoded
- Flow path terminates at an async boundary or serialization hop that built-in models do not cross

### C. Consult the machine-generated DFD/CFD diagrams

The `## CodeQL Structural Analysis` section of `vigolium-results/attack-surface/knowledge-base-report.md` contains
machine-generated Mermaid DFD and CFD diagrams derived from the extracted artifacts. Use them as
a navigation aid: identify which path in the DFD matches the slice being reviewed, trace the
intermediate nodes, and check whether the CFD diagram models the security gates relevant to that
path. Annotate discrepancies between the machine-generated diagram and the actual code directly
in the KB as manual corrections.

### D. Use the live database for on-demand queries

The database at `vigolium-results/codeql-artifacts/db/` is live until Phase 12 completes. When a manual
trace raises a structural question answerable faster by machine — "are there other callers?",
"what paths reach this sink?", "which functions read this field?" — write and run a narrow QL query:

```bash
codeql query run \
  --database=vigolium-results/codeql-artifacts/db/ \
  --output=/tmp/on-demand.bqrs \
  -- vigolium-results/codeql-queries/on-demand-<slug>.ql

codeql bqrs decode --format=json /tmp/on-demand.bqrs
```

Store reusable on-demand queries at `vigolium-results/codeql-queries/on-demand-<slug>.ql`. These become
Phase 12 variant analysis inputs.

### E. Cross-reference entry-points with the KB attack surface

Compare `entry-points.json` against `## Attack Surface Summary` in `knowledge-base-report.md`.
Discrepancies where CodeQL found a recognized source absent from the manual KB indicate:
- An entry point missed by Phase 3 manual review
- A dynamically registered route, plugin hook, or generated endpoint invisible to static inspection

These discrepancies are high-priority Phase 10 targets.

### F. Scope and limitations

This method requires a working database with meaningful extraction coverage. If
the `## Static Analysis Summary` section of `vigolium-results/attack-surface/knowledge-base-report.md` documents `--build-mode=none` or low extraction quality,
do not treat `reachable: false` as meaningful — false negatives from poor extraction are likely.
Document the extraction quality limitation in the Phase 10 Addendum.

## 3) Analyze Control Internals

Read implementation code (not marketing docs) and extract:

- Exact mechanism (allowlist, parser, policy engine, sanitizer, verifier)
- Assumptions (type, encoding, order of operations, caller privilege)
- Preconditions required for the control to work
- Failure modes when assumptions are violated

## 4) Generate Attack Hypotheses

Derive hypotheses from observed assumptions:

- Encoding/normalization mismatches
- Alternative syntax paths
- Parser differential behavior
- Policy bypass via composition or ordering
- TOCTOU and async race windows
- Cross-boundary trust confusion
- Identity propagation drift across hops
- Schema or IDL drift between producers and consumers
- Control-plane action triggered from lower-trust surfaces
- Plugin, tool, or extension capability exposure beyond intended scope

Each hypothesis should name attacker capability and target asset.

## 5) RFC Gap Analysis Workflow

Use this when code appears to implement an RFC-based protocol or format.

### A. Identify RFC Scope in Code

- Locate parser/serializer/state-machine modules
- Map implemented sections to RFC requirements (MUST/SHOULD/MAY)
- Note unsupported sections and declared deviations

### B. Research Security-Relevant RFC Clauses

- Extract normative constraints affecting validation, canonicalization, auth, replay, downgrade, and interoperability
- Mark "MUST" clauses as required checks during review

### C. Map Historical Attack Patterns

- First, read the `## Domain Attack Research` section of `vigolium-results/attack-surface/knowledge-base-report.md`.
  Phase 3 Mode C already catalogued known attacks for the identified technology domains. Use the
  domain attack taxonomy and manual review checklist as the starting list — avoid re-researching
  what was already discovered.
- For any identified domain not covered by Phase 3 Mode C, research known attacks/CVEs against the
  protocol family using web search or MCP tools. See `references/domain-attack-playbooks.md` for
  per-domain templates.
- Translate patterns into test hypotheses for this implementation.
- Focus on parser confusion, downgrade, ambiguous canonical form, and state desync.

### D. Detect Implementation Gaps

For each clause/pattern, classify:

- Implemented correctly
- Partially implemented
- Missing
- Implemented but bypassable under composition

### E. Report RFC Gaps

Write findings to `rfc-gaps-report.md` with:

- RFC clause reference
- Relevant code path
- Gap classification
- Exploitability condition
- Security impact if abused

## 6) Parsing, Normalization, and Sanitization Discrepancies

Many historical vulnerabilities stem not from missing security controls but from the security control and the dangerous operation using different interpretations of the same input. These are often high-severity because they bypass controls that appear correct in isolation.

### URL and Path Parsing Discrepancies

The security check and the router/file handler may parse the same URL differently:

- **Percent-encoding**: a check that decodes `%2F` → `/` may be bypassed with double encoding `%252F` if the check only decodes once but the handler decodes twice.
- **Unicode normalization**: `%EF%BC%8F` (fullwidth solidus) may normalize to `/` after the security check runs.
- **Null bytes**: `path\x00.jpg` may pass an extension check but be truncated by the OS to `path`.
- **Trailing slashes and dots**: `/admin` vs `/admin/` vs `/admin.` may be treated differently by the router vs the auth check.
- **Backslash normalization**: `path\..\..\etc\passwd` on Windows may not be caught by a Unix-style path traversal check.

### Header Injection via Spec-Non-Compliant Parsing

- **CRLF injection**: if a header value is not stripped of `\r\n`, an attacker can inject additional headers.
- **Header folding**: obsolete HTTP/1.1 header folding (continuation lines starting with whitespace) may be parsed differently by proxies and backends.
- **Multiple header values**: `Authorization: Bearer token1\r\nAuthorization: Bearer token2` — which value does each layer use?
- **`X-Forwarded-For` and IP spoofing**: rate limiting or access control keyed on the client IP from `X-Forwarded-For` can be bypassed by adding the header.

### Content-Type and Format Confusion

- **ZIP/Office confusion**: `.docx`, `.xlsx`, `.jar` are ZIP files. A content-type check that allows `application/zip` may allow Office files, and vice versa.
- **Polyglot files**: a file that is simultaneously valid in two formats (e.g., a JPEG that is also a valid ZIP) can bypass format-specific checks.
- **Multipart boundary tricks**: a multipart body with a crafted boundary may be parsed differently by the framework vs the application code.
- **JSON/XML type confusion**: a field expected to be a string that accepts an object or array may bypass string-specific sanitization.

### Sanitization Applied at the Wrong Stage

- **Sanitize-then-parse**: sanitizing HTML before parsing means the parser may reconstruct dangerous markup from sanitized fragments (mutation XSS).
- **Parse-then-sanitize**: parsing before sanitizing means the sanitizer operates on the parsed DOM, which may differ from what the browser re-parses.
- **Double sanitization**: applying HTML encoding twice can produce encoded entities that are decoded by the browser into dangerous content.
- **Context mismatch**: sanitizing for HTML context but inserting into a JavaScript or CSS context.

### Spec-Non-Compliant Behavior as a Vulnerability Source

When a project implements a standard protocol or format, deviations from the spec are a primary source of exploitable bugs:

- **JWT algorithm confusion**: accepting `alg: none` or allowing RS256 tokens to be verified as HS256 (using the public key as the HMAC secret).
- **OAuth `redirect_uri` validation**: accepting prefix matches, allowing subdomains, or not validating the scheme allows open redirect and code theft.
- **OAuth `state` parameter omission**: missing or non-validated `state` enables CSRF on the OAuth callback.
- **XML namespace handling**: namespace-aware parsers and namespace-unaware parsers may interpret the same document differently, enabling signature wrapping attacks.
- **SAML assertion validation**: checking the wrong element, accepting unsigned assertions, or not validating the `InResponseTo` field.
- **HTTP request smuggling**: discrepancies between `Content-Length` and `Transfer-Encoding` handling between a proxy and a backend.
- **Cookie attribute parsing**: browsers and servers may parse `SameSite`, `Secure`, and `HttpOnly` attributes differently for malformed cookie headers.

### Canonicalization Attacks

- **Case normalization**: a check for `script` may miss `SCRIPT` or `Script` if case normalization happens after the check.
- **Unicode case folding**: `ı` (Turkish dotless i) uppercases to `I` in some locales, which can bypass case-insensitive checks.
- **Homoglyph substitution**: visually similar Unicode characters (e.g., Cyrillic `а` vs Latin `a`) may bypass string equality checks.
- **IDN homograph**: internationalized domain names can be used to bypass domain allowlists.

## 7) Validate in Context

When runtime checks are authorized:

- Use deterministic, minimal tests
- Verify both isolated and composed paths
- Re-check under realistic deployment assumptions

## 8) Evidence Quality Bar

High-quality deep-analysis evidence includes:

- Explicit trust-boundary crossing
- Concrete attacker-controlled input path
- Demonstrated or strongly justified control failure
- Concrete attacker gain tied to protected assets

## 9) How Later Phases Reuse the Model

Phase 3 DFD/CFD slices are not optional notes. Use them directly in later phases:

- **Phase 4**: generate custom CodeQL models, custom QL queries, and custom Semgrep rules for blind
  spots; also run structural extraction (method 2.6 inputs: entry-points.json, sinks.json,
  call-graph-slices.json, flow-paths-all-severities.md, machine-generated DFD/CFD diagrams)
- **Phase 5**: decide whether a SAST finding crosses a real trust boundary or reaches a real policy
  gate; use call-graph-slices.json for machine-assisted reachability before manual assessment
- **Phase 9**: map specs, IDLs, and contracts to the exact implementation points in the flow
- **Phase 10**: apply method 2.6 to front-load machine-computed path information before manual
  tracing; use informational nodes from flow-paths-all-severities.md to locate sanitizer/validation
  sites that warrant close scrutiny
- **Phase 11**: judge exploitability from actual flow reachability, not isolated code smell
- **Phase 12**: search for the same flow shape in sibling components using on-demand QL queries
  and AST-level structural matches against the live database
