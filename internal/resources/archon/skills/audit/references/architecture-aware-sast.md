# Architecture-Aware SAST

Use this reference when Phase 3 identifies high-risk flows that built-in tooling may model incompletely.

## Table of Contents

1. [Purpose](#purpose)
2. [Discovery Matrix](#discovery-matrix)
3. [SAST Layering Model](#sast-layering-model)
4. [How DFD and CFD Drive Modeling](#how-dfd-and-cfd-drive-modeling)
5. [Load These References Before Authoring](#load-these-references-before-authoring)
6. [Custom CodeQL Workflow](#custom-codeql-workflow)
7. [Custom Semgrep Workflow](#custom-semgrep-workflow)
8. [Semgrep Resource Tuning](#semgrep-resource-tuning)
9. [Architecture Examples](#architecture-examples)

## Purpose

Run built-in CodeQL and built-in Semgrep coverage first. Add custom CodeQL and Semgrep coverage only when the architecture introduces blind spots:

- custom wrappers around request parsing, RPC, auth, storage, or execution
- generated interfaces, schemas, or IDLs that hide trust-boundary crossings
- unusual transports or execution models
- policy decisions separated from the dangerous sink by orchestration layers
- complex multi-component flows where attacker control or identity propagation is easy to misread

Custom rules do not replace built-in rules. They close gaps that built-ins cannot see well enough.

## Discovery Matrix

Use this matrix to decide what must be modeled.

| Dimension | What to Inventory | Why It Matters |
|----------|-------------------|----------------|
| Ingress | HTTP handlers, CLI args, files, IPC, queues, webhooks, plugins, tool invocations | Identifies attacker-controlled sources |
| Synchronous transports | HTTP clients, RPC clients, gRPC stubs, SDK wrappers, service clients | Identifies cross-component trust handoffs |
| Asynchronous transports | queues, topics, events, schedulers, workers, retries | Identifies delayed or reordered security assumptions |
| Control-plane interfaces | admin APIs, job orchestration, deployment hooks, agent control channels | Identifies higher-privilege decision paths |
| Plugin and tool execution | extension APIs, agent tools, capability registration, command execution | Identifies confused-deputy and unsafe exposure risk |
| Storage and serialization | ORM wrappers, caches, blobs, message encoders, protocol codecs | Identifies sink classes and parser drift |
| Identity propagation | session lookup, token forwarding, headers, metadata, claims, tenant context | Identifies authn/authz blind spots |
| Dependency and supply chain edges | manifests, lockfiles, build files, images, sidecars, generated code | Identifies vulnerable libraries and hidden execution paths |

## SAST Layering Model

Always apply SAST in this order:

1. **Built-in CodeQL suites**
   Use standard built-in suites for the languages present.
2. **Built-in Semgrep baseline and language/framework rulesets**
   Use whole-repo baseline coverage plus language and framework rulesets.
3. **Custom CodeQL modeling**
   Add data extensions and narrow QL queries where built-ins miss real flows or control invariants.
4. **Custom Semgrep rules**
   Add structural and pattern rules for unsafe registration, missing middleware, policy bypasses, and architecture-specific misuse patterns.

Document the split in the `## Static Analysis Summary` section of `archon/knowledge-base-report.md`.

## How DFD and CFD Drive Modeling

Use Phase 3 outputs directly:

- **DFD slices** identify sources, summaries, sinks, trust-boundary crossings, and serialization boundaries.
- **CFD slices** identify policy gates, alternate paths, fallbacks, retries, orchestration logic, and bypass edges.

For each high-risk slice, answer:

1. Which input is attacker-controlled?
2. Which transformations preserve or amplify attacker influence?
3. Which decision points gate access or privilege?
4. Which sink causes real impact?
5. Which part is already covered by built-in tooling?
6. Which part needs custom modeling?

## Load These References Before Authoring

Do not invent custom query or rule structure from memory. Open the relevant reference or template first.

**For custom CodeQL models and queries:**
- `../codeql/workflows/create-data-extensions.md`
- `../codeql/workflows/run-analysis.md`
- `../codeql/references/extension-yaml-format.md`
- `../codeql/references/diagnostic-query-templates.md`
- `../variant-analysis/resources/codeql/<language>.ql`

**For custom Semgrep rules:**
- `../variant-analysis/resources/semgrep/<language>.yaml`
- `../semgrep/references/rulesets.md`

Pick `<language>` from the repo slice you are modeling. Use the variant-analysis resources as a starting template, then narrow the pattern to the specific DFD/CFD slice.

## Custom CodeQL Workflow

Workflow:

1. Start from the highest-risk DFD slice.
2. Identify missing sources, summaries, or sinks caused by wrappers, adapters, generated interfaces, or custom transport layers.
3. Open `../codeql/workflows/create-data-extensions.md` and follow it to create the missing data extensions.
4. Use `../codeql/references/extension-yaml-format.md` for the exact YAML columns and language-specific format rules.
5. Use `../codeql/references/diagnostic-query-templates.md` to build source and sink enumeration queries and confirm the new models are recognized.
6. Start the custom QL file from `../variant-analysis/resources/codeql/<language>.ql`, then narrow it to the specific invariant from the DFD/CFD slice.
7. Add narrow custom QL queries only for architecture-specific invariants, such as:
   - missing authorization gate before a privileged sink
   - identity forwarded without re-verification
   - unsafe fallback path after a policy failure
   - parsing or schema mismatch between adjacent layers
8. Store artifacts under `archon/codeql-queries/`. Store slice reachability queries as
   `archon/codeql-queries/slice-<name>.ql` — distinct from security-finding queries; their
   purpose is structural validation of Phase 3 DFD slices, not vulnerability detection.
9. In the report, cite the DFD/CFD slice that motivated each custom model or query.

Prefer one narrow query per invariant over a broad speculative query pack.

## Structural Extraction Workflow

Run at the start of Phase 4, before any security scan, using the freshly built database stored at
`archon/codeql-artifacts/db/`. The purpose is structural intelligence — not security findings.
The outputs feed Phase 3 KB validation, Phase 4 inline enrichment, Phase 7 deep bug hunting, and
Phase 9 variant analysis.

### Why informational results matter

CodeQL's `note`-level and informational results represent data flow nodes that CodeQL modeled but
did not classify as exploitable under the current threat model or built-in query logic. These include
sanitizer call sites, validation function calls, encoding/decoding nodes, transformation summaries,
and intermediate propagation nodes on paths that terminate before a known sink. Retaining them gives
manual reviewers an annotated map of where CodeQL tracked data and where it stopped — a negative
result from CodeQL is as informative as a positive one.

### Output files

All outputs go to `archon/codeql-artifacts/`:

| File | Content | Used by |
|------|---------|---------|
| `entry-points.json` | All recognized source nodes, by type and file:line | Phase 3 KB validation, Phase 5 |
| `sinks.json` | All recognized sink nodes, by kind and file:line | Phase 5, Phase 7 |
| `call-graph-slices.json` | Per-DFD-slice reachability: reachable bool, hop count, shortest paths | Phase 5, Phase 7 |
| `flow-paths-raw.sarif` | Full unfiltered SARIF including note/none severity (git-ignored) | Phase 7 on-demand |
| `flow-paths-all-severities.md` | Human-readable summary of informational/low results by rule | Phase 5, 7 |

### Step 1: Source enumeration

For each language in the repo, run the source enumeration query (RemoteFlowSource template, adjusted
per language). Expand threat model scope if Phase 3 KB identified CLI args or env vars as
attacker-controlled.

```bash
codeql query run \
  --database=archon/codeql-artifacts/db/ \
  --output=archon/codeql-artifacts/entry-points.bqrs \
  -- archon/codeql-queries/list-sources.ql

codeql bqrs decode \
  --format=json \
  --output=archon/codeql-artifacts/entry-points.json \
  archon/codeql-artifacts/entry-points.bqrs
```

Include a `threat_model` field per record. Run additional passes with `--threat-model local` and
`--threat-model environment` as needed and merge outputs.

### Step 2: Sink enumeration

Run the sink enumeration query for the detected language. Decode to `archon/codeql-artifacts/sinks.json`.
Group results by `kind` field.

### Step 3: Call graph slice queries

For each high-risk DFD slice in `archon/knowledge-base-report.md` under
`## Phase 4 CodeQL Extraction Targets`, author a narrow QL path-problem query that tests
reachability from the identified source type to the identified sink kind. Use variant-analysis
QL templates as a starting point. Store queries at `archon/codeql-queries/slice-<name>.ql`.
Run with `--threat-model all`. Decode to JSON records in `call-graph-slices.json`:

```json
{
  "slice": "user-input-to-exec",
  "reachable": true,
  "path_count": 3,
  "shortest_paths": [
    ["src/api/handler.py:42", "src/util/shell.py:17", "src/exec/run.py:91"]
  ]
}
```

If `reachable: false`, record as a meaningful signal for Phase 5: either the DFD slice is a
false concern, or the source/sink models are incomplete and custom modeling is needed.

### Step 4: Full raw SARIF with all severities

Run the full security-and-quality suite with `--threat-model all`, writing unfiltered output:

```bash
codeql database analyze archon/codeql-artifacts/db/ \
  --format=sarif-latest \
  --output=archon/codeql-artifacts/flow-paths-raw.sarif \
  --threads=0 \
  --threat-model all
```

Expect 1.5-3x the file size of the security-only SARIF. This file is git-ignored.

### Step 5: Human-readable informational summary

Extract all `note`-level or unleveled results from the raw SARIF. Group by rule ID and write to
`archon/codeql-artifacts/flow-paths-all-severities.md` with sections per rule category. This
is the file Phase 7 reviewers read to understand where CodeQL tracked data and where it terminated.

### Step 6: Generate Mermaid DFD and CFD diagrams

After the JSON artifacts are written, generate machine-assisted DFD and CFD Mermaid diagrams and
write them into the `## CodeQL Structural Analysis` section of `archon/knowledge-base-report.md`.

**DFD diagram** — derive from `entry-points.json`, `call-graph-slices.json`, and `sinks.json`:

- Nodes: all entry point file:lines as source boxes; all sink file:lines as sink boxes with their kind label
- Intermediate nodes: for each reachable slice, include the intermediate call nodes from the
  shortest path array as intermediate boxes
- Solid edges: source → intermediate → sink for reachable slices
- Dashed edges with label `no path (CodeQL)`: for slices where `reachable: false`

Write the resulting `flowchart LR` Mermaid block to the `### Machine-Generated DFD Diagram`
subsection of the KB.

**CFD diagram** — derive from `flow-paths-all-severities.md` and `flow-paths-raw.sarif`:

- Extract security-relevant conditional branch points from informational CodeQL results
  (guards, validators, sanitizer calls) that appear on call-graph paths
- Model each as a decision node with `passes` and `fails` edges
- Include any known fallback/alternate paths from CFD slices in the Phase 3 KB
- Write the resulting `flowchart TD` Mermaid block to the `### Machine-Generated CFD Diagram`
  subsection of the KB

If a diagram would exceed ~30 nodes, limit to the highest-risk slice paths only and note the
truncation. If CodeQL extraction quality was low (few recognized sources/sinks), mark the diagram
as `[incomplete — low extraction coverage]` rather than presenting misleading auto-generated paths.

### Step 7: Update KB — CodeQL Structural Analysis section

After all extraction steps complete, populate the `## CodeQL Structural Analysis` section of
`archon/knowledge-base-report.md` from the JSON artifacts:

- Fill entry point and sink tables from `entry-points.json` and `sinks.json`
- Fill the call graph reachability table from `call-graph-slices.json`
- Fill the informational flow node summary from `flow-paths-all-severities.md`
- Cross-reference with the Phase 3 KB attack surface: flag any CodeQL-discovered source
  missing from `## Attack Surface Summary`
- Embed the Mermaid DFD and CFD diagrams from Step 6

### When to skip

Skip only if the CodeQL database build fails entirely (zero extracted files). Document the skip in
`archon/knowledge-base-report.md`. The Phase 4 enrichment substep, Phase 7, and Phase 9 fall back to pure manual analysis.
Do not skip for small repos — call graph reachability data is most valuable where DFD construction
is complete but unvalidated.

## Custom Semgrep Workflow

Use custom Semgrep rules for structural and local patterns that are faster to express than QL, especially when you need to detect:

- missing middleware, interceptors, or registration hooks
- unsafe handler or tool exposure
- privileged operations reachable from low-trust interfaces
- inconsistent validation or policy checks across sibling code paths
- wrappers that built-in Semgrep rules do not understand

Workflow:

1. Start from the highest-risk CFD slice.
2. Identify the required security gate, registration step, or wrapper contract.
3. Start the rule from `../variant-analysis/resources/semgrep/<language>.yaml`, then replace the generic pattern with the concrete unsafe shape from the slice.
4. Keep the rule narrow: detect the missing gate, unsafe registration, or bypass shape, not every loosely related construct nearby.
5. Scope the rule to the relevant files, paths, or languages.
6. Validate the rule by checking that it matches the known risky instance and does not explode into noisy unrelated results.
7. Store artifacts under `archon/semgrep-rules/`.
8. In the report, cite the DFD/CFD slice that motivated each custom rule.

Prefer a small set of precise rules over a large catch-all ruleset that is expensive and noisy.

## Semgrep Resource Tuning

Semgrep Pro can be expensive on large repos. Keep coverage while avoiding host saturation:

1. Run a whole-repo baseline pass for high-signal built-in rulesets.
2. Separate Pro-heavy taint passes from lightweight structural passes.
3. Batch Pro-heavy scans by high-risk subsystem or architecture slice, not all at once.
4. Use file, path, and language scoping aggressively for targeted passes.
5. Prefer targeted follow-up passes for custom rules instead of repeating whole-repo broad scans.
6. Record any batching, throttling, or narrowed scope in the `## Static Analysis Summary` section of `archon/knowledge-base-report.md`.

The required outcome is bounded runtime without dropping mandatory built-in baseline coverage.

## Architecture Examples

Treat these as examples, not the full scope:

- service-to-service HTTP APIs
- gRPC and generated RPC clients
- message brokers, queues, workers, and schedulers
- plugins, extensions, and tool ecosystems
- agent frameworks and MCP servers
- desktop or local IPC
- mixed control-plane and data-plane systems

The discovery matrix and DFD/CFD slices decide what to model. Do not hard-code the audit to a short list of architecture names.
