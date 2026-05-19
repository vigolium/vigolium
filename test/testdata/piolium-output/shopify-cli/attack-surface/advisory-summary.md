# Stage 01 Advisory, Dependency, and Architecture Intelligence — Shopify CLI

Generated: 2026-05-01  
Target: `/Users/bytedance/Desktop/oss-to-run/shopify-cli`  
Repository identity: `shopify/cli` (resolved via git remote).  
Current checked-out HEAD observed during audit: `c3e54bea421d23743b5f2b83b34347f5bb729cc4`.

## Executive Summary

No public first-party CVE/GHSA/OSV advisory was found for the published Shopify CLI workspace packages queried (`@shopify/cli`, `@shopify/cli-kit`, `@shopify/create-app`, `@shopify/theme`, `@shopify/app`, `@shopify/store`, and plugin packages). However, Stage 01 found:

- **9 structured GHSA/OSV advisories affecting current direct dependency versions** in the lockfile: `liquidjs@10.25.0`, `lodash@4.17.23`, and `vite@6.4.1`.
- **4 project-hosted non-CVE security signals** in release notes / git history: GraphiQL authorization hardening, theme-dev CORS hardening, GraphiQL script-context XSS hardening on a non-main branch, and a critical Windows `treeKill` command-injection fix that exists on remote branches but is **not an ancestor of current HEAD**.
- **22 vulnerable lockfile package-version entries / 29 unique GHSA records** across direct and transitive dependencies from OSV querybatch, including a critical `protobufjs@7.5.4` advisory reachable through OpenTelemetry telemetry dependencies until proven otherwise.

Primary audit focus for later phases: **localhost browser-facing dev servers**, **template/config/file parsing**, **process execution / external binary management**, and **OAuth/session/token flows**.

## Historical Coverage Metadata

| Field | Value |
|---|---|
| Tier reached | Tier 2 (all-time expansion). Recent first-party public advisory count was 0, below the 15-advisory signal threshold. |
| Inventory rows in this report | 13 total: 9 official GHSA/OSV direct-dependency advisories + 4 project-hosted non-CVE security signals. |
| Recent vs older | Recent 2yr: 12 rows; older: 1 row (2023 GraphiQL random-key hardening). Public first-party advisories: 0 all-time from queried structured sources. |
| Severity distribution (inventory rows) | CRITICAL: 1, HIGH: 6, MEDIUM: 5, LOW: 1. |
| Repository identity | `shopify/cli` resolved via git remote. |
| Git history available | true (`PIGOLIUM_GIT_AVAILABLE=true`; `.git` available). |
| Source 1 local signals | Ran grep over docs/release notes and git history. No CVE/GHSA IDs in markdown/txt/rst; security commits/release notes found. Raw evidence: `piolium/tmp/source1-local-security-signals.txt`. |
| Source 2 GitHub Security Advisories | `gh api` attempted but blocked by invalid gh credentials (HTTP 401 bad credentials). Supplementary unauthenticated GitHub REST checks for first-party packages and repo advisories returned 0. Coverage gap recorded. |
| Source 3 OSV | First-party package query returned 0 advisories. Versioned direct-dependency query returned 9 advisories. Full lockfile OSV query found 22 vulnerable package-version entries / 38 package-version advisory hits. |
| Source 4 NVD | Keyword query found `CVE-2026-35525` (LiquidJS) via `shopify theme`; direct advisory CVSS enriched via NVD `cveId` queries where available. |
| Source 5 WebSearch | Not used; structured sources and curl/API lookups were sufficient, and user warned WebSearch only returns fallback in this environment. |
| Patch-commit discovery | Local git was available. Project-hosted signal diffs saved under `piolium/tmp/local-security-diffs/`. Upstream dependency patch commits taken from OSV/GHSA references. No first-party public advisory version-to-version diff was applicable because public first-party advisories were not found. |
| Coverage gaps | GitHub `gh api/graphql` source unavailable due invalid token; private Dependabot alert details (#91/#108) referenced by commits are not accessible without repository security access; some local security commits are on non-main remote branches and require merge-state verification. |

## Advisory Inventory

### A. Official GHSA/OSV advisories affecting current direct dependency versions

| ID | Severity | CVSS | Affected package/version | Affected versions | Patched version / commit | CWE IDs | Inferred component | Description |
|---|---:|---:|---|---|---|---|---|---|
| GHSA-r5fr-rjxr-66jc (CVE-2026-4800) | HIGH | 8.1 | lodash@4.17.23 | >=4.0.0, <4.18.0 | 4.18.0; 3469357cff396a26c363f8c1b5a91dde28ba4b1c | CWE-94 | cli-kit common object/path helpers | lodash vulnerable to Code Injection via `_.template` imports key names |
| GHSA-p9ff-h696-f583 (CVE-2026-39363) | HIGH | 7.5 | vite@6.4.1 | >=8.0.0, <8.0.5; >=7.0.0, <7.3.2; >=6.0.0, <6.4.2 | 8.0.5, 7.3.2, 6.4.2; f02d9fde0b195afe3ea2944414186962fbbe41e0 / PR #22159 | CWE-200, CWE-306 | ui-extensions dev console build/dev tooling | Vite Vulnerable to Arbitrary File Read via Vite Dev Server WebSocket |
| GHSA-56p5-8mhr-2fph (CVE-2026-35525) | HIGH | 7.5 | liquidjs@10.25.0 | <10.25.3 | 10.25.3; PR #867 / release v10.25.3 | CWE-61 | cli-kit Liquid template rendering / app init+extension template copy | LiquidJS: Root restriction bypass for partial and layout loading through symlinked templates |
| GHSA-4rc3-7j7w-m548 (CVE-2026-41311) | HIGH | 7.5 | liquidjs@10.25.0 | <10.25.7 | 10.25.7; e2311dfd6e82f73509308aa8a3a1fafc92e226f0 | CWE-674 | cli-kit Liquid template rendering / app init+extension template copy | liquidjs has a Denial of Service via circular block reference in layout |
| GHSA-f23m-r3pf-42rh (CVE-2026-2950) | MEDIUM | 6.5 | lodash@4.17.23 | <4.18.0; >=4.0.0, <4.18.0 | 4.18.0; fixed in lodash 4.18.0 (advisory refs) | CWE-1321 | cli-kit common object/path helpers | lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit` |
| GHSA-4w7w-66w2-5vf9 (CVE-2026-39365) | MEDIUM | 5.3 | vite@6.4.1 | >=8.0.0, <8.0.5; >=7.0.0, <7.3.2; <6.4.2 | 8.0.5, 7.3.2, 6.4.2; 79f002f2286c03c88c7b74c511c7f9fc6dc46694 / PR #22161 | CWE-200, CWE-22 | ui-extensions dev console build/dev tooling | Vite Vulnerable to Path Traversal in Optimized Deps `.map` Handling |
| GHSA-rv5g-f82m-qrvv (CVE-2026-39412) | MEDIUM | 5.3 | liquidjs@10.25.0 | <10.25.4 | 10.25.4; e743da0020d34e2ee547e1cc1a86b58377ebe1ce / PR #869 | CWE-200 | cli-kit Liquid template rendering / app init+extension template copy | LiquidJS: ownPropertyOnly bypass via sort_natural filter — prototype property information disclosure through sorting side-channel |
| GHSA-v273-448j-v4qj (CVE-2026-39859) | MEDIUM | 7.5 | liquidjs@10.25.0 | <10.25.5 | 10.25.5; f41c1fc02fe901598f3328118b42b13bc6bc9b04 / PR #870 | CWE-22 | cli-kit Liquid template rendering / app init+extension template copy | LiquidJS: `renderFile()` / `parseFile()` bypass configured `root` and allow arbitrary file read |
| GHSA-mmg9-6m6j-jqqx (CVE-2026-34166) | LOW | 3.7 | liquidjs@10.25.0 | <10.25.3 | 10.25.3; abc058be0f33d6372cd2216f4945183167abeb25 | CWE-400 | cli-kit Liquid template rendering / app init+extension template copy | LiquidJS Has Memory Limit Bypass via Quadratic Amplification in `replace` Filter |

### B. Project-hosted non-CVE security signals

| ID | Severity | CVSS | Affected versions / scope | Patch commit(s) | CWE IDs | Inferred component | Description |
|---|---:|---:|---|---|---|---|---|
| LOCAL-GIT-2026-treeKill-command-injection | CRITICAL (commit-labeled) | N/A | Current `main` at `c3e54bea` still shows pre-fix `Number.isNaN(rootPid)` + `exec(\`taskkill /pid ${pid}\`)`; fix exists only on remote branches | `f4de6ef1ab`, `0b38241657` (not ancestors of current HEAD) | CWE-78 | `@shopify/cli-kit` process-tree cleanup / Windows `taskkill` | Windows PID string validation allowed shell metacharacters before replacing `exec` with `spawn` and strict `/^\d+$/` validation. |
| LOCAL-GIT-2025-theme-dev-cors | MEDIUM | N/A | Fixed in `@shopify/theme` 3.88.0; release note 3.88 | `226b49e740` / PR #6607 | CWE-942 / CWE-346 | Theme dev localhost proxy (`packages/theme/.../theme-environment`) | Removed wildcard/proxied CORS headers so arbitrary websites cannot read local theme dev server data. |
| LOCAL-GIT-2025-graphiql-config-xss | HIGH | N/A | Non-main branch signal (`origin/feat/graphiql-standalone-package`); not ancestor of current HEAD | `7719dd5af5` | CWE-79 | App dev GraphiQL local server config injection | Escaped `<`, `>`, `&` when embedding query-derived JSON into a `<script>` block. |
| LOCAL-GIT-2023-graphiql-random-key | HIGH | N/A | Fixed in `@shopify/app` 3.52.0 | `adba3d9bb7`, `fa3266ea42`, `306c0f6d37` / PR #3168 | CWE-306 / CWE-287 | App dev GraphiQL local server | Added random key to GraphiQL URL/API requests and changed unauthorized behavior to baseline-like 404. |

Notes:

- `LOCAL-GIT-*` rows are not public CVE/GHSA records. They are included because the repo itself labels or describes them as security fixes and they materially shape audit targeting.
- For `treeKill`, the checked-out source still shows the vulnerable pre-fix pattern at `packages/cli-kit/src/public/node/tree-kill.ts` while fix commits exist on remote branches. Treat as a **high-priority merge/regression target** in Phase 2/5 rather than as a resolved historical issue.

## Vulnerability Pattern Analysis

### Component Vulnerability Heatmap

| Component / module | Count | Severity distribution | Dominant bug types | Heat flag |
|---|---:|---|---|---|
| `@shopify/cli-kit` Liquid template rendering / app init + extension template copy (`liquidjs`) | 5 | HIGH: 2, MEDIUM: 2, LOW: 1 | Symlink/root restriction bypass, arbitrary file read, info disclosure, resource exhaustion | **HIGH-HEAT** (3+ advisories) |
| App dev GraphiQL local server | 2 | HIGH: 2 | Broken auth / missing random key, script-context XSS/config injection | **HIGH-HEAT** (recurring security fixes) |
| UI extensions Vite dev/build tooling | 2 | HIGH: 1, MEDIUM: 1 | Dev-server WebSocket arbitrary file read, optimized-deps path traversal | Medium/high |
| `@shopify/cli-kit` common object helpers via `lodash` | 2 | HIGH: 1, MEDIUM: 1 | Code injection in template helper, prototype pollution via path operations | Medium/high |
| Theme dev localhost proxy/server | 1 | MEDIUM: 1 | CORS policy/data exposure from localhost server | Medium |
| `@shopify/cli-kit` process management / `treeKill` | 1 | CRITICAL: 1 | Windows command injection through shell execution | **HIGH-HEAT** (critical) |

High-heat architecture layers: local dev HTTP servers and shared `cli-kit` helpers map directly to Phase 3 DFD slices.

### Bug Type Recurrence

| Bug class | CWEs | Count | Examples | Recurrence |
|---|---|---:|---|---|
| Path traversal / arbitrary file read | CWE-22, CWE-61, CWE-200 | 4 | LiquidJS symlink/root bypass; LiquidJS `renderFile/parseFile` arbitrary read; Vite source-map traversal; Vite WebSocket file read | **Recurring** |
| DoS / resource exhaustion | CWE-400, CWE-674 | 2 | LiquidJS circular layout; LiquidJS `replace` amplification | **Recurring** |
| Command/code injection | CWE-78, CWE-94 | 2 | Windows `treeKill`; lodash `_.template` imports-key code injection | **Recurring** |
| Auth bypass / broken auth | CWE-287, CWE-306 | 2 | GraphiQL random-key hardening; Vite WS no-auth file-read advisory | **Recurring** |
| Info disclosure / cross-origin data exposure | CWE-200, CWE-942, CWE-346 | 3 | Theme dev CORS; LiquidJS sort side-channel; Vite file reads | **Recurring** |
| XSS / script injection | CWE-79 | 1 | GraphiQL config JSON embedded in `<script>` | Single but high-impact in local dev browser context |
| Prototype pollution | CWE-1321 | 1 direct; multiple transitive | lodash `unset/omit`; transitive `defu`, `flatted`, `immutable` | Recurs in dependency graph |
| Glob/parser ReDoS | CWE-400 class | Multiple transitive | `minimatch`, `picomatch`, `brace-expansion` | Recurs in lockfile |

### Attack Surface Trends

1. **Browser-origin to localhost dev servers** — Theme dev CORS, GraphiQL auth/XSS, Vite WS/file-read advisories all point to risk when a malicious website can reach `localhost`, a bound dev-host interface, or a tunnel URL.
2. **Filesystem/template/config parsing** — Liquid templates, generated extension templates, TOML/YAML app/theme config, glob patterns, and theme files are recurrent parser inputs.
3. **CLI arguments, env vars, and process execution** — `treeKill`, `execa`, `execCommand`, `SHOPIFY_CLI_CLOUDFLARED_PATH`, global proxy env variables, and external tool invocation are privileged local-machine boundaries.
4. **Network proxying and token-bearing HTTP** — Shopify Admin/Partners/Identity GraphQL/REST, storefront renderer proxying, `follow-redirects`, `undici`, and custom header forwarding can expose tokens or local services if redirect/CORS/header filtering is incomplete.
5. **OAuth/session persistence** — Store auth PKCE local callback, device auth/session store, and token refresh flows repeatedly cross browser/local/Shopify platform boundaries.

### Patch Quality Signals

| Structural recurrence candidate | Evidence | Patch-bypass hypothesis |
|---|---|---|
| GraphiQL/local dev browser interface | 2023 random-key auth hardening + 2025 script-context XSS branch + permissive CORS/ping/status support in current server | Review every GraphiQL route and generated HTML for key enforcement, origin policy, script-context escaping, forwarded headers, and token leakage. |
| Localhost dev servers as a class | Theme dev CORS fix + GraphiQL fixes + Vite dev-server advisories | Apply a common local-server policy: bind to loopback by default, deny wildcard CORS on sensitive routes, require unguessable keys for token-bearing APIs, and test malicious-browser requests. |
| Template rendering and scaffolding | 5 LiquidJS advisories plus `recursiveLiquidTemplateCopy` over downloaded/generated template directories | Update `liquidjs` and test symlink/include/render/path traversal and DoS payloads in app init/generate and extension-template flows. |
| Process execution cleanup | Critical `treeKill` fix exists on non-main branches while current HEAD still shows pre-fix shell execution | Verify merge status and all process-kill call sites; ensure no shell invocation receives strings derived from args/env/PIDs. |
| Object-path operations | lodash prototype pollution advisory and codebase wrappers `getPathValue/setPathValue/unsetPathValue` | Audit paths sourced from extension specifications, remote config, TOML, GraphQL, or user input for `__proto__`/constructor/prototype pollution. |

## Architecture Inventory

### Components

- **`@shopify/cli`**: oclif entrypoint/command registry; wires app, theme, store, Hydrogen, oclif plugin commands, and global proxy support.
- **`@shopify/cli-kit`**: shared platform layer for auth/session storage, GraphQL/REST requests, filesystem/path helpers, Liquid rendering, process execution, local config/conf store, UI, telemetry, and error handling.
- **`@shopify/app`**: app init/generate/build/deploy/dev; extension templates; app dev process supervisor; local GraphiQL server; dev proxy/tunnel integration; TOML config transforms.
- **`@shopify/theme`**: theme commands; theme dev local h3 server; hot reload; local/remote file sync; storefront renderer/CDN proxy; theme check; package/push/pull.
- **`@shopify/store`**: store auth PKCE flow, local callback listener, persisted app sessions, Admin GraphQL execute command.
- **`@shopify/plugin-cloudflare`**: downloads and executes `cloudflared`; provides tunnel provider/start hooks.
- **UI extension packages**: dev console React app/server-kit, Vite-built assets, test utilities.
- **Workspace/release tooling**: Nx, Changesets, release scripts, docs/schema generation, GitHub automation scripts.

### Transports and data paths

- CLI args, flags, stdin, environment variables, local config files, generated templates, and project directories.
- Local HTTP servers on `localhost` / configured host: GraphiQL, theme dev server, OAuth callback, hot reload/WebSocket-like flows.
- HTTPS/GraphQL/REST to Shopify Admin, Partners, Identity, storefront renderer, GitHub template repositories, and Cloudflare release downloads.
- Cloudflare tunnels and browser-open flows, including preview and GraphiQL URLs.
- Child processes and external tools via `execa`, `spawn`, `execCommand`, `open`, `taskkill`, `tar`, `cloudflared`, package managers, build tools.

### Trust boundaries

- **Internet/browser → local developer machine**: malicious websites, preview/tunnel users, or browser pages reaching local dev endpoints.
- **User project/template repo → CLI process**: untrusted app/theme/extension templates, TOML/YAML/JSON, Liquid, globs, symlinks, and generated files.
- **CLI process → Shopify platform**: token-bearing GraphQL/REST requests, token refresh, Admin/Partners/Storefront APIs.
- **CLI process → external binaries/plugins**: cloudflared, package managers, esbuild/native modules, ast-grep native package.
- **CI/release automation → repository/package publishing**: Changesets, Nx, GitHub scripts, Homebrew/release tooling.

### Highest-risk flows for Phase 3 DFD/CFD

1. `shopify app dev`: app config/TOML → dev process setup → tunnel/proxy → GraphiQL local server → Admin API token use.
2. `shopify theme dev`: theme filesystem watcher → local h3 server → storefront renderer/CDN proxy → browser origins/CORS/cookies.
3. App/extension generation: remote or selected template repo → Liquid rendering / file copy → local project filesystem.
4. Store auth/execute: browser PKCE flow → loopback callback → token persistence → Admin GraphQL execution from stdin/file/CLI args.
5. Process and plugin lifecycle: tunnel install/start/kill, child-process cleanup, env-controlled binary paths and proxy settings.

## Dependency Intelligence

### Manifest and lockfile overview

- Package manager: `pnpm@10.11.1`.
- Workspace packages: 14 named package manifests plus root workspace.
- Unique direct dependency names across manifests: 161.
- Versioned OSV direct-dependency checks: 156 package/version queries; 3 vulnerable direct packages; 9 advisory hits.
- Versioned OSV lockfile checks: 1,903 package/version queries in chunks; 22 vulnerable package-version entries; 38 package-version advisory hits; 29 unique GHSA IDs.

### Current direct dependency advisories requiring triage

| Dependency | Current use | Advisories | Immediate dependency action | Reachability questions |
|---|---|---|---|---|
| `liquidjs@10.25.0` | Root dev dep and `@shopify/cli-kit` runtime dependency for `renderLiquidTemplate` / `recursiveLiquidTemplateCopy` | 5 GHSA: file read/path traversal/info disclosure/DoS | Upgrade to at least `10.25.7` to cover all listed LiquidJS fixes. | Can attacker-controlled templates use `include/render/layout`, symlinks, or deep/circular constructs during app init/generate/extension template rendering? |
| `lodash@4.17.23` | `@shopify/cli-kit` runtime common helpers, including object path wrappers | Code injection in `_.template`, prototype pollution in `_.unset/omit` | Upgrade to `4.18.0` when available/compatible; meanwhile constrain path inputs. | Are `setPathValue/getPathValue/unsetPathValue` paths ever sourced from remote extension specs, TOML, GraphQL, or user-controlled arrays containing `__proto__`/constructor? |
| `vite@6.4.1` | UI extensions dev console/server-kit dev/build tooling | WebSocket arbitrary file read; optimized deps map path traversal | Upgrade to `6.4.2` (or newer) in affected workspaces. | Is any Vite dev server bound beyond loopback during development/CI, or reachable from untrusted browsers? |

### Lockfile transitive advisory clusters

| Package@version | Worst severity | Count | Advisories / themes | Likely parent(s) observed in lockfile |
|---|---:|---:|---|---|
| protobufjs@7.5.4 | CRITICAL | 1 | GHSA-xq3m-2v4x-88gg (CRITICAL)<br>Arbitrary code execution in protobufjs | @opentelemetry/otlp-transformer -> cli-kit telemetry |
| defu@6.1.4 | HIGH | 1 | GHSA-737v-mqg7-c878 (HIGH)<br>defu: Prototype pollution via `__proto__` key in defaults argument | h3 (runtime local servers) |
| flatted@3.3.3 | HIGH | 2 | GHSA-25h7-pfq9-p65f (HIGH), GHSA-rf6f-7fwh-wjgh (HIGH)<br>Prototype Pollution via parse() in NodeJS flatted; flatted vulnerable to unbounded recursion DoS in parse() revive phase | flat-cache (eslint/tooling) |
| immutable@3.7.6 | HIGH | 1 | GHSA-wf6x-7x77-mvgw (HIGH)<br>Immutable is vulnerable to Prototype Pollution | relay-compiler / sass |
| immutable@5.1.4 | HIGH | 1 | GHSA-wf6x-7x77-mvgw (HIGH)<br>Immutable is vulnerable to Prototype Pollution | relay-compiler / sass |
| liquidjs@10.25.0 | HIGH | 5 | GHSA-4rc3-7j7w-m548 (HIGH), GHSA-56p5-8mhr-2fph (HIGH), GHSA-mmg9-6m6j-jqqx (LOW), GHSA-rv5g-f82m-qrvv (MEDIUM), GHSA-v273-448j-v4qj (MEDIUM)<br>LiquidJS Has Memory Limit Bypass via Quadratic Amplification in `replace` Filter; LiquidJS: Root restriction bypass for partial and layout loading through symlinked templates; LiquidJS: `renderFile()` / `parseFile()` ... | direct cli-kit/root |
| lodash@4.17.23 | HIGH | 2 | GHSA-f23m-r3pf-42rh (MEDIUM), GHSA-r5fr-rjxr-66jc (HIGH)<br>lodash vulnerable to Code Injection via `_.template` imports key names; lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit` | direct cli-kit |
| minimatch@9.0.3 | HIGH | 3 | GHSA-23c5-xmqv-rm74 (HIGH), GHSA-3ppc-4f35-3m26 (HIGH), GHSA-7r86-cg39-jmmj (HIGH)<br>minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions; minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBSTAR segments; minimatch has a ... | @nx/devkit / @oclif/core / eslint |
| picomatch@2.3.1 | HIGH | 2 | GHSA-3v7f-55p6-f55p (MEDIUM), GHSA-c2c7-rcm5-vvqj (HIGH)<br>Picomatch has a ReDoS vulnerability via extglob quantifiers; Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching | nx / parcel watcher / chokidar/micromatch |
| picomatch@4.0.2 | HIGH | 2 | GHSA-3v7f-55p6-f55p (MEDIUM), GHSA-c2c7-rcm5-vvqj (HIGH)<br>Picomatch has a ReDoS vulnerability via extglob quantifiers; Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching | nx / parcel watcher / chokidar/micromatch |
| picomatch@4.0.3 | HIGH | 2 | GHSA-3v7f-55p6-f55p (MEDIUM), GHSA-c2c7-rcm5-vvqj (HIGH)<br>Picomatch has a ReDoS vulnerability via extglob quantifiers; Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching | nx / parcel watcher / chokidar/micromatch |
| undici@5.29.0 | HIGH | 5 | GHSA-2mjp-6q6p-2qxm (MEDIUM), GHSA-4992-7rv2-5pvq (MEDIUM), GHSA-g9mf-h72j-4rw9 (MEDIUM), GHSA-v9p9-hfj2-hcw8 (HIGH), GHSA-vrm6-8vpv-qv8q (HIGH)<br>Undici has CRLF Injection in undici via `upgrade` option; Undici has Unbounded Memory Consumption in WebSocket permessage-deflate Decompression; Undici has Unhandled Exception in WebSocket Client Due to Invalid server... | @actions/http-client (workspace dev); jsdom (tests) |
| vite@6.4.1 | HIGH | 2 | GHSA-4w7w-66w2-5vf9 (MEDIUM), GHSA-p9ff-h696-f583 (HIGH)<br>Vite Vulnerable to Arbitrary File Read via Vite Dev Server WebSocket; Vite Vulnerable to Path Traversal in Optimized Deps `.map` Handling | direct ui extension packages |
| ajv@8.12.0 | MEDIUM | 1 | GHSA-2g4f-4pwh-qvx6 (MEDIUM)<br>ajv has ReDoS when using `$data` option | @microsoft/tsdoc-config / conf / eslint |
| brace-expansion@5.0.2 | MEDIUM | 1 | GHSA-f886-m6hf-6m8v (MEDIUM)<br>brace-expansion: Zero-step sequence causes process hang and memory exhaustion | minimatch |
| brace-expansion@5.0.3 | MEDIUM | 1 | GHSA-f886-m6hf-6m8v (MEDIUM)<br>brace-expansion: Zero-step sequence causes process hang and memory exhaustion | minimatch |
| fast-xml-parser@5.5.8 | MEDIUM | 1 | GHSA-gh4j-gqv2-49f6 (MEDIUM)<br>fast-xml-parser XMLBuilder: XML Comment and CDATA Injection via Unescaped Delimiters | @aws-sdk/xml-builder transitive |
| follow-redirects@1.15.11 | MEDIUM | 1 | GHSA-r4q5-vmmm-2653 (MEDIUM)<br>follow-redirects leaks Custom Authentication Headers to Cross-Domain Redirect Targets | http-proxy-node16 / nx / axios |
| postcss@8.5.6 | MEDIUM | 1 | GHSA-qx2v-qp2m-jg93 (MEDIUM)<br>PostCSS has XSS via Unescaped </style> in its CSS Stringify Output | vite / theme-check-common |
| smol-toml@1.6.0 | MEDIUM | 1 | GHSA-v3rj-xjv7-4jmq (MEDIUM)<br>smol-toml: Denial of Service via TOML documents containing thousands of consecutive commented lines | knip / nx (tooling) |
| yaml@2.8.0 | MEDIUM | 1 | GHSA-48c2-rrv3-qjmp (MEDIUM)<br>yaml is vulnerable to Stack Overflow via deeply nested YAML collections | theme-check-node / nx / typedoc |
| yaml@2.8.2 | MEDIUM | 1 | GHSA-48c2-rrv3-qjmp (MEDIUM)<br>yaml is vulnerable to Stack Overflow via deeply nested YAML collections | theme-check-node / nx / typedoc |

Dependency findings are exploit hypotheses until a reachable path is shown. The clusters most relevant to Shopify CLI's architecture are: `protobufjs` via telemetry, `defu/h3` in local servers, `follow-redirects/undici` in network clients/proxies, `yaml/smol-toml/@iarna/toml/@shopify/toml-patch` in config parsing, and glob/ReDoS packages around project/theme filesystem traversal.

### Supply-chain risk notes

- Current HEAD does not contain a `SECURITY.md` file; security reporting may rely on GitHub advisories or Shopify external processes. Confirm intended disclosure path.
- `@shopify/plugin-cloudflare` downloads a fixed `cloudflared` release from GitHub and installs/executes it; no checksum/signature validation was observed in the inspected installer. `SHOPIFY_CLI_CLOUDFLARED_PATH` can redirect execution to an env-provided path.
- Native/binary dependencies with elevated supply-chain impact: `@ast-grep/napi`, `esbuild`, `node-pty` (e2e), `@parcel/watcher`, and `@shopify/toml-patch` (WASM).
- High-risk parsers and validators: LiquidJS, TOML/YAML parsers, JSON schema refs/AJV, GraphQL parsers, glob/micromatch/minimatch, PostCSS/Vite.
- `gh` was required by the supply-chain-risk-auditor skill for exact GitHub dependency health metrics, but the local gh credential is invalid; dependency health checks requiring GitHub stars/issues were therefore not completed in this phase.

## Patch Commit Discovery Notes

- Local security diffs were captured under `piolium/tmp/local-security-diffs/`.
- Theme CORS patch `226b49e740`: changed `handleCors(origin: '*')` to an origin allowlist and removed proxied CORS response headers.
- GraphiQL auth patch series `adba3d9bb7/fa3266ea42/306c0f6d37`: added random key to GraphiQL URL/API calls and baseline-like 404 for failed key.
- GraphiQL XSS patch `7719dd5af5`: escaped script-breaking JSON characters before embedding config in HTML. This commit is on a non-main remote branch, so use as pattern intelligence.
- treeKill patches `f4de6ef1ab/0b38241657`: strict PID regex and `spawn('taskkill', args)`; not ancestors of current HEAD, while current source still shows pre-fix shell execution.

## Audit Targeting Recommendations

> Based on pattern analysis: Phase 3 should prioritize **app dev GraphiQL**, **theme dev proxy/hot reload**, **cli-kit Liquid/template rendering**, **store auth callback/token execution**, and **process/tunnel lifecycle** for DFD slices. Phase 5 deep probe should target **browser-origin-to-localhost**, **file/template path traversal and symlink handling**, **CLI/env/process execution**, and **token-bearing HTTP proxy/header flows**. Phase 8 chambers should include **command injection**, **path traversal/arbitrary file read**, **XSS/script-context injection**, **CORS/broken auth**, **prototype pollution/object-path abuse**, and **ReDoS/resource exhaustion** as mandatory attack modes. Patch-bypass-checker should flag **GraphiQL/local dev server**, **LiquidJS/template rendering**, and **treeKill/process cleanup** as structural-recurrence candidates.
