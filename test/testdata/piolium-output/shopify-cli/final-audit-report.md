# Security Audit Report: Shopify CLI

## Executive Summary

The deep audit of Shopify CLI confirmed 12 Medium-severity security findings and no Critical or High findings. The dominant risk theme is developer-workstation compromise or secret disclosure across local dev servers, malicious project/template input, and downloaded executable toolchains. Nine findings have executed PoCs and three are theoretical due to Windows-only or live CI/dev-server preconditions. Remediation should prioritize integrity verification for downloaded binaries, filesystem-root confinement for templating/assets, and authenticated/origin-checked local dev control planes.

## Findings by Severity

Report verification: every directory under `piolium/findings/` contains `report.md` larger than 500 bytes.

### Critical

No Critical findings were confirmed.

### High

No High findings were confirmed.

### Medium

| ID | Finding | Severity | PoC Status | Primary Impact |
|---|---|---:|---:|---|
| P10-001 | [Windows `treeKill` string PID command injection](findings/p10-tree-kill-windows-command-injection/report.md) | MEDIUM | theoretical | If a Windows CLI, plugin, or other downstream consumer passes attacker-controlled text into `treeKill()`, the attacker can execute arbitrary shell commands with the privileges of t… |
| P10-002 | [UI extension dev server exposes an unauthenticated control plane](findings/p10-extension-dev-server-unauthenticated-control-plane/report.md) | MEDIUM | theoretical | An attacker who can cause a developer's browser to visit a malicious page while `shopify app dev` is running can attempt cross-origin requests to the local extension dev server; an… |
| P10-003 | [Extension asset route follows symlinks after lexical containment](findings/p10-extension-asset-symlink-file-read/report.md) | MEDIUM | executed | An attacker who can influence a Shopify extension project or its build output can plant or preserve a symlink in the extension output tree. When the developer runs the extension de… |
| P10-004 | [App static asset route uses unsafe prefix containment](findings/p10-app-assets-prefix-path-traversal/report.md) | MEDIUM | executed | Any client that can reach the extension dev server or its public tunnel can read files that escape the configured app asset root when a sibling-prefix path or symlink layout exists… |
| P10-005 | [Cloudflared installer executes downloaded release artifacts without integrity verification](findings/p10-cloudflared-download-exec-no-integrity/report.md) | MEDIUM | executed | A successful artifact replacement results in local code execution as the developer running Shopify CLI when the Cloudflare tunnel plugin installs or updates `cloudflared`. The real… |
| P10-006 | [Gardener issue prompt injection into write-capable Claude workflow](findings/p10-agentic-gardener-issue-prompt-injection/report.md) | MEDIUM | theoretical | A successful prompt injection can cause CI to perform repository write actions chosen by an issue author: editing files, committing, pushing a branch, and creating a pull request. … |
| P10-007 | [GraphiQL inline script context XSS via query parameters](findings/p10-graphiql-script-context-xss/report.md) | MEDIUM | executed | An attacker who can induce a developer to open a GraphiQL URL containing the valid key can execute arbitrary JavaScript in the local GraphiQL origin. In that origin, the script can… |
| P10-008 | [Custom app templates can include files from the developer's working directory](findings/p10-liquid-template-root-file-disclosure/report.md) | MEDIUM | executed | A malicious or compromised GitHub app template can disclose files that the developer process can read from the directory where `shopify app init` is launched, such as `.env` secret… |
| P12-001 | [Function toolchain downloads are executed without integrity verification](findings/p12-function-toolchain-download-exec-no-integrity/report.md) | MEDIUM | executed | A successful attack gives local code execution as the developer running Shopify CLI. Practical attacker positions include compromise of a GitHub release asset, compromise of the CD… |
| P12-002 | [mkcert release download is executed without integrity verification](findings/p12-mkcert-download-exec-no-integrity/report.md) | MEDIUM | executed | A compromised `FiloSottile/mkcert` release asset, poisoned local cache, or trusted-network/TLS-breaking attacker that can supply the release bytes can obtain local code execution w… |
| P12-003 | [Extension template Liquid include can disclose local root files](findings/p12-extension-generate-liquid-root-file-disclosure/report.md) | MEDIUM | executed | An attacker who convinces a developer to generate an extension from a malicious `--clone-url` can cause local files readable by the CLI process and resolvable from the developer's … |
| P12-004 | [Include-assets source containment bypass copies outside files into deploy bundles](findings/p12-include-assets-source-containment-file-disclosure/report.md) | MEDIUM | executed | An attacker who can control an app or extension repository, extension TOML, or symlinked asset tree can make a developer or CI deploy build copy files outside the intended extensio… |

## Technical Findings Detail

### P10-001 — Windows `treeKill` string PID command injection
- **Severity:** MEDIUM
- **PoC Status:** theoretical
- **Summary:** `@shopify/cli-kit` exposes `treeKill(pid: number | string)`. On Windows, arbitrary string PIDs are not rejected because the code applies `Number.isNaN()` to a string value, then interpolates the original `pid` into a `child_process.exec()` command. A downstream CLI, plugin, or script that forwards attacker-controlled PID text to this public helper can execute shell commands as the invoking user. Vulnerability class: OS command injection (CWE-78). PoC status: **theoretical**; the prepared exploit requires Windows `cmd.exe` and was not executed on this Darwin host.
- **Impact:** If a Windows CLI, plugin, or other downstream consumer passes attacker-controlled text into `treeKill()`, the attacker can execute arbitrary shell commands with the privileges of that process. Practical consequences include writing or deleting files, launching programs, changing project state, or running further commands in the developer's environment. Exposure is conditional on Windows and an untrusted string reaching this public helper; numeric-only first-party call sites are not directly exploitable.
- **Root Cause:** The implementation accepts string PIDs at a public boundary but does not canonicalize and validate them as numeric process identifiers before use. `Number.isNaN()` is the wrong validation primitive for this path because it does not coerce strings; arbitrary strings are therefore considered valid. The Windows implementation also uses `exec()` with a formatted command string instead of invoking `taskkill` with an argument vector, allowing shell metacharacters in `pid` to reach `cmd.exe`.
- **Key Code Reference:** - `packages/cli-kit/src/public/node/tree-kill.ts:20-31` — public helper accepts `number | string`.<br>- `packages/cli-kit/src/public/node/tree-kill.ts:53-56` — validation does not convert strings before `Number.isNaN`.
- **Detailed Report:** [piolium/findings/p10-tree-kill-windows-command-injection/report.md](findings/p10-tree-kill-windows-command-injection/report.md)
- **Proof of Concept:** [piolium/findings/p10-tree-kill-windows-command-injection/poc.js](findings/p10-tree-kill-windows-command-injection/poc.js)
- **Evidence:** [piolium/findings/p10-tree-kill-windows-command-injection/evidence](findings/p10-tree-kill-windows-command-injection/evidence)

### P10-002 — UI extension dev server exposes an unauthenticated control plane
- **Severity:** MEDIUM
- **PoC Status:** theoretical
- **Summary:** The Shopify CLI UI-extension dev server used by `shopify app dev` exposes `/extensions` HTTP payload endpoints with wildcard CORS and upgrades `WS /extensions` connections after only checking the request URL. A malicious browser origin on the developer machine, or a remote client that can reach a tunnel exposing the dev server, can read app/store/extension metadata and use the WebSocket control channel without authentication to receive payloads and send update, dispatch, or log events.
- **Impact:** An attacker who can cause a developer's browser to visit a malicious page while `shopify app dev` is running can attempt cross-origin requests to the local extension dev server; an attacker who can reach a tunnel exposing that server can do the same remotely. Successful exploitation discloses development metadata such as the store FQDN, app API key, socket URL, manifest version, and extension payloads. The same client can join the WebSocket control channel, receive connected payloads, send dispatch messages to other connected clients, mutate in-memory extension/app payload state via update events, and inject log output into the developer terminal path. The demonstrated impact is limited to the development server/control plane rather than direct production store compromise, but it can compromise local development previews and developer workflow integrity.
- **Root Cause:** The dev server treats a developer-local control plane as implicitly trusted by network location, but it exposes browser-reachable HTTP and WebSocket endpoints without a shared session secret or origin/host validation. Wildcard CORS makes the HTTP payload readable from arbitrary origins, and the WebSocket upgrade path relies only on `request.url === '/extensions'`, allowing untrusted browser or tunnel clients to join the same control channel as legitimate extension clients.
- **Key Code Reference:** - `packages/app/src/cli/services/dev/extension/server/middlewares.ts:14-21` — wildcard CORS.<br>- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:180-225` — extension payload response contains API key, socket URL, store, and extension payload.
- **Detailed Report:** [piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/report.md](findings/p10-extension-dev-server-unauthenticated-control-plane/report.md)
- **Proof of Concept:** [piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/poc.py](findings/p10-extension-dev-server-unauthenticated-control-plane/poc.py)
- **Evidence:** [piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/evidence](findings/p10-extension-dev-server-unauthenticated-control-plane/evidence)

### P10-003 — Extension asset route follows symlinks after lexical containment
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** The extension dev server's `/extensions/:extensionId/assets/**` route validates only the lexical path under an extension output directory before serving the file. A malicious project, template, or build output that places a symlink inside that output directory can cause the unauthenticated asset route to read the symlink target outside the intended bundle root and return local file contents to any origin that can reach the dev server.
- **Impact:** An attacker who can influence a Shopify extension project or its build output can plant or preserve a symlink in the extension output tree. When the developer runs the extension dev server, any browser origin or network peer that can reach the server can request the symlink name and receive the target file's contents, limited to files readable by the CLI process. This is most relevant for malicious templates, compromised project dependencies/build steps, or shared/tunneled dev-server workflows; it does not require Shopify authentication once the dev server is running.
- **Root Cause:** The implementation treats `resolvePath(joinPath(outputDir, requestedPath))` plus a `relativePath()` prefix check as an access-control boundary. That boundary is only lexical: it proves the symlink pathname is inside the output directory, not that the file ultimately opened by `readFile()` is inside the output directory. There is no `realpath()`-based containment check and no no-follow or `lstat()` rejection for symlinks before the file read.
- **Key Code Reference:** - `packages/app/src/cli/services/dev/extension/server/middlewares.ts:75-107` — asset path resolution and lexical `relativePath` check.<br>- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:34-56` — `fileServerMiddleware()` reads the final path with `readFile()`.
- **Detailed Report:** [piolium/findings/p10-extension-asset-symlink-file-read/report.md](findings/p10-extension-asset-symlink-file-read/report.md)
- **Proof of Concept:** [piolium/findings/p10-extension-asset-symlink-file-read/poc.sh](findings/p10-extension-asset-symlink-file-read/poc.sh)
- **Evidence:** [piolium/findings/p10-extension-asset-symlink-file-read/evidence](findings/p10-extension-asset-symlink-file-read/evidence)

### P10-004 — App static asset route uses unsafe prefix containment
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** The extension development server exposes app-level static assets at `/extensions/assets/:assetKey/**:filePath` and attempts to confine requests to an admin extension `static_root` with a raw `startsWith` string check. Because the attacker-controlled wildcard path is resolved and then compared without a path-segment boundary or canonical symlink target check, a reachable browser/tunnel client can request a sibling-prefix path such as `../public-secret/secret.txt` and receive file contents outside the configured static asset root.
- **Impact:** Any client that can reach the extension dev server or its public tunnel can read files that escape the configured app asset root when a sibling-prefix path or symlink layout exists in the project. The demonstrated effect is disclosure of a local file outside `static_root` through an unauthenticated HTTP response. In practice, exposure is limited to environments where the Shopify CLI dev server is running with an admin extension `static_root` configured, but those sessions commonly proxy local developer resources through a browser/tunnel boundary.
- **Root Cause:** The route implements directory containment with an unsafe string-prefix comparison instead of a path-aware containment check. It normalizes the requested path, but it does not require the result to be equal to the root or contained below `root + pathSeparator`, and it does not compare canonical `realpath` values to prevent symlink escapes.
- **Key Code Reference:** - `packages/app/src/cli/services/dev/extension/payload/store.ts:22-29`, `:72-80`, `:273-277` — admin extension `static_root` becomes the `staticRoot` asset directory.<br>- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:155-170` — unsafe `startsWith` containment check and file read.
- **Detailed Report:** [piolium/findings/p10-app-assets-prefix-path-traversal/report.md](findings/p10-app-assets-prefix-path-traversal/report.md)
- **Proof of Concept:** [piolium/findings/p10-app-assets-prefix-path-traversal/poc.sh](findings/p10-app-assets-prefix-path-traversal/poc.sh)
- **Evidence:** [piolium/findings/p10-app-assets-prefix-path-traversal/evidence](findings/p10-app-assets-prefix-path-traversal/evidence)

### P10-005 — Cloudflared installer executes downloaded release artifacts without integrity verification
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** The Cloudflare tunnel plugin downloads a platform-specific `cloudflared` executable or archive from GitHub Releases and installs it into the CLI plugin binary path without verifying a pinned checksum, signature, or digest. If an attacker can replace that release artifact through a supply-chain compromise, poisoned cache, or trusted-network/TLS-breaking position, the CLI will write attacker-controlled bytes as `cloudflared` and execute them in the developer's local user context. This is a download-of-code-without-integrity-check weakness (CWE-494).
- **Impact:** A successful artifact replacement results in local code execution as the developer running Shopify CLI when the Cloudflare tunnel plugin installs or updates `cloudflared`. The realistic attacker precondition is supply-chain control over the release asset path or a trusted-network/TLS-breaking/caching position capable of supplying malicious bytes for the expected GitHub Release artifact; ordinary on-path attackers are still constrained by TLS. Under those conditions, the attacker can execute arbitrary commands with the user's local privileges, read or modify project files and environment variables available to the CLI process, and persist by leaving a malicious `cloudflared` binary at the plugin binary path.
- **Root Cause:** The installer trusts transport success from a GitHub Release URL as sufficient authorization to execute the artifact. It does not pin expected SHA-256 hashes, verify a signed checksum/provenance statement, or otherwise bind the downloaded artifact to an authenticated release identity before storing it in the executable path.
- **Key Code Reference:** - `packages/plugin-cloudflare/src/install-cloudflared.ts:20-45` — versioned release URL construction.<br>- `packages/plugin-cloudflare/src/install-cloudflared.ts:123-151` — download, write, chmod/extract without integrity verification.
- **Detailed Report:** [piolium/findings/p10-cloudflared-download-exec-no-integrity/report.md](findings/p10-cloudflared-download-exec-no-integrity/report.md)
- **Proof of Concept:** [piolium/findings/p10-cloudflared-download-exec-no-integrity/poc.js](findings/p10-cloudflared-download-exec-no-integrity/poc.js)
- **Evidence:** [piolium/findings/p10-cloudflared-download-exec-no-integrity/evidence](findings/p10-cloudflared-download-exec-no-integrity/evidence)

### P10-006 — Gardener issue prompt injection into write-capable Claude workflow
- **Severity:** MEDIUM
- **PoC Status:** theoretical
- **Summary:** The `Gardener - Investigate Issue` GitHub Actions workflow runs Claude Code when the `devtools-investigate-for-gardener` label is applied to an issue. Because the workflow passes the attacker-created issue URL into the agent while also granting repository-write permissions and write-capable tools, untrusted issue body/title text can become prompt-injection input to a CI agent that can edit files, commit, push a branch, and create a pull request. PoC status: **theoretical**; live exploitation requires the real GitHub Actions/Claude secrets and a maintainer-applied label.
- **Impact:** A successful prompt injection can cause CI to perform repository write actions chosen by an issue author: editing files, committing, pushing a branch, and creating a pull request. GitHub's default `GITHUB_TOKEN` loop prevention may stop the created PR from automatically triggering follow-up CI, and a human would still need to review and merge any PR. However, the attacker still gains a confused-deputy path to create maintainer-looking branches/PRs and to manipulate the investigation report delivered to maintainers, which increases the risk of unauthorized changes or social-engineered review.
- **Root Cause:** The workflow combines untrusted issue triage input with an autonomous, write-capable coding agent in a single execution context. A maintainer-applied label controls when the workflow starts, but there is no separate read-only analysis phase, prompt isolation, or human approval boundary before exposing `contents: write`, `pull-requests: write`, `Edit`/`Write`, `git push`, and `gh pr create` to content originating from the labeled issue.
- **Key Code Reference:** - `.github/workflows/gardener-investigate-issue.yml:5-8` — `issues:labeled` trigger.<br>- `.github/workflows/gardener-investigate-issue.yml:15-18` — repository write/PR permissions.
- **Detailed Report:** [piolium/findings/p10-agentic-gardener-issue-prompt-injection/report.md](findings/p10-agentic-gardener-issue-prompt-injection/report.md)
- **Proof of Concept:** [piolium/findings/p10-agentic-gardener-issue-prompt-injection/poc.sh](findings/p10-agentic-gardener-issue-prompt-injection/poc.sh)
- **Evidence:** [piolium/findings/p10-agentic-gardener-issue-prompt-injection/evidence](findings/p10-agentic-gardener-issue-prompt-injection/evidence)

### P10-007 — GraphiQL inline script context XSS via query parameters
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** The local GraphiQL page renders attacker-controlled `query` and `variables` URL parameters into an inline `<script>` block using `JSON.stringify` only. When a developer opens a GraphiQL URL containing the valid per-run GraphiQL key, a crafted `</script><script>...</script>` value breaks out of the JavaScript string and executes in the trusted local GraphiQL origin.
- **Impact:** An attacker who can induce a developer to open a GraphiQL URL containing the valid key can execute arbitrary JavaScript in the local GraphiQL origin. In that origin, the script can call `/graphiql/graphql.json` as same-origin and use the same GraphiQL key, enabling actions through the token-backed Admin GraphQL proxy with the app scopes available to the developer's local session. The valid-key precondition limits exposure, but the executed PoC confirms that, once the key is accepted, the page renders the payload as an executable script tag instead of escaping it.
- **Root Cause:** The implementation uses JavaScript string serialization as if it were safe HTML script-context serialization. Data from URL parameters crosses from the request into an executable `<script>` block without an HTML-safe JSON serializer or equivalent escaping that prevents `</script>` from being interpreted by the HTML parser.
- **Key Code Reference:** - `packages/app/src/cli/services/dev/graphiql/server.ts:206-227` — decodes URL parameters and passes `JSON.stringify` output to the template.<br>- `packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx:254-259` — inserts `query` and `variables` into inline JavaScript.
- **Detailed Report:** [piolium/findings/p10-graphiql-script-context-xss/report.md](findings/p10-graphiql-script-context-xss/report.md)
- **Proof of Concept:** [piolium/findings/p10-graphiql-script-context-xss/poc.js](findings/p10-graphiql-script-context-xss/poc.js)
- **Evidence:** [piolium/findings/p10-graphiql-script-context-xss/evidence](findings/p10-graphiql-script-context-xss/evidence)

### P10-008 — Custom app templates can include files from the developer's working directory
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** `shopify app init --template` accepts custom GitHub template repositories and renders attacker-controlled `.liquid` files with LiquidJS' default filesystem lookup settings. Because the Liquid engine is not rooted to the downloaded template directory, a malicious template can use tags such as `{% include ".env" %}` to read files from the developer process' current working directory and write their contents into the generated app scaffold.
- **Impact:** A malicious or compromised GitHub app template can disclose files that the developer process can read from the directory where `shopify app init` is launched, such as `.env` secrets, local app configuration, or other predictable project files. The demonstrated effect is local file disclosure into the newly generated scaffold. From there, the exposed data may be exfiltrated by template-controlled dependency installation behavior, accidentally committed, or shared with the generated project.
- **Root Cause:** The renderer crosses the trust boundary between an untrusted downloaded template repository and the developer's local filesystem. Template content is attacker controlled, but the Liquid engine is constructed with default filesystem resolution instead of being constrained to the downloaded template directory or to a non-filesystem template loader. As a result, filesystem tags in the untrusted template are evaluated with access to files outside the template tree.
- **Key Code Reference:** - `packages/app/src/cli/commands/app/init.ts:41-45` — custom GitHub templates are accepted.<br>- `packages/app/src/cli/services/init/validate.ts:11-16` — validation only restricts the origin to GitHub.
- **Detailed Report:** [piolium/findings/p10-liquid-template-root-file-disclosure/report.md](findings/p10-liquid-template-root-file-disclosure/report.md)
- **Proof of Concept:** [piolium/findings/p10-liquid-template-root-file-disclosure/poc.sh](findings/p10-liquid-template-root-file-disclosure/poc.sh)
- **Evidence:** [piolium/findings/p10-liquid-template-root-file-disclosure/evidence](findings/p10-liquid-template-root-file-disclosure/evidence)

### P12-001 — Function toolchain downloads are executed without integrity verification
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** Shopify CLI's app function toolchain downloads `function-runner`, `javy`, `shopify-function-trampoline`, the Javy plugin, and `wasm-opt` from GitHub releases or CDNs, caches them under the CLI package `bin` directory, and later executes them during function build/run workflows. If an attacker can replace one of those upstream artifacts before it is cached locally, the CLI accepts the bytes, marks them executable, and runs them in the developer's user context without checking a pinned digest or signature.
- **Impact:** A successful attack gives local code execution as the developer running Shopify CLI. Practical attacker positions include compromise of a GitHub release asset, compromise of the CDN-hosted tooling, a poisoned local cache before first use, or a trusted-network/TLS-breaking intermediary that can supply malicious artifact bytes. The executed payload could read project source, environment variables, Shopify credentials, access tokens, SSH keys, or other developer workstation secrets. This is a supply-chain/developer-workstation impact; it does not by itself imply unauthenticated remote compromise of a deployed Shopify app.
- **Root Cause:** The function tooling download model treats the artifact URL and version string as sufficient identity for executable code. `DownloadableBinary` implementations provide a `name`, `version`, `path`, and `downloadUrl()`, but no expected digest or signature metadata is enforced before the file is cached or executed. The cache also trusts file existence alone, so a previously poisoned binary is reused without later integrity validation.
- **Key Code Reference:** - `packages/app/src/cli/services/function/binaries.ts:63-134` — GitHub release URL construction for native `javy`, `function-runner`, and trampoline executables.<br>- `packages/app/src/cli/services/function/binaries.ts:147-183` — CDN URLs for the Javy plugin and `wasm-opt.cjs`.
- **Detailed Report:** [piolium/findings/p12-function-toolchain-download-exec-no-integrity/report.md](findings/p12-function-toolchain-download-exec-no-integrity/report.md)
- **Proof of Concept:** [piolium/findings/p12-function-toolchain-download-exec-no-integrity/poc.js](findings/p12-function-toolchain-download-exec-no-integrity/poc.js)
- **Evidence:** [piolium/findings/p12-function-toolchain-download-exec-no-integrity/evidence](findings/p12-function-toolchain-download-exec-no-integrity/evidence)

### P12-002 — mkcert release download is executed without integrity verification
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** When no configured, cached, or system `mkcert` binary is available, Shopify CLI downloads a `FiloSottile/mkcert` GitHub release asset into the app's `.shopify` directory, marks it executable, and later runs it to generate localhost certificates. The downloaded bytes are trusted solely because the HTTP request succeeded; no pinned checksum, signature, digest, or attestation is verified before execution. If the release asset or download path is compromised, attacker-controlled code runs in the developer's user context.
- **Impact:** A compromised `FiloSottile/mkcert` release asset, poisoned local cache, or trusted-network/TLS-breaking attacker that can supply the release bytes can obtain local code execution when a developer triggers localhost certificate generation and the CLI falls back to downloading `mkcert`. The payload runs with the developer's privileges, so it can read or modify project files, steal local credentials available to the user, tamper with development dependencies, or abuse the certificate-generation flow. This is not an unauthenticated remote exploit against a running service; it is a supply-chain/local developer execution risk that depends on the download fallback being reached.
- **Root Cause:** This is a download-and-execute supply-chain issue (CWE-494: Download of Code Without Integrity Check). The implementation treats a successful fetch from a GitHub release URL as sufficient authenticity for executable code, and the shared downloader even sets executable permissions before the caller runs the artifact. There is no pinned digest, release signature verification, trusted public key, or fail-closed integrity policy for the `mkcert` binary.
- **Key Code Reference:** - `packages/app/src/cli/utilities/mkcert.ts:23-47` — selects the app-local `.shopify/mkcert` path when no env/system binary is available.<br>- `packages/app/src/cli/utilities/mkcert.ts:56-76` — constructs platform release asset names and calls `downloadGitHubRelease()`.
- **Detailed Report:** [piolium/findings/p12-mkcert-download-exec-no-integrity/report.md](findings/p12-mkcert-download-exec-no-integrity/report.md)
- **Proof of Concept:** [piolium/findings/p12-mkcert-download-exec-no-integrity/poc.sh](findings/p12-mkcert-download-exec-no-integrity/poc.sh)
- **Evidence:** [piolium/findings/p12-mkcert-download-exec-no-integrity/evidence](findings/p12-mkcert-download-exec-no-integrity/evidence)

### P12-003 — Extension template Liquid include can disclose local root files
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** `shopify app generate extension` accepts a custom extension-template repository through the hidden `--clone-url` flag / `SHOPIFY_FLAG_CLONE_URL` environment variable, then renders downloaded `.liquid` files with the shared Liquid template helper. Because that helper creates a default `new Liquid()` engine instead of pinning include/layout roots to the downloaded template directory, a malicious template can include files from the developer's current working directory, such as `.env`, into generated extension files. PoC-Status: `executed`.
- **Impact:** An attacker who convinces a developer to generate an extension from a malicious `--clone-url` can cause local files readable by the CLI process and resolvable from the developer's current working directory to be copied into generated extension files. The demonstrated effect is disclosure of a victim app `.env` secret into `extensions/leaky-ext/leak.txt`. Direct attacker access still depends on follow-on exposure, such as the developer committing, sharing, deploying, logging, or otherwise processing the generated scaffold, but the CLI creates the secret-bearing file without warning. The affected surface includes theme, function, and UI extension generation paths because all of them call the same Liquid copy helper.
- **Root Cause:** Untrusted extension template contents are rendered with a Liquid engine that has filesystem include capabilities but no root confinement to the template directory. The code treats downloaded `.liquid` files as safe scaffolding templates, yet it does not disable or sandbox Liquid tags such as `include`/`render`/`layout`, nor does it reject paths that resolve outside the downloaded template repository.
- **Key Code Reference:** - `packages/app/src/cli/commands/app/generate/extension.ts:42-47` — hidden `--clone-url` / `SHOPIFY_FLAG_CLONE_URL` accepts a custom template repository URL.<br>- `packages/app/src/cli/commands/app/generate/extension.ts:89-93` — passes the clone URL into the generation service.
- **Detailed Report:** [piolium/findings/p12-extension-generate-liquid-root-file-disclosure/report.md](findings/p12-extension-generate-liquid-root-file-disclosure/report.md)
- **Proof of Concept:** [piolium/findings/p12-extension-generate-liquid-root-file-disclosure/poc.js](findings/p12-extension-generate-liquid-root-file-disclosure/poc.js)
- **Evidence:** [piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence](findings/p12-extension-generate-liquid-root-file-disclosure/evidence)

### P12-004 — Include-assets source containment bypass copies outside files into deploy bundles
- **Severity:** MEDIUM
- **PoC Status:** executed
- **Summary:** The `include_assets` build step sanitizes output destinations but not project-controlled source paths. A malicious or compromised extension configuration can set an asset path such as `admin.static_root = "../.env"`; during deploy, Shopify CLI joins that value with the extension directory and copies the resulting outside file into the deploy bundle and generated manifest.
- **Impact:** An attacker who can control an app or extension repository, extension TOML, or symlinked asset tree can make a developer or CI deploy build copy files outside the intended extension root into the build output. In deploy flows where generated assets are uploaded, this can disclose local secrets or CI files as extension assets; in local development, the copied file may also be served or exposed from the generated output. The demonstrated behavior is local file disclosure into the bundle and manifest, not arbitrary code execution.
- **Root Cause:** The include-assets implementation treats asset source paths from project configuration and glob results as trusted after only destination-side sanitization. It never canonicalizes the selected source path, resolves symlinks, and enforces that the real source remains inside the extension or declared source root before copying it into the deploy output.
- **Key Code Reference:** - `packages/app/src/cli/services/build/steps/include-assets-step.ts:138-151` — only `entry.destination` is sanitized before config-key copying.<br>- `packages/app/src/cli/services/build/steps/include-assets/copy-config-key-entry.ts:43-64` — attacker-controlled config values become `sourcePath` entries.
- **Detailed Report:** [piolium/findings/p12-include-assets-source-containment-file-disclosure/report.md](findings/p12-include-assets-source-containment-file-disclosure/report.md)
- **Proof of Concept:** [piolium/findings/p12-include-assets-source-containment-file-disclosure/poc.js](findings/p12-include-assets-source-containment-file-disclosure/poc.js)
- **Evidence:** [piolium/findings/p12-include-assets-source-containment-file-disclosure/evidence](findings/p12-include-assets-source-containment-file-disclosure/evidence)


## Attack Surface Summary

The audit model treats Shopify CLI primarily as a developer-workstation and CI/CD trust-boundary system rather than a conventional internet-facing service. High-risk surfaces include browser/tunnel access to local dev servers, malicious local projects/templates/configuration, external executable downloads, token-bearing Shopify API clients, and package-manager/subprocess execution.

| Area | Artifact | Notes |
|---|---|---|
| Knowledge base / threat model | [piolium/attack-surface/knowledge-base-report.md](attack-surface/knowledge-base-report.md) | Architecture, trust boundaries, DFD/CFD slices, threat model, SAST summaries, and phase addenda. |
| Advisory intelligence | [piolium/attack-surface/advisory-summary.md](attack-surface/advisory-summary.md) | Dependency/advisory collection and first-party security signal summary. |
| Patch-bypass review | [piolium/attack-surface/patch-bypass-summary.md](attack-surface/patch-bypass-summary.md) | Review of security-relevant historical/local patches and bypass opportunities. |
| Architecture entry points | [piolium/attack-surface/architecture-entrypoints.md](attack-surface/architecture-entrypoints.md) | Command, route, and high-risk entry point inventory. |
| Manual attack surface inventory | [piolium/attack-surface/manual-attack-surface-inventory.md](attack-surface/manual-attack-surface-inventory.md) | Manual enumeration of local dev servers, build/package, auth, and process surfaces. |
| Authorization matrix | [piolium/attack-surface/public-routes-authz-matrix.md](attack-surface/public-routes-authz-matrix.md) | Public/local route and operation authorization coverage matrix. |
| Cross-service edges | [piolium/attack-surface/cross-service-edges.md](attack-surface/cross-service-edges.md) | Local HTTP/WS/external HTTP service-edge model and propagation notes. |
| Source/sink flows | [piolium/attack-surface/source-sink-flows-all-severities.md](attack-surface/source-sink-flows-all-severities.md) | Merged source-to-sink paths used for manual triage. |
| Merged SAST SARIF | [piolium/attack-surface/sast-merged.sarif](attack-surface/sast-merged.sarif) | Consolidated CodeQL/Semgrep scanner output. |
| SAST enrichment JSON | [piolium/attack-surface/sast-enrichment.json](attack-surface/sast-enrichment.json) | Normalized scanner findings and enrichment metadata. |
| Spec gap summary | [piolium/attack-surface/spec-gap-summary.md](attack-surface/spec-gap-summary.md) | Spec-to-code compliance notes for OAuth, HTTP/CORS, WS/SSE, Liquid, GraphQL, and archives. |
| State/concurrency summary | [piolium/attack-surface/state-concurrency-summary.md](attack-surface/state-concurrency-summary.md) | State-holding entities and concurrency/idempotency observations. |
| Agentic workflow review | [piolium/attack-surface/agentic-actions-auditor.md](attack-surface/agentic-actions-auditor.md) | Review of AI-agent GitHub Actions workflows. |
| Deep probe summary | [piolium/attack-surface/deep-probe-summary.md](attack-surface/deep-probe-summary.md) | Manual high-risk probe outcomes. |

Key attack-surface conclusions:

- Local HTTP/WebSocket/SSE services (`app dev`, GraphiQL, UI extension dev server, theme dev, store callback) are security-critical because arbitrary browser origins and public tunnel visitors can reach them in realistic workflows.
- Malicious project repositories and templates are in scope: they control TOML/JSON/YAML/Liquid, globs, symlinks, package scripts, generated assets, and web commands that the CLI processes with developer privileges.
- External binary/tool downloads (`cloudflared`, function toolchain, `mkcert`) cross directly from network artifacts into local executable trust.
- Credential-bearing API clients and local session stores make XSS, local file disclosure, log leakage, and confused-deputy paths high-value even when exploitation is development-only.

## Coverage Gaps

- **Runtime localhost/tunnel testing:** Stage 03 notes no full live malicious-origin/tunnel dynamic test pass for CORS, DNS rebinding, WebSocket `Origin`, and SSE behavior. See [piolium/attack-surface/knowledge-base-report.md#coverage-gaps](attack-surface/knowledge-base-report.md).
- **Windows-specific validation:** Windows-only process/path behavior, including the `treeKill` finding, was not dynamically executed on this Darwin audit host.
- **Private/authenticated intelligence:** GitHub authenticated security-advisory/Dependabot data and private Shopify platform behavior were unavailable; server-side authorization assumptions could not be fully validated from the repository alone.
- **Generated/published artifacts:** Source was prioritized; generated `dist`/published package bundles and release provenance were not exhaustively diffed against TypeScript sources.
- **Out-of-repository route owners:** External Hydrogen commands, user-installed oclif plugins, app reverse-proxy downstream routes, and dynamic theme URL spaces are outside this repository's complete route inventory. See [piolium/authz-coverage-gaps.md](authz-coverage-gaps.md).
- **Recent community intelligence:** Last-30-days Reddit/X research was unavailable in the recorded phase and should be rerun if external context is required before disclosure or remediation prioritization.

## Methodology Notes

- **Mode:** `/piolium-deep`, Stage 15 final report assembly, target commit recorded in the knowledge base as `c3e54bea421d23743b5f2b83b34347f5bb729cc4`.
- **Collection and modeling:** advisory intelligence, patch-bypass review, architecture inventory, trust-boundary modeling, DFD/CFD slices, and domain/spec research were consolidated in the knowledge base.
- **Patch-bypass evidence:** Detailed bypass notes are retained under [piolium/bypass-analysis/](bypass-analysis/).
- **Cold verification:** Adversarial review outputs are retained under [piolium/adversarial-reviews/](adversarial-reviews/), with chamber transcripts under [piolium/chamber-workspace/](chamber-workspace/).
- **Static and manual analysis:** CodeQL structural extraction, CodeQL security-and-quality, Semgrep Pro baseline/targeted/custom rules, manual source tracing, authz matrixing, state/concurrency review, and spec gap analysis were used to generate and triage hypotheses.
- **Review chambers:** 7 adversarial review chambers were recorded in [piolium/chamber-workspace/index.md](chamber-workspace/index.md). Hypothesis flow: 16 chamber source hypotheses -> 8 P10 survivors; 4 P12 variants confirmed; 12 final findings.
- **Pattern registry:** 8 confirmed attack patterns are tracked in [piolium/attack-pattern-registry.json](attack-pattern-registry.json).
- **Variant analysis:** 4 variant findings were retained; see [piolium/variant-summary.md](variant-summary.md).
- **PoC status:** 9 executed, 3 theoretical, 0 blocked.
- **Finding artifacts:** Each retained finding directory includes `draft.md`, `report.md`, PoC script, and an `evidence/` directory; individual links are listed in the technical detail section.
- **Consistency check log:** Manual and validator results are retained in [piolium/final-consistency-checks.md](final-consistency-checks.md) and [piolium/final-validation.log](final-validation.log).

## Conclusion

Shopify CLI's confirmed issues cluster around local developer trust boundaries: untrusted files/templates/configuration, local browser-accessible services, and unauthenticated executable downloads. The absence of Critical/High findings lowers immediate platform-wide risk, but the Medium findings are practically important because exploitation can expose local secrets or run code as a developer/CI user. The strongest hardening themes are fail-closed artifact integrity, canonical filesystem containment with symlink-aware checks, HTML/script-context-safe serialization, and explicit authentication/origin validation for dev-server control planes.
