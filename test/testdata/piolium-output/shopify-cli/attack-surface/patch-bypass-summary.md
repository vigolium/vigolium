# Stage 02 — Patch History & Bypass Review

Generated: 2026-05-01  
Repository: `/Users/bytedance/Desktop/oss-to-run/shopify-cli`  
HEAD: `c3e54bea421d23743b5f2b83b34347f5bb729cc4` (`main`)

## Sweep parameters

All `git log` sweeps in this phase used the required bounded form:

```bash
MAX_COMMITS="${PIGOLIUM_COMMIT_SCAN_LIMIT:-500}"   # observed: 500
MAX_AGE="${PIGOLIUM_COMMIT_SCAN_SINCE:-60 days ago}" # observed: 60 days ago
git log --all -n "$MAX_COMMITS" --since="$MAX_AGE" ...
```

Raw sweep artifacts are under `piolium/tmp/stage02/`.

## Relevant commits and conclusions

| Cluster | Commit(s) | Fix class | Current verdict | Conclusion |
|---|---|---|---|---|
| C-P2-TREEKILL-WINDOWS | `f4de6ef1ab`, `0b38241657` | Windows command injection in `treeKill` | **relocated / not fixed** | Fix is only on remote branches. Current `tree-kill.ts` still has `Number.isNaN(rootPid)` and shell `exec(\`taskkill /pid ${pid}\`)`. |
| C-P2-GRAPHIQL-LOCAL-DEV | `04702b0a1f`, older PR #3168 commits, non-main `7719dd5af5` | GraphiQL localhost auth, API-version path traversal, script-context XSS | **relocated / bypassable** | Current H3 server regressed key protection on `/graphiql/status`, lacks `api_version` allowlist before `adminUrl`, and does not apply the non-main JSON `<>&` escaping pattern to script-embedded query/variables. |
| C-P2-INCLUDE-ASSETS-PATHS | `08b23f3c8e` | `include_assets` destination/path traversal | **partially sound; symlink-bypass precondition remains** | Direct `..` and backslash destination traversal is fixed via `sanitizeRelativePath`; pattern relpath escape is skipped. Lexical checks can still be bypassed if an attacker-controlled output tree contains symlinks. |
| C-P2-OAUTH-TOKEN-LOGGING | `92b092af1d` | OAuth credential leakage in URL query strings/logs | **sound** | Current token exchange sends OAuth params in POST body; no alternate `/oauth/token?...` caller found. |
| C-P2-THEME-CORS | `226b49e740` | Theme dev localhost wildcard/proxied CORS | **sound** | Current server uses exact allowed origins and strips proxied `access-control-*` headers. |
| C-P2-DEPS-UNMERGED | `56e23693cb`, `88403f94d5`, `6341fd237c`, `9b7e726bd6`, `d2b696328a`, `ab622513de` | Dependabot updates for vulnerable `liquidjs`, `lodash`, `vite` | **relocated / not fixed** | Patch branches exist, but current manifests still use vulnerable versions from Stage 01. |

## Bypass attempts performed

### TreeKill command injection

- Checked merge ancestry for `f4de6ef1ab` and `0b38241657`: neither is in current HEAD.
- Confirmed current vulnerable sink at `packages/cli-kit/src/public/node/tree-kill.ts:55` and `:76`.
- Checked callers: current first-party callers pass numeric process IDs, but the exported API accepts `number | string`; downstream/plugin string PID usage would still reach the shell sink on Windows.

**Conclusion:** not a patch bypass; the patch has not landed on `main`.

### GraphiQL local dev server

- Compared `04702b0a1f` claims to current code after later h3/refactor changes.
- Current `packages/app/src/cli/services/dev/graphiql/server.ts` sets `Access-Control-Allow-Origin: *` globally (`:130`), serves `GET /graphiql/status` without key validation (`:162`), and returns `storeFqdn`, `appName`, `appUrl`.
- Current GraphQL proxy still builds `adminUrl(storeFqdn, query.api_version as string)` without the advertised `YYYY-MM|unstable` allowlist (`:244`).
- Current template embeds `query` and `variables` directly in a `<script>` (`templates/graphiql.tsx:255-258`); the non-main XSS fix `7719dd5af5` escaped JSON before script insertion but is not merged.

**Conclusion:** security hardening was partially relocated/regressed. Treat GraphiQL as high-priority local-server review surface.

### include_assets path traversal

- Confirmed destination sanitization is applied for all inclusion types (`include-assets-step.ts:142`, `:163`).
- Confirmed pattern copy bounds check (`include-assets/copy-by-pattern.ts:36`).
- Checked sibling helpers; they receive sanitized destinations, but final writes use normal `copyFile`/`copyDirectoryContents` without `realpath` or no-follow enforcement.

**Conclusion:** direct traversal is fixed, but a malicious template/project with pre-existing output symlinks may still write outside the intended output root.

### OAuth token URL leakage

- Confirmed current `tokenRequest()` uses bare `/oauth/token` URL and form body (`exchange.ts:229-240`).
- Grepped for alternate `/oauth/token?` and token-query construction; none found in current first-party code.

**Conclusion:** patch appears sound.

### Theme dev CORS

- Confirmed exact-origin allowlist (`theme-environment.ts:128-144`).
- Confirmed proxied CORS headers are stripped (`proxy.ts:238-245`).
- Checked related proxy host parsing; current code rejects hostname mismatch (`proxy.ts:303-305`).

**Conclusion:** patch appears sound.

### Dependency bump branches

- Bounded git sweep found Dependabot security-relevant updates for `liquidjs`, `lodash`, and `vite`.
- Merge-state and manifest checks show they are not applied to current HEAD.

**Conclusion:** dependency fixes are not bypassed; they are unmerged and should remain open risk items.

## Reviewed but not classified as historical security fixes

- `390de73448` switches an internal `bin/update-observe.js` helper from bearer-token auth to Observe CLI cookie-cache auth. Security-sensitive, but not a product vulnerability fix; no bypass target identified.
- `02d9ef33f8` gates Gardener Slack notifications behind manual labeling except Dependabot. The separate Claude-based investigation workflow remains label-gated; full agentic workflow review should be handled in CI/CD audit phases.
- `b2fc8bcfdf` (`--path` must be a directory), `ae0a747e94` (scope delimiter parsing), and `7d8423aded`/related bundle path normalization are correctness/DoS-hardening candidates, but no direct security bypass was identified in this phase.
