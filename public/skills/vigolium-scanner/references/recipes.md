# Recipes

> **Related:** [agent-loop.md](agent-loop.md) · [scanning.md](scanning.md) · [auth.md](auth.md) · [agent-modes.md](agent-modes.md) · [extensions.md](extensions.md) · [kit.md](kit.md)

Multi-step workflows beyond the four in `SKILL.md` (CI gate, triage loop,
authenticated scan, parallel fan-out). Single commands are in the SKILL.md
command router.

## Plan, scan in the background, wait, read what is new

The loop an agent runs against a target it has scanned before.

```bash
# 1. Plan: sends nothing. Exit 1 no_targets_in_scope if scope refuses the target.
vigolium scan -t https://target.example --dry-run -j > plan.json
jq '.plan.estimate, .plan.warnings' plan.json

# 2. Scan in the background under a UUID you chose, so you can find it again.
ID=$(uuidgen | tr A-Z a-z)
vigolium scan -t https://target.example --scan-uuid "$ID" \
  --scanning-max-duration 45m >/dev/null 2>&1 &

# 3. Wait. Exit 0 completed; 1 failed, abandoned or timed out; 5 partial.
vigolium scan wait "$ID" --timeout 60m --fail-on-partial -j > scan.json
jq '{status, completeness, stop_reason, reasons, counts_by_severity}' scan.json

# 4. Only the findings this scan saw that the previous one did not.
vigolium finding --new-since previous -j --compact \
  --fields id,severity,module_id,url
```

Check `completeness` before step 4: a `partial` head makes "not new" weaker
evidence. `vigolium scan diff previous latest -j` gives the same comparison
with `fixed` / `not_reobserved` and a `comparable` verdict.

## One-off scan that keeps nothing

For a quick look at a target that should leave no trace in the shared store:
`-S` scans into a temporary database that is discarded at exit (kept only on a
failed export, or with `--keep-db-on-error`). Everything you need comes back in
the one document; ask for an artifact with `--format`/`-o` if you want a copy.

```bash
vigolium scan -t https://target.example -S --dry-run -j | jq .plan.estimate   # sends nothing
vigolium scan -t https://target.example -S -j --compact > scan.json           # persisted: false
jq '{status, completeness, counts_by_severity, items: [.items[] | {finding_hash, severity, module_id, url}]}' scan.json
vigolium scan-url https://target.example/api/item?id=1 -S -j -m sqli,xss       # one request, input only
```

Unpersisted findings have no `id`: cite `finding_hash`. To keep the run as a
file instead, `-S --format sqlite -o run` writes `run.sqlite`, which every read
takes with `--db run.sqlite`.

## Borrow the operator's browser session for your own Playwright

When you need to drive a browser against a logged-in app, take the session the
local browser already has instead of scripting a login. Nothing here is
vigolium-specific past the first command — the artifacts are Playwright's own.

```bash
# 0. Will this work here at all? Names the blocker if not. On macOS answer
#    the keychain prompt with "Allow" (this read only): "Always Allow" lets
#    every local process read the browser's key, and every cookie.
vigolium kit cookies doctor -j

# 1. Is the session actually there? Values are redacted, so this is safe to
#    print. Check EXPIRES: "session" cookies may already be dead.
vigolium kit cookies app.target.example --with-storage

# 2. Take it, into 0600 files: both are live credentials. Under a coding
#    agent this is the only way out for the values (-j masks them, --stdout
#    is refused); load the files, do not print them.
vigolium kit cookies app.target.example --with-storage \
    --as playwright -o state.json
vigolium kit cookies app.target.example --with-storage \
    --as playwright-init -o session-init.js
```

```js
// 3. Use it. The init script restores sessionStorage, which a storageState
//    has no field for.
const ctx = await browser.newContext({ storageState: 'state.json' });
await ctx.addInitScript({ path: 'session-init.js' });
const page = await ctx.newPage();
await page.goto('https://app.target.example/');
```

**If the app still shows a login page**, read `unreadable` in the `-j` output:
an origin with IndexedDB keeps its session somewhere no export can carry
(Firebase Auth and several SPA auth libraries do). Clone the profile instead —
it carries IndexedDB because the browser reads its own files:

```bash
vigolium kit cookies app.target.example --clone-profile ./agent-profile
```

```js
const ctx = await chromium.launchPersistentContext('./agent-profile', { headless: false });
```

The clone is scoped to the origins asked for — every other site's cookies and
storage are deleted from it and the stores compacted — and it rewrites two
things so a launched browser can use it: cookie values become plaintext (an
automation launch has no OS keyring key and **deletes** rows it cannot decrypt)
and session cookies get a 12h expiry (a browser discards cookies with no expiry
at startup). Both are reported. sessionStorage still needs the init script: a
launch starts fresh per-tab namespaces.

Pick by where the session lives: `--as playwright` for cookies and
localStorage, which is most apps and the lighter artifact; `--clone-profile`
when IndexedDB is in play. Details and every caveat: [cookies.md](cookies.md).

## Spec scan with auth

```bash
vigolium scan -I openapi -i spec.yaml -t https://api.target.example \
  --spec-header "Authorization: Bearer <token>" --fail-on high
```

`--spec-var name=value` fills required parameters; `--spec-url` uses the
spec's own `servers`. Input formats: `vigolium --list-input-mode`. Details:
[ingest.md](ingest.md) and [scanning.md](scanning.md#input-formats).

## Whitebox: source plus the running app

```bash
# Autopilot reads the source, then scans the live target.
vigolium agent autopilot -t http://localhost:3000 --source ./src

# Source-only audit, no target required.
vigolium agent audit --source . --intensity balanced

# Only the changed code in a PR.
vigolium agent autopilot -t http://localhost:3000 --source ./src \
  --diff main...feature-branch
```

`--source` accepts a local path, a git URL, a `.zip`/`.tar.gz` archive, or a
`gs://` object. `agent autopilot` runs a nested audit harness only with
`--audit`. Modes, intensities and providers: [agent-modes.md](agent-modes.md).

## Capture traffic from a proxy, then scan it

```bash
# Terminal 1: capture, mirroring to a live file tree an agent can grep.
vigolium server --ingest-proxy-port 8080 --mirror-fs ./mirror

# Terminal 2: scan what was captured.
vigolium scan --only dynamic-assessment -t https://target.example
```

Or scan each request as it arrives: `vigolium server --scan-on-receive`.
`server` takes no target flag; what gets scanned is limited by the project's
`scope.*` rules (`vigolium scope view`). Both listeners bind `127.0.0.1`.
Details: [server.md](server.md).

## Custom detection logic in JavaScript

```bash
vigolium ext preset                                   # install the examples
vigolium ext docs                                     # API reference
vigolium ext lint ./custom-check.js                   # validate (exit 1 on errors)
vigolium run extension -t https://target.example --ext ./custom-check.js
```

An `--ext` file that fails to load stops the scan before any traffic (exit 2,
`extension_load_failed`). Writing modules against the `vigolium.*` API:
[extensions.md](extensions.md).
