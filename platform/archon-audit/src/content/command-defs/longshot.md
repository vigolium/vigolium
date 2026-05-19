---
description: Hail-mary file-by-file vulnerability hunt. Enumerates every interesting source file in the repo, scores them by danger heuristics, then fans out one independent hunter agent per file (concurrent). A single aggregator deduplicates the swarm output. This mode is bottom-up — it does NOT use the knowledge-base or DFD/CFD slices, so it surfaces findings that architecture-anchored audits miss.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: longshot
phases:
  - id: "1"
    title: Enumerate Targets
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: "2"
    title: Hunt (file-by-file fan-out)
    agent: longshot-prober
    requires_git: false
    parallel_with: []
    depends_on: ["1"]
  - id: "3"
    title: Aggregate & Deduplicate
    agent: longshot-collector
    requires_git: false
    parallel_with: []
    depends_on: ["2"]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat archon/audit-context.md 2>/dev/null || echo "(none)"`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null | head -40 || echo "No prior audit state"`
- Prior longshot run: !`test -f archon/longshot/targets.json && echo "present ($(jq -r '.targets | length' archon/longshot/targets.json 2>/dev/null) targets)" || echo "none"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree" || echo "Plain dir"`

## Your Task

Run a **longshot** audit — a hail-mary, file-by-file vulnerability hunt. Target scope: $ARGUMENTS

This mode is fundamentally different from `/archon:lite`, `/archon:balanced`, and `/archon:deep`. Those modes are top-down: they build a knowledge base, model the architecture into DFD/CFD slices, then dispatch component teams. Longshot is bottom-up: every interesting source file gets independent attention from a fresh hunter agent. The hypothesis is that architecture-anchored audits cluster their reasoning around a model, and bugs that don't fit any cluster get missed. Longshot trades that organized coverage for raw, untargeted breadth.

Longshot does NOT require a prior audit and is a *complement* to deep mode, not a substitute — its cross-file reasoning is weaker per-tile but its breadth is wider.

### Output directory

All longshot artifacts live under `archon/longshot/` to keep them quarantined from `archon/findings-draft/` and `archon/findings/` (which belong to deep/balanced):

```
archon/longshot/
├── targets.json              # Phase 1 sidecar; per-anchor scoring + run state
├── findings-draft/           # Phase 2 raw hunter output
│   ├── longshot-<sha8>-001-<slug>.md
│   ├── longshot-<sha8>-000-no-finding.md
│   └── ...
└── longshot-summary.md       # Phase 3 curated report
```

Curated findings stay in `archon/longshot/findings-draft/longshot-curated-*.md`. They are NOT auto-promoted into `archon/findings/` — the user can promote manually after reviewing the summary.

### Pre-Flight Check

If `archon/longshot/targets.json` already exists, use `AskUserQuestion`:

- **Incomplete run**: "A longshot run is already in progress. What would you like to do?"
  - Options: "Resume from last checkpoint" | "Start fresh (clears archon/longshot/)" | "Cancel"
- **Complete run**: "A completed longshot run exists. What would you like to do?"
  - Options: "Re-aggregate (re-run Phase 3 only)" | "Start fresh" | "Cancel"

**Resume**: Phase 1 short-circuits if `targets.json` exists; Phase 2 walks targets and skips `status: "complete"` entries; Phase 3 re-runs against whatever drafts are present.

**Start fresh**: `rm -rf archon/longshot/` then proceed.

Do not proceed past pre-flight without an explicit user choice.

### Pre-Audit Setup

1. `mkdir -p archon/longshot/findings-draft/`

The orchestrator engine owns `archon/audit-state.json` — do not write to it from inside this command-def. Per-phase status transitions (`in_progress` → `complete`/`failed`) are recorded automatically when each phase ends.

---

## Phase 1: Enumerate Targets

This is an inline phase. You walk the repo, score every candidate source file by danger heuristics, and write the ranked list to `archon/longshot/targets.json`.

### Step 1.1: Detect dominant languages

Walk the target directory (skipping excluded dirs — see step 1.2) and count source files by extension across the standard set (TypeScript, JavaScript, Python, Go, Rust, Ruby, Java, Kotlin, Swift, C, C++, C#, PHP, Scala, Clojure, Shell, Lua, Objective-C). Pick the language with the highest count plus any with ≥25% of its file count (so polyglot repos like Go+Python get full coverage). This is your `languages[]` list.

### Step 1.2: Skip rules (deterministic, mandatory)

**Skip these directories entirely** (do not descend):

```
node_modules .git vendor dist build target out .next .nuxt .cache
.venv venv __pycache__ .pytest_cache .mypy_cache .idea .vscode
archon third_party third-party
```

Plus any directory whose name starts with `.`.

**Skip test directories** (don't descend):

```
tests test __tests__ spec specs e2e fixtures testdata test-data
```

**Skip files matching these test patterns**:

```
test_*.py    *_test.py    *_test.go    *.test.ts    *.spec.ts
*.test.js    *.spec.js    *.test.rb    *_spec.rb
*Test.java   *Tests.java  *Spec.scala  test_*.rs
```

**Skip files matching these generated patterns**:

```
*.pb.go   *_pb2.py   *.pb.cc   *.pb.h   *.gen.go
*_generated.*   *.generated.*   *.min.js   *.min.css
*.bundle.js   *-generated.*   bindata.go   *_string.go
```

**Skip files larger than 1 MB**.

### Step 1.3: Score each surviving file

For every file that passed step 1.2 AND has an extension in your detected languages list, compute a score:

**Path signals** (additive, match against the relative path):

| Substring (in path) | Weight |
|---|---|
| `/cmd/` | 4 |
| `/main/` | 3 |
| `/handlers/` or `/handler/` | 5 |
| `/routes/` or `/route/` | 5 |
| `/controllers/` or `/controller/` | 5 |
| `/api/` | 4 |
| `/auth/` | 5 |
| `/middleware/` | 4 |
| `/server/` | 3 |
| `/rpc/` | 4 |
| `/gateway/` | 4 |
| `/session/` | 3 |
| `/permissions/` | 4 |
| `/users/` | 3 |
| `/admin/` | 4 |
| `/upload/` | 5 |

**Content signals** (additive, count regex matches in file content; cap each pattern at 10 matches):

| Pattern (case-insensitive where noted) | Weight per match (×min(N,10)) |
|---|---|
| `os/exec`, `exec.Command`, `subprocess`, `child_process`, `popen(`, `Runtime.exec` | 6 |
| `eval(`, `new Function(`, `Function('` | 7 |
| `unsafe`, `reflect.unsafe` | 4 |
| `db.Exec`, `db.Query`, `db.Raw`, `raw_query`, `cursor.execute`, `conn.query` (i) | 5 |
| `SELECT...FROM` (within 80 chars) (i) | 3 |
| `http.Handle`, `router.`, `app.get/post/put/delete` | 5 |
| `jwt`, `oauth`, `saml`, `sso`, `auth(enticate|orize)?` (i) | 4 |
| header-related: `request.headers`, `getHeader`, `Header.Get`, `x-forwarded-`, `x-real-ip`, `x-original-`, `x-rewrite-url`, `x-http-method-override`, `x-(user|auth|tenant|org|admin|internal|debug|preview|middleware)` (i) | 5 |
| `password`, `passwd`, `secret`, `api[_-]?key`, `token`, `credential` (i) | 3 |
| `crypto`, `md5`, `sha1`, `aes`, `rsa`, `pkcs`, `encrypt`, `decrypt`, `sign(`, `verify(` (i) | 3 |
| `pickle.loads`, `yaml.load`, `fromXml`, `XMLDecoder`, `unmarshal`, `deserialize` (i) | 6 |
| `readFile`, `writeFile`, `open(`, `fopen`, `os.path.join`, `filepath.Join` (i) | 2 |
| `redirect`, `sendFile`, `res.send`, `response.write`, `res.json` (i) | 2 |
| `../`, `path.resolve`, `path.join`, `os.path.abspath` | 2 |
| `shell=True`, `cmd /c`, `sh -c`, `bash -c` | 6 |
| `requests.get/post`, `axios`, `fetch(`, `http.Get`, `net/http` | 3 |
| `\bSSRF\b`, `\bRCE\b`, `\bXXE\b`, `\bSSTI\b`, `\bIDOR\b`, `\bCSRF\b`, `\bXSS\b` | 5 |

For very large files (>256 KB), score only the first 256 KB to keep the walk fast.

The **total score** = sum of path-signal weights + sum of (content-pattern-weight × min(matchCount, 10)).

For each scored file, also compute:
- `bytes`: file size in bytes
- `language`: from the extension table above
- `sha8`: first 8 hex chars of `sha1(<relative-path-as-utf8>)` — a stable per-anchor namespace so hunters' draft filenames don't collide

### Step 1.4: Rank and cap

Sort all candidates: `score DESC`, then `path.length ASC`, then `path ASC` (stable lexicographic).

Take the top **1000** entries (`limit = 1000`). On dense repos that produces ~6 hours wall-clock at 3 concurrent hunters; tune the limit down on smaller repos by inspection.

### Step 1.5: Write targets.json

Write `archon/longshot/targets.json`:

```json
{
  "generated_at": "<ISO timestamp>",
  "cwd": "<absolute target dir>",
  "languages": ["TypeScript", "Python"],
  "limit": 1000,
  "total_candidates": <total before cap>,
  "skipped_tests": <count>,
  "skipped_generated": <count>,
  "skipped_oversized": <count>,
  "skipped_unrecognized": <count>,
  "targets": [
    {
      "path": "src/api/handlers/users.ts",
      "language": "TypeScript",
      "score": 47,
      "bytes": 8192,
      "sha8": "a3f9c2e1",
      "status": "pending"
    },
    ...
  ]
}
```

**Implementation hint**: A small inline `bun` or `python3` script run via Bash is the right tool here — pure deterministic file walking + regex matching, no LLM reasoning needed. Don't grep file-by-file for 17 separate patterns; do one walk that buffers content and tests every pattern in-memory. Keep the script under 200 lines; inline it, don't write it to disk.

When `targets.json` exists already (resume case), preserve `status` / `attempts` / `completed_at` / `draft_count` for paths that still match, and reset everything else to `pending`.

If 0 candidates survive, write a minimal `targets.json` with `targets: []` and skip directly to writing a "no candidates" `longshot-summary.md`.

---

## Phase 2: Hunt (file-by-file fan-out)

Group the pending targets into batches of 3. For each batch:

1. Spawn three `archon:longshot-prober` Tasks **concurrently in a single message**, each with `run_in_background: true` (Claude) / equivalent on Codex. Each Task carries the four input variables in its prompt — nothing more — because the hunter's system prompt already specifies the workflow:

   ```
   Anchor: <target.path>
   Anchor-Sha8: <target.sha8>
   Language: <target.language>
   Rank: <rank>/<total>
   ```

2. Poll `TaskGet`/`TaskList` (or platform equivalent) until **all three Tasks** in the batch have settled (`status: complete` or `failed`). Do NOT spawn the next batch before then.

3. Re-read `archon/longshot/targets.json` once per batch to refresh statuses (hunters update their own rows on completion).

The 3-at-a-time cap prevents overwhelming the platform's tool budget on 1000-anchor runs.

### Failure handling

If a hunter Task settles as `failed`, or completes without writing any draft for its anchor:
1. Mark its target's `status: "failed"` and write `last_error: "<reason>"` in `targets.json`.
2. Continue with the rest of the batch — do not abort the run for one failed file.
3. Do not retry failed hunters automatically. The user can re-run with the resume flow.

Phase 2 finishes when every target has `status` ∈ `{complete, failed}`. If **all** hunters fail, STOP — do not run Phase 3 against zero output.

---

## Phase 3: Aggregate & Deduplicate

Dispatch `archon:longshot-collector` (single foreground run, no fan-out). It reads every draft under `archon/longshot/findings-draft/`, deduplicates by root cause, ranks by severity+confidence, writes curated drafts (`longshot-curated-NNN-<slug>.md`), and writes the final report at `archon/longshot/longshot-summary.md`.

Verify `archon/longshot/longshot-summary.md` exists and is non-empty after the aggregator finishes.

---

## Output

After all phases complete, print a brief summary to the user:

```
Longshot Audit Complete

  Targets enumerated: <N> (skipped <M> tests, <K> generated)
  Hunters dispatched: <N>     completed: <C>     failed: <F>
  Raw drafts:         <D>
  Curated findings:   <U>     critical: <c>  high: <h>  medium: <m>  low: <l>

  Summary report:     archon/longshot/longshot-summary.md
  Curated drafts:     archon/longshot/findings-draft/longshot-curated-*.md

  Next steps:
    - Review the summary report; promote curated findings into archon/findings/ manually.
    - Run /archon:confirm against any high-confidence finding to build a live PoC.
```

---

## Notes

- **No knowledge base, no DFD/CFD, no probe teams**. Longshot is intentionally architecture-blind. If you find yourself building component models, you are running the wrong mode.
- **No final-audit-report.md**. Longshot writes its own `archon/longshot/longshot-summary.md`; the deep-mode report is untouched.
- **Curated findings are not auto-promoted**. The user reviews `longshot-summary.md` and manually promotes high-confidence findings into `archon/findings/<ID>-<slug>/` if they want them in the canonical findings tree.
- **Cost**: A 1000-file run at 3-concurrent hunters can spend several USD per file on Opus and burn 6+ wall-clock hours. Tune the `limit` in Phase 1 down for cheaper runs.
- **Resume is cheap**: targets.json tracks per-anchor state. Killing the run and restarting picks up only the files that didn't complete.
