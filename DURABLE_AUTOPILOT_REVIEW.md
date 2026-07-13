# Durable Autopilot — review guide

Evolves `pkg/olium/autopilot` in place with three capabilities, all behind one
config flag that defaults to `legacy`, so **current behavior is byte-for-byte
unchanged unless opted in**:

1. **Bounded operator sections with context rotation** — removes the
   unbounded-history context ceiling by splitting a run into sections
   (`eng.Reset()` + a reconstructed brief) driven by turn/stall/token limits.
2. **Durable state + resume** — sections + candidates persist to new DB tables;
   `--resume <uuid>` re-enters a run from durable state.
3. **Verify-before-promote findings** — in non-legacy modes the operator
   *proposes candidates*; a fresh-context skeptic verifier grades each against a
   per-class evidence gate and promotes only the confirmed ones into findings.

## How to enable

```yaml
# vigolium-configs.yaml
agent:
  olium:
    autopilot_mode: enforced   # legacy (default) | shadow | enforced
```

- **legacy** (default / empty / any unknown value): current path. No rotation,
  `report_finding` writes findings directly, the new tables are never touched.
- **shadow**: rotation ON; `report_finding` still writes findings directly, but
  each is *mirrored* into a candidate row and re-verified. Confirmed candidates
  are promoted as **distinct** findings (`finding_source=autopilot-shadow-verified`,
  separate hash) so FP rates of the direct path vs. the verified path can be
  compared side by side.
- **enforced**: rotation ON; `report_finding` is replaced by `propose_candidate`.
  Only verified candidates become findings (`finding_source=autopilot-verified`).

Rotation additionally requires a session dir (always present for real runs).

## Files

### Stage A — Config + DB
- `internal/config/agent.go` — `OliumConfig.AutopilotMode` (`autopilot_mode`),
  `NormalizeAutopilotMode()` (single source of truth), `EffectiveAutopilotMode()`,
  `AutopilotMode{Legacy,Shadow,Enforced}` consts.
- `pkg/database/db.go` — new `agent_sections` + `agent_finding_candidates` DDL in
  the `tables` slice, indexes (incl. `UNIQUE(agentic_scan_uuid, dedup_hash)` for
  candidate dedup) in the `indexes` slice. No new BOOLEAN columns, so `adaptDDL`
  is unchanged.
- `pkg/database/models.go` — Bun models `AgentSection`, `AgentFindingCandidate`.
- `pkg/database/repository_agent_state.go` — `SaveAgentSection`,
  `UpdateAgentSection`, `ListAgentSections`, `SaveCandidate` (ON CONFLICT dedup),
  `ListCandidates`, `UpdateCandidateStatus`; status consts.
- `pkg/database/query.go` — cascade wiring: `agentic_scans` `CascadeFirst`s the
  two child tables; both added to `AllowedCleanTables` + `allTablesDeleteOrder`.
- `pkg/database/repository_projects.go` — both tables added to
  `projectOwnedTables` (project reassign/purge; enforced by an existing invariant
  test).
- Tests: `repository_agent_state_test.go`, `internal/config/agent_test.go`
  (`TestEffectiveAutopilotMode`).

### Stage B — Candidate tool
- `pkg/olium/autopilot/candidate.go` — `CandidateSink` interface +
  `RepoCandidateSink` adapter (repo's `SaveCandidate` returns `(bool,error)`),
  `ProposeCandidateContext`, `NewProposeCandidateTool` (`propose_candidate`,
  report_finding schema + `class` enum + `verification_notes` + `oast_ids`),
  `PersistCandidateFromArgs` (reuses `hashFinding`/`hashDedupKey`/`parseRecordUUIDs`/
  `extractHostname`), and `NewShadowReportFindingTool` (writes finding **and**
  mirrors a candidate).
- Test: `candidate_test.go` (persist, dedup, validation, no-sink).

### Stage C — Section controller (the crux)
- `pkg/olium/autopilot/section.go` — `SectionController` (SessionDir, optional
  Repo, project/scan uuids, scratchpad, `SectionRecorder`, knobs
  `MaxTurnsPerSection`=40, `StallTurns`=12, `ContextTokenSoftCap`), `BeginSection`
  (mints uuid, continues seq across resume, persists running row, emits
  section_start), `ShouldRotate` (turn cap / token soft cap / stall, with
  `progressed` resetting the stall counter), `EndSection`, `StoreClosingSummary`
  (keyed scratch note `section-<N>-closing`), `BuildReconstructedBrief`
  (mission + working memory + previous closing summary + candidate ledger +
  current task + recent-actions window + record count), and the nil-safe
  `SectionRecorder` interface.
- `pkg/olium/autopilot/scratchpad.go` — added `Render()` (locked wrapper),
  `Remember()`/`NoteByKey()` (keyed-note store/read), `NextOpenTask()`.
- Test: `section_test.go` (ShouldRotate triggers, begin/end persistence,
  reconstructed-brief content).

### Stage D — Wire autopilot.go
- `pkg/olium/autopilot/autopilot.go` — `Options.Mode`; mode gate
  (`rotationEnabled = mode!=legacy && SessionDir!=""`); finding-tool registration
  branch (legacy→report_finding, enforced→propose_candidate, shadow→shadow tool);
  per-section turn/token counters + an 8-entry recent-actions ring fed from
  `EventToolExecEnd`; a `progressedThisWindow` flag; a `ShouldRotate` check at
  `EventTurnDone` (after budget checks) that cancels the iteration like the halt
  path; and an outer-loop handoff (closing summary via one tool-less engine call
  → `StoreClosingSummary` → `EndSection` → `eng.Reset()` → `BeginSection` →
  `BuildReconstructedBrief`). The `EventError` arm now treats a rotation cancel as
  expected (`!halted && !pendingRotation`). **Every rotation variable is inert in
  legacy** (`rotationEnabled=false`, `controller=nil`).
- `pkg/olium/autopilot/rotation.go` — `buildRotationMission`, recent-actions
  helpers, `summarizeSection` (the cheap tool-less closing-note call),
  `productiveTools` set, `oneLine`.

### Stage E — Transcript events
- `pkg/olium/sessionlog/schema.go` — `section_start` / `section_end` /
  `section_interrupted` structs (additive, following the non-Pi `error` event
  precedent; Pi viewers ignore unknown types).
- `pkg/olium/sessionlog/recorder.go` — `SectionStart` / `SectionEnd` /
  `SectionInterrupted` methods (single-writer safe; sections are serial). No
  concurrent tagging / sequence number, per spec.
- Test: `section_events_test.go`.

### Stage F — Verification + promotion
- `pkg/agent/autopilot_verify.go` — `VerifyCandidates` (lists proposed
  candidates, runs a fresh-context skeptic per candidate with bounded
  concurrency, each its **own** engine + its **own** `transcript-verify-<n>.jsonl`,
  read-only tools query_records/inspect_record/replay_request/oast_poll/
  browser_probe), per-class evidence gates (idor→owner/non-owner, xss→browser
  execution, sqli→paired controls, ssrf/rce→unique OAST, auth→bypass, else→
  attack+baseline), verdict application, and `promoteCandidate` (builds a
  `database.Finding` reusing report_finding's composition/hash via the exported
  wrappers, `SaveFindingDirect`, sets candidate `promoted_finding_id`+status).
- `pkg/agent/autopilot_verify_tool.go` — `submit_verdict` tool + `verdictSink`
  (the verifier's structured-output channel; a verifier that never submits
  defaults to `needs_evidence` — never confirm without an explicit judgment).
- `pkg/olium/autopilot/report_finding.go` — exported thin wrappers
  `HashFinding`/`HashDedupKey`/`ComposeDescription`/`ExtractHostname`/`Truncate`
  so pkg/agent promotes with identical hashing/composition.
- Wiring: `pkg/agent/autopilot_pipeline.go` (after the artifact verification, in
  non-legacy mode) and `pkg/cli/agent_autopilot_olium.go` (direct target-only
  path, before finalize/summary so DB counts include promotions). Both add
  `Mode: oliumCfg.EffectiveAutopilotMode()` to the `oautopilot.Options`.
- Test: `autopilot_verify_test.go` (verdict tool validation, evidence gates,
  shadow-vs-enforced hash, promotion writes a finding).

### Stage G — Resume
- `pkg/cli/agent_autopilot.go` — `--resume <agentic-scan-uuid>` flag + call.
- `pkg/cli/agent_autopilot_resume.go` — `prepareAutopilotResume`: loads the
  `AgenticScan`, reuses its uuid (so the session dir is reopened and
  `CreateAgenticScan` no-ops — no new scan), pins project/target/source, skips
  pre-scan + preflight + audit re-prep, marks still-running sections interrupted
  (DB + a `section_interrupted` transcript event), flips status back to running.
  The operator then re-enters seeded from the durable scratchpad + candidate
  ledger.

## How to review, stage by stage

```bash
# Everything type-checks (no binary produced):
go -C . build ./...

# Fast required suites:
go -C . test ./pkg/olium/autopilot/... ./pkg/database/... ./internal/config/... ./pkg/olium/sessionlog/...

# Stage F helpers (LLM-driven VerifyCandidates end-to-end is not unit-tested; the
# deterministic pieces are):
go -C . test ./pkg/agent/ -run 'TestSubmitVerdict|TestEvidenceGate|TestPromoted|TestPromoteCandidate'
```

Suggested reading order: config+DB (A) → candidate tool (B) → section controller
(C) → the `autopilot.go` diff (D, the crux — confirm legacy is untouched) →
transcript events (E) → verifier (F) → resume (G).

**Legacy-preservation checkpoints:** in `autopilot.go`, `rotationEnabled` is the
single gate; when false, the finding-tool registration falls to the `default`
case (`report_finding`), no section counters are touched, `ShouldRotate` is never
called, `pendingRotation` stays false, and `controller` is nil. The verify pass
and resume flag are both no-ops in legacy.

## Build / test status

- `go build ./...` — GREEN.
- `go vet` on all touched packages — clean.
- `pkg/olium/autopilot`, `pkg/database`, `internal/config`, `pkg/olium/sessionlog`,
  `pkg/agent` (short) — all PASS.

## Deferred / limitations (v1)

- **Token soft cap plumbed but disabled.** `SectionController.ContextTokenSoftCap`
  is wired end-to-end; `autopilot.go` passes `0` (disabled). Turn cap (40) + stall
  (12) are the active rotation triggers. A caller that knows the model's context
  ceiling can pass a fraction to enable it. `// TODO(durable-autopilot)`: source a
  per-model ceiling and pass a fraction.
- **`VerifyCandidates` not exercised end-to-end in tests** (needs a live provider).
  The deterministic pieces (verdict tool, gates, hash, promotion) are unit-tested;
  the LLM investigation loop is not.
- **Resume is minimal.** It reuses identity + durable state and skips pre-scan /
  preflight / audit re-prep and does **not** replay the original `--instruction`
  or diff context; it re-enters the operator loop from the durable scratchpad +
  candidate ledger. Resume opens a short-lived recorder to append the
  `section_interrupted` events, which writes a fresh transcript header segment
  (harmless for a debug log). Resume of the whitebox *pipeline* path (audit +
  frozen context) is not specially handled beyond skipping re-prep.
- **Shadow mode inflates finding counts by design** (direct finding + a distinct
  verified finding per confirmed candidate) so the two paths can be compared; this
  is intentional and only affects shadow runs.
- **`finalizeOliumAutopilotRun` finding_count column** reflects the operator's
  runtime counter, which is 0 in enforced mode (the operator proposes, it doesn't
  report). The operator-facing summary uses the DB-backed count
  (`findingCountForRun`), which is accurate because the verify pass runs before
  the summary; only the raw `finding_count` column may under-report for enforced
  runs. `// TODO(durable-autopilot)`: refresh the column from the DB after verify.
