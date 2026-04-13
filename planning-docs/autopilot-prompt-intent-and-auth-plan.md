# Autopilot Prompt Intent, Auth, and Browser Planning

This document captures the current `vigolium agent autopilot` prompt-handling flow, where information is lost today, and the most practical path to support natural-language configuration of target, source, intensity, credentials, session setup, and browser focus.

## Goal

Support commands like:

```bash
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
```

and eventually richer prompts such as:

```bash
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005 with admin/admin123, compare user/user123, focus on IDOR, use browser for login, run deep"
```

The desired outcome is that the prompt can drive:

- target URL
- source path
- diff/files focus
- intensity
- archon mode
- browser enablement and focus
- credentials and session construction
- authenticated scan preparation before the main autonomous operator starts

## Current Autopilot Flow

### CLI prompt entry

The CLI accepts a positional natural-language prompt in:

- [pkg/cli/agent_autopilot.go](/Users/j3ssie/Desktop/external/vigolium/pkg/cli/agent_autopilot.go:41)

When no explicit `--target`, `--input`, or `--source` flags are set:

1. `runAgentAutopilot()` calls `runAutopilotFromPrompt()`
2. `runAutopilotFromPrompt()` calls `parsePromptIntent()`
3. `parsePromptIntent()` calls `agent.ParseAndResolveIntent()`
4. the resolved `AppIntent` is copied into autopilot package-level flags via `applyIntentToAutopilotFlags()`
5. the normal autopilot flow resumes

Relevant code:

- [pkg/cli/agent_input.go](/Users/j3ssie/Desktop/external/vigolium/pkg/cli/agent_input.go:123)
- [pkg/cli/agent_autopilot.go](/Users/j3ssie/Desktop/external/vigolium/pkg/cli/agent_autopilot.go:597)
- [pkg/cli/agent_autopilot.go](/Users/j3ssie/Desktop/external/vigolium/pkg/cli/agent_autopilot.go:625)

### API prompt entry

The server supports the same idea through:

- [pkg/server/handlers_agent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/server/handlers_agent.go:110)

When `prompt` is present and explicit fields are empty:

1. `HandleAgentAutopilot()` calls `resolvePromptIntent()`
2. the first resolved app is mapped into the request
3. autopilot pipeline config is built and executed

Relevant code:

- [pkg/server/handlers_agent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/server/handlers_agent.go:118)
- [pkg/server/handlers_agent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/server/handlers_agent.go:257)

### Intent extraction layer

Prompt parsing is currently implemented in:

- [pkg/agent/intent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/intent.go:1)
- [pkg/agent/agenttypes/constants.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/agenttypes/constants.go:94)

The extractor returns `ScanIntent` with one or more `AppIntent` objects.

Current `AppIntent` fields:

- `target`
- `source_path`
- `focus`
- `instruction`
- `discover`
- `code_audit`
- `archon`
- `diff`
- `files`
- `browser`
- `max_commands`
- `timeout`
- `intensity`

### Autopilot pipeline layer

Once flags/request fields are set, autopilot builds:

- [pkg/agent/autopilot_pipeline.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_pipeline.go:36)

The pipeline:

1. resolves source/diff
2. optionally runs Archon
3. builds a context bundle and plan
4. renders the autonomous brief
5. launches the SDK agent

Relevant code:

- [pkg/agent/autopilot_pipeline.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_pipeline.go:80)
- [pkg/agent/autopilot_context.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_context.go:79)
- [pkg/agent/autopilot_pipeline.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_pipeline.go:386)
- [pkg/agent/engine.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/engine.go:124)

### Browser exposure in autopilot

Autopilot browser support is currently capability-based, not workflow-based.

- The SDK system prompt is loaded from [autopilot-system-prompt.md](/Users/j3ssie/Desktop/external/vigolium/public/presets/prompts/autopilot/autopilot-system-prompt.md:1)
- When browser is enabled, an extra browser appendix is added from [autopilot-browser-section.md](/Users/j3ssie/Desktop/external/vigolium/public/presets/prompts/autopilot/autopilot-browser-section.md:1)
- `agent-browser` is allowed or blocked at the SDK runner level in [pkg/agent/backend/sdk_runner.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/backend/sdk_runner.go:158)

This tells the autonomous operator how to use a browser, but does not force or structure an auth phase.

## What Prompt Parsing Can Drive Today

Today a prompt can reasonably affect:

- target URL
- source path
- focus text
- instruction text
- diff reference
- files list
- browser enablement hint
- max commands
- timeout
- intensity

This is enough for examples like:

```bash
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
```

The parser can produce:

- `target = http://localhost:3005`
- `source_path = ~/src/VAmPI`

and the rest of autopilot proceeds normally.

## What Prompt Parsing Cannot Drive Today

The current schema does not support a structured auth or browser target contract.

Missing capabilities:

- credentials in a structured form
- multiple roles or accounts
- login endpoint definition
- login method/body/content type
- bearer token path
- cookie capture strategy
- compare sessions for IDOR
- protected route hints
- browser start URL
- browser focus routes
- post-login landing hints
- MFA/TOTP hints
- session config injection
- auth header injection before operator launch

As a result, if the user puts credentials into the prompt, autopilot can only treat them as loose instruction text.

## Important Problems Found

### 1. Intent schema mismatch for Archon

The extraction prompt in [pkg/agent/intent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/intent.go:17) tells the model to emit:

- `audit_agent`

but the Go struct expects:

- `archon`

This likely causes prompt-derived Archon values to be dropped.

### 2. CLI and API mapping are inconsistent

CLI single-app autopilot applies more fields from `AppIntent` than the API path does.

The API path maps:

- target
- source
- focus
- instruction
- archon
- diff
- files
- max_commands
- timeout

but not `browser` or `intensity`.

Relevant code:

- [pkg/server/handlers_agent.go](/Users/j3ssie/Desktop/external/vigolium/pkg/server/handlers_agent.go:118)

### 3. Browser in autopilot is heuristic, not planned

Browser decision in autopilot comes from:

- focus text
- inferred auth hints from Archon findings
- target type

Relevant code:

- [pkg/agent/autopilot_context.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_context.go:179)

This is too indirect for prompts like:

- "use browser for login"
- "focus the browser on the admin UI"
- "log in first, then scan `/books` and `/users`"

### 4. Autopilot skips the existing session pipeline

This is the biggest gap.

Swarm already has:

- source auth analysis
- `session_config` formatting
- validation
- repair
- hydration
- DB persistence
- fallback reuse
- optional browser auth phase

Autopilot does not call any of it.

## Existing Swarm Capabilities Worth Reusing

### Source-derived session discovery

Swarm source exploration and formatting prompts:

- [swarm-source-explore.md](/Users/j3ssie/Desktop/external/vigolium/public/presets/prompts/swarm/swarm-source-explore.md:1)
- [swarm-source-format-session.md](/Users/j3ssie/Desktop/external/vigolium/public/presets/prompts/swarm/swarm-source-format-session.md:1)

These already mine:

- auth routes
- default credentials
- roles
- token locations
- cookie vs bearer model
- multi-step login flows

### Session config validation and repair

Relevant code:

- [pkg/agent/backend/session_validate.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/backend/session_validate.go:1)
- [pkg/agent/session_repair.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/session_repair.go:1)

This already fixes common LLM corruption:

- bad roles
- garbled content types
- truncated login URLs
- bad JSON bodies
- malformed token extraction

### Session hydration

Swarm can execute discovered login flows and produce real auth headers:

- [pkg/agent/swarm.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/swarm.go:2856)
- [pkg/session/session.go](/Users/j3ssie/Desktop/external/vigolium/pkg/session/session.go:1)
- [pkg/session/login.go](/Users/j3ssie/Desktop/external/vigolium/pkg/session/login.go:1)

Supported auth patterns include:

- bearer token login
- cookie login
- header extraction
- regex extraction
- multi-step login with variable passing

### Browser-based auth phase

Swarm already has a dedicated browser-auth prompt and phase:

- [agent-swarm-auth.md](/Users/j3ssie/Desktop/external/vigolium/public/presets/prompts/swarm/agent-swarm-auth.md:1)
- [pkg/agent/swarm_phase_ai.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/swarm_phase_ai.go:176)
- [pkg/agent/swarm.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/swarm.go:398)

This is more structured than autopilot:

- it accepts credentials input
- it has a clear browser task
- it requires an `auth-config.yaml` output

## Recommended Design Direction

The strongest approach is:

**Do not invent a separate auth/session system for autopilot. Reuse the existing swarm auth pipeline.**

Autopilot should gain a preflight preparation stage before the autonomous operator starts.

## Proposed Target Architecture

### Phase 1: Extend prompt intent schema

Extend `AppIntent` with structured auth and browser focus fields.

Suggested new fields:

- `credentials`
- `credential_sets`
- `login_url`
- `login_method`
- `login_body`
- `auth_type`
- `token_path`
- `protected_routes`
- `browser_start_url`
- `browser_focus_routes`
- `requires_browser`
- `session_config`

Also fix the current field mismatch:

- replace `audit_agent` in the prompt with `archon`

### Phase 2: Extend autopilot request/config contracts

Add first-class fields to:

- [pkg/server/types.go](/Users/j3ssie/Desktop/external/vigolium/pkg/server/types.go:461)
- [pkg/agent/autopilot_pipeline.go](/Users/j3ssie/Desktop/external/vigolium/pkg/agent/autopilot_pipeline.go:36)

New fields should include:

- `session_config`
- `auth_headers`
- `credentials`
- `browser_focus`
- `protected_routes`
- `auth_required`

### Phase 3: Add autopilot preflight auth preparation

Before the main autonomous operator runs, autopilot should optionally do:

1. source-auth analysis if `source` exists
2. prompt-to-session-config conversion if credentials are given directly
3. session validation
4. LLM repair if needed
5. hydration
6. persistence of:
   - `session-config.json`
   - `auth-headers.json`
   - `auth-state.json`
   - DB session rows

This should happen inside autopilot, not be left to the main operator as freeform work.

### Phase 4: Make browser focus explicit

Autopilot browser behavior should not depend only on heuristics.

The plan should be able to carry:

- where to open first
- which routes are probably login-gated
- which UI areas matter
- whether browser is required or only recommended

Suggested fields:

- `browser_start_url`
- `login_page_url`
- `focus_routes`
- `post_login_routes`

### Phase 5: Start operator with prepared auth context

After preflight completes, the autonomous operator should start with:

- hydrated auth headers
- known login endpoints
- known protected routes
- known browser focus points
- session artifacts already present

That is much more deterministic than asking the operator to discover and build all of it from scratch.

## Concrete Minimal Path

If implementation should stay small, the shortest viable path is:

1. Fix `intent.go` schema mismatch for `archon`
2. Add `browser` and `intensity` propagation on the API autopilot path
3. Add a prompt-to-session-config parser for direct credentials
4. Reuse existing session validation + hydration helpers from swarm
5. Write hydrated results into autopilot artifacts before `RunAutonomous()` launches the operator

This would already unlock:

- prompt-defined credentials
- prompt-defined browser usage
- prompt-defined intensity
- prompt-defined session preparation

without a large redesign.

## Ideal User Experience

The long-term target should allow prompts like:

```bash
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005 with admin/admin123, compare user/user123, focus on IDOR, use browser on the profile and books flows, run deep"
```

Expected resolved behavior:

- target URL: `http://localhost:3005`
- source path: `~/src/VAmPI`
- intensity: `deep`
- browser: enabled
- browser start/login focus: derived from prompt and source
- primary session: admin
- compare session: user
- auth hydrated before main execution
- operator brief explicitly prioritizes IDOR on protected routes

## Summary

Autopilot already has:

- natural-language target/source extraction
- source/diff resolution
- Archon integration
- browser capability injection
- an autonomous operator pipeline

What it lacks is the structured preparation layer between prompt parsing and operator launch.

Swarm already implements most of that missing layer.

The most defensible plan is to:

- strengthen the prompt intent schema
- promote auth/session data to first-class autopilot config
- reuse swarm's session discovery/validation/hydration pipeline
- convert browser use from heuristic prose into explicit preflight setup and plan inputs

That is the cleanest route to making natural-language autopilot prompts configure real scanning behavior instead of just decorating the operator brief.
