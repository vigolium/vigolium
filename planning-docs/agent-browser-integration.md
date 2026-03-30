# Agent-Browser Integration Plan

Integrate [vercel-labs/agent-browser](https://github.com/vercel-labs/agent-browser) as a browser automation tool for Vigolium's agent autopilot and swarm modes. Primary goal: enable agents to explore and capture login flows, perform authenticated browsing, and feed captured credentials into the scanning pipeline.

## Background

### What is agent-browser?

A Rust CLI that wraps Chrome via CDP, designed as a tool for AI agents. Not a crawler — it's a low-level browser automation primitive.

- Agent issues shell commands (`snapshot`, `click @e2`, `fill @e3 "text"`)
- Primary representation: **accessibility tree** with element refs (not pixels, not DOM)
- Stateful daemon keeps Chrome alive between commands
- Agent-safety features: domain allowlists, action policies, content boundaries
- **Does NOT support MCP** — pure CLI tool, integrated via skills (prompt-engineering)

### Key agent-browser capabilities for this integration

- **Auth vault**: AES-256-GCM encrypted credential storage, LLM never sees raw passwords
- **Session persistence**: `--session-name <name>` persists cookies + localStorage across commands
- **State export**: `state save ./auth.json` exports cookies + localStorage as JSON
- **Cookie extraction**: `cookies --json` for direct cookie access
- **Profile persistence**: `--profile <path>` for full Chrome user data directory reuse

### How Vigolium currently teaches agents

```
Layer 1: CLAUDE.md (system prompt, written to session dir)
   Loaded from: public/presets/prompts/autopilot/autopilot-system-prompt.md
   Override at: ~/.vigolium/prompts/autopilot-system-prompt.md

Layer 2: SKILL.md (detailed CLI operator guide)
   public/skills/vigolium-scanner/SKILL.md (679 lines)
   + references/ folder with deep-dive docs per topic

Layer 3: Prompt templates (per-phase instructions for swarm)
   public/presets/prompts/swarm/ — plan, extension phases
   public/presets/prompts/autopilot/ — specialist templates
   Variables injected: {{.TargetURL}}, {{.Extra.RequestContext}}, etc.
```

### How tools are exposed to agents

This integration targets the **SDK protocol only** (Claude Agent SDK). The SDK protocol gives agents full Claude Code CLI tool access (Read, Grep, Glob, Bash, Edit, Write), so `agent-browser` is just another CLI tool the agent can call via Bash — no special tool registration needed.

The agent learns about agent-browser through the prompt/skill system (CLAUDE.md + SKILL.md), not through protocol-level tool declarations.

## Global Enable/Disable: Config + CLI Flag

All agent-browser functionality is gated behind a config setting and a CLI flag. When disabled (the default), no agent-browser skill is loaded, no browser instructions appear in prompts, and the auth phase is skipped.

### Config setting

**File:** `internal/config/agent.go`

```yaml
# vigolium-configs.yaml
agent:
  browser:
    enabled: false                    # default: disabled
    command: "agent-browser"          # path or binary name
    session_dir: ""                   # override browser session storage (default: session dir)
    default_flags:                    # flags appended to every agent-browser invocation
      - "--json"
```

```go
type BrowserConfig struct {
    Enabled      *bool    `yaml:"enabled"`
    Command      string   `yaml:"command"`       // default: "agent-browser"
    SessionDir   string   `yaml:"session_dir"`
    DefaultFlags []string `yaml:"default_flags"`
}
```

### CLI flags

Applied to `vigolium agent autopilot` and `vigolium agent swarm`:

```bash
--browser           # Enable agent-browser (overrides config)
--no-browser        # Disable agent-browser (overrides config)
```

Examples:

```bash
# Config has browser.enabled: false, but enable for this run
vigolium agent autopilot --target https://app.example.com --browser

# Config has browser.enabled: true, but skip browser for this run
vigolium agent swarm --target https://app.example.com --no-browser --discover

# Combined with auth
vigolium agent swarm --target https://app.example.com --browser --auth \
  --credentials "username=admin,password=secret123"
```

### Resolution order

```
CLI --browser/--no-browser  (highest priority)
    ↓
Config agent.browser.enabled
    ↓
Default: false (disabled)
```

### What the flag controls

When `browser` is **enabled**:
- Agent-browser skill is copied to `{sessionDir}/.claude/skills/agent-browser/` (Phase 3)
- Browser instructions section is included in the autopilot system prompt (Phase 2)
- `agent-browser` is not added to `DisallowedTools` Bash restrictions (Phase 4)
- `SwarmPhaseAuth` is available (Phase 5, still requires `--auth` to trigger)
- Agent is informed that `agent-browser` is available and when to use it

When `browser` is **disabled** (default):
- No agent-browser skill is copied
- No browser instructions in system prompt
- `agent-browser` is added to `DisallowedTools` as `Bash(agent-browser:*)` to prevent use (Phase 4)
- `SwarmPhaseAuth` is skipped even if `--auth` is passed (with a warning)
- Agent has no knowledge of agent-browser — zero context overhead

## Integration Phases

### Phase 1: Skill Creation (no code changes)

Create an agent-browser skill alongside the existing vigolium-scanner skill.

**Directory structure:**

```
public/skills/agent-browser/
├── SKILL.md                    # Core workflow guide
└── references/
    ├── auth-workflows.md       # Login capture patterns
    ├── state-management.md     # Session persistence, auth vault
    └── commands-reference.md   # Full command index
```

**SKILL.md content should cover:**

1. **Core workflow** — the snapshot -> ref -> action loop:
   - `agent-browser open <url>` — navigate
   - `agent-browser snapshot --json` — get accessibility tree with refs (@e1, @e2...)
   - `agent-browser click @e5` / `agent-browser fill @e3 "text"` — interact via refs
   - Re-snapshot after each page change

2. **When to use** — decision criteria:
   - Login forms that need real browser interaction
   - SPAs where endpoints only appear after JS execution
   - Multi-step auth flows (OAuth, MFA setup pages)
   - Capturing cookies/localStorage after authentication

3. **Auth capture workflow** — step-by-step recipe:
   - Open login page
   - Snapshot and identify form fields
   - Fill credentials and submit
   - Wait for redirect: `agent-browser wait --url "/dashboard"`
   - Export state: `agent-browser state save ./auth-state.json`
   - Extract cookies: `agent-browser cookies --json`
   - Feed into vigolium: `vigolium scan --header "Cookie: ..." ...`

4. **Auth vault usage** — for pre-stored credentials:
   - `agent-browser auth login <name>` — auto-fills login form
   - LLM never sees raw passwords

5. **Key flags reference**:
   - `--session-name <name>` — persist browser session across commands
   - `--json` — machine-readable output for parsing
   - `--profile <path>` — full Chrome profile persistence
   - `--annotate` — numbered labels on screenshots for visual models

**References docs** should cover:
- `auth-workflows.md`: Common login patterns (form-based, OAuth redirect, SSO, MFA), how to detect login success, handling CAPTCHAs (manual intervention), token refresh patterns
- `state-management.md`: Session persistence (`--session-name`), state files (`state save/load`), auth vault (`auth save/login`), profile persistence, encryption, import from running Chrome (`--auto-connect`)
- `commands-reference.md`: Categorized command index (navigation, interaction, observation, network, cookies/storage, auth, sessions, batch)

### Phase 2: Autopilot System Prompt Update (small code change)

Add agent-browser instructions to the autopilot system prompt **conditionally** — only when `browser` is enabled.

**File to modify:** `pkg/agent/sdk_prompts.go` (or wherever the system prompt is assembled)

**Change:** After loading the base autopilot system prompt, append the browser section only if `cfg.Browser.IsEnabled()`:

```go
systemPrompt := loadBaseAutopilotPrompt()
if cfg.Browser.IsEnabled() {
    systemPrompt += "\n\n" + loadBrowserPromptSection()
}
```

The browser prompt section (stored as a separate embedded file, e.g., `public/presets/prompts/autopilot/autopilot-browser-section.md`) contains:

```markdown
## Browser Automation (agent-browser)

When you need to interact with a real browser (login flows, SPAs, JavaScript-rendered content), use `agent-browser`:

### Core Loop
1. `agent-browser open <url>` — navigate to page
2. `agent-browser snapshot --json` — get accessibility tree with element refs (@e1, @e2...)
3. `agent-browser fill @ref "value"` / `agent-browser click @ref` — interact using refs
4. Re-snapshot after each interaction to see updated state

### When to Use
- Target requires authentication and you have credentials
- Login flow is complex (OAuth, MFA, multi-step)
- You need to discover endpoints behind a login wall
- SPA routes only appear after JavaScript execution

### Auth Capture
After successful login:
1. `agent-browser cookies --json` — extract session cookies
2. Use captured cookies with vigolium: `vigolium scan --header "Cookie: session=abc123" ...`
3. Or save state for later: `agent-browser state save ./auth-state.json`

### Auth Vault (pre-stored credentials)
If credentials are pre-stored in the auth vault:
- `agent-browser auth login <name>` — browser handles login automatically
- Credentials are encrypted, you never see raw passwords

### Important
- Always use `--session-name <hostname>` to persist browser state across commands
- Use `--json` flag for machine-readable output you can parse
- After capturing auth, ALWAYS verify by accessing an authenticated endpoint before scanning
```

### Phase 3: Skill Auto-Discovery in Session Workspace (small code change)

Currently, Vigolium writes `CLAUDE.md` to the session dir but doesn't copy skills. Claude Code auto-discovers `.claude/skills/` from the working directory.

**File to modify:** `pkg/agent/sdk_runner.go`

**Change:** After writing `CLAUDE.md` to `sessionDir`, also copy embedded skills into `{sessionDir}/.claude/skills/`:

```go
// After writing CLAUDE.md:
skillsDir := filepath.Join(sessionDir, ".claude", "skills")
os.MkdirAll(skillsDir, 0o755)

// Copy embedded skills from public/skills/
// - public/skills/vigolium-scanner/ → skillsDir/vigolium-scanner/
// - public/skills/agent-browser/    → skillsDir/agent-browser/
```

This gives the agent automatic access to both skills without embedding everything in the system prompt (which would bloat context for simple tasks).

**Gating:** Only copy the agent-browser skill when `browser` is enabled (config or `--browser` flag). The vigolium-scanner skill is always copied.

```go
// Always copy vigolium-scanner skill
copyEmbeddedSkill("vigolium-scanner", skillsDir)

// Only copy agent-browser skill when browser is enabled
if cfg.Browser.IsEnabled() {
    copyEmbeddedSkill("agent-browser", skillsDir)
}
```

### Phase 4: SDK Tool Access Control (small code change)

The SDK protocol gives agents full Bash access by default. When `browser` is disabled, we block `agent-browser` via the existing `DisallowedTools` mechanism to enforce the gate even if the agent somehow learns about the tool.

**File to modify:** `pkg/agent/sdk_runner.go` (where SDK options are built)

**Change:** Conditionally add `agent-browser` to the disallowed tools list:

```go
disallowed := []string{
    "AskUserQuestion",
    "EnterWorktree",
    "EnterPlanMode",
    "ExitPlanMode",
}

if !cfg.Browser.IsEnabled() {
    // Block agent-browser CLI when browser is disabled
    browserCmd := cfg.Browser.Command // default: "agent-browser"
    disallowed = append(disallowed, fmt.Sprintf("Bash(%s:*)", browserCmd))
}
```

When `browser` is enabled, no Bash restriction is added — the agent can freely call `agent-browser` commands. The skill and system prompt (Phases 1-3) teach it when and how to use them.

**Why not just rely on prompt omission?** The prompt/skill gate (Phases 2-3) is the primary control — the agent won't know about `agent-browser` if the instructions aren't loaded. The `DisallowedTools` entry is a defense-in-depth measure for cases where the agent might discover the binary on its own (e.g., via `which agent-browser` or `ls /usr/local/bin/`).

### Phase 5: Swarm Auth Phase (medium code change)

Add a dedicated authentication phase to the swarm pipeline that runs before discovery. This phase uses the SDK protocol — the agent gets full Claude Code tools (including Bash) and uses `agent-browser` CLI commands to perform browser-based authentication.

#### 5a. New phase constant

**File:** `pkg/agent/swarm.go`

```go
const SwarmPhaseAuth = "auth"
```

Insert in pipeline order: `Normalize → Source Analysis → Auth → Discovery → Plan → ...`

#### 5b. Auth phase prompt template

**File:** `public/presets/prompts/swarm/agent-swarm-auth.md`

The auth phase agent runs via SDK protocol with full Bash access. It calls `agent-browser` commands through Bash tool calls.

```markdown
---
id: agent-swarm-auth
name: Agent Swarm Auth
description: Authenticate to target using agent-browser (via Bash) and capture session state
output_schema: session_config
variables:
  - TargetURL
  - Hostname
---

# Authentication Phase

Target: {{.TargetURL}}

## Objective
Use `agent-browser` via Bash to authenticate to the target application and capture the session state for subsequent scanning phases.

## Credentials
{{if .Extra.AuthCredentials}}
Use these credentials: {{.Extra.AuthCredentials}}
{{else}}
Check if `agent-browser auth list` has stored credentials for this target.
If not, look for common login pages at {{.TargetURL}} (/login, /signin, /auth, /api/auth).
{{end}}

## Steps
Use Bash to run these agent-browser commands:

1. Open the login page: `agent-browser --session-name {{.Hostname}} open <login-url>`
2. Snapshot to identify the login form fields: `agent-browser snapshot --json`
3. Fill credentials using refs from the snapshot: `agent-browser fill @ref "value"`
4. Submit the form: `agent-browser click @ref`
5. Verify successful login (check URL change, presence of dashboard/profile elements)
6. Export cookies: `agent-browser cookies --json`
7. If the app uses JWT/Bearer tokens, check localStorage: `agent-browser storage local --json`
8. Save the full browser state for potential reuse: `agent-browser state save {{.Extra.SessionDir}}/browser-state.json`

## Output
Return a session_config with captured authentication data:
- Cookie headers for the authenticated session
- Any Bearer/JWT tokens found in localStorage
- The login endpoint and method used
```

#### 5b-alt. SDK execution details

The auth phase is dispatched via `RunAgenticSDK()` like other SDK-based phases. The agent-browser skill (Phase 1) is available in the session workspace's `.claude/skills/` directory, so the agent has full reference documentation for `agent-browser` commands.

```go
// In swarm.go, auth phase execution:
func (s *SwarmRunner) runAuthPhase(ctx context.Context, cfg *SwarmConfig) error {
    opts := &Options{
        PromptTemplate: "agent-swarm-auth",
        AgentName:      cfg.AgentName,
        TargetURL:      cfg.TargetURL,
        OutputSchema:   "session_config",
        Extra: map[string]string{
            "AuthCredentials": cfg.Credentials,
            "SessionDir":      cfg.SessionDir,
        },
    }
    // Uses SDK protocol — agent gets Bash access to call agent-browser
    result, err := s.engine.Run(ctx, opts)
    // Parse session_config from result, write to session-config.json
    return s.writeSessionConfig(cfg.SessionDir, result)
}
```

#### 5c. Credential passing between phases

The mechanism already exists: `session-config.json` in the session directory.

**Flow:**
```
Auth Phase (agent + agent-browser)
  ├─ Performs login via browser
  ├─ Extracts cookies/tokens
  ├─ Writes session-config.json to session dir
  │
  ↓
Discovery Phase (Spitolas/Deparos)
  ├─ Reads session-config.json
  ├─ Applies Cookie/Auth headers to all HTTP requests
  │
  ↓
Scan Phase (native modules)
  ├─ Same auth headers applied to all scan requests
```

For agent-browser session persistence across swarm phases, use `--session-name` tied to the target hostname. The browser state survives between agent calls, enabling re-authentication if tokens expire during long scans.

#### 5d. CLI flags for auth phase

Add `--auth`, `--credentials`, and `--auth-vault` flags to `vigolium agent swarm`:

```bash
# With pre-stored auth vault credentials
vigolium agent swarm --target https://app.example.com --discover --browser --auth

# With inline credentials (passed to agent via prompt template)
vigolium agent swarm --target https://app.example.com --discover --browser \
  --credentials "username=admin,password=secret123"

# With auth vault name
vigolium agent swarm --target https://app.example.com --discover --browser \
  --auth-vault myapp
```

**Dependency:** `--auth` requires `--browser` (either via flag or config). If `--auth` is passed without browser enabled, print a warning and skip the auth phase:

```
WARN: --auth requires --browser to be enabled. Skipping auth phase.
      Enable with: --browser flag or agent.browser.enabled: true in config.
```

`--browser` without `--auth` is valid — the agent has browser access but no dedicated auth phase (it can still use agent-browser ad-hoc during autopilot or other phases).

## Credential Flow Diagram

```
                    ┌─────────────────────────┐
                    │   Credential Sources     │
                    ├─────────────────────────┤
                    │ 1. agent-browser vault   │  agent-browser auth save myapp ...
                    │ 2. CLI --credentials     │  --credentials "user=x,pass=y"
                    │ 3. Config file           │  vigolium-configs.yaml
                    │ 4. Source analysis        │  Agent discovers from code
                    └──────────┬──────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │   Auth Phase (Swarm)     │
                    │   agent + agent-browser  │
                    ├─────────────────────────┤
                    │ open login page          │
                    │ snapshot → find form     │
                    │ fill credentials         │
                    │ click submit             │
                    │ wait for redirect        │
                    │ cookies --json           │
                    │ storage local --json     │
                    └──────────┬──────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │  session-config.json     │
                    │  (session directory)     │
                    ├─────────────────────────┤
                    │ {                        │
                    │   "sessions": [{         │
                    │     "type": "session",   │
                    │     "headers": {         │
                    │       "Cookie": "..."    │
                    │     }                    │
                    │   }]                     │
                    │ }                        │
                    └──────────┬──────────────┘
                               │
                    ┌──────────┴──────────────┐
                    │                          │
                    ▼                          ▼
          ┌─────────────────┐      ┌─────────────────┐
          │ Discovery Phase │      │   Scan Phase     │
          │ (authenticated) │      │ (authenticated)  │
          └─────────────────┘      └─────────────────┘
```

## Implementation Priority

| Priority | Phase | Effort | Effect |
|----------|-------|--------|--------|
| P0 | Config + CLI flag (`--browser`/`--no-browser`) | 1-2 hours | Global gate for all browser functionality |
| P0 | Phase 1: Create SKILL.md | 1-2 hours | Agent has structured reference for agent-browser |
| P0 | Phase 2: Conditional autopilot system prompt | 1 hour | Autopilot agent knows when and how to use browser |
| P1 | Phase 3: Conditional skill auto-discovery | 2-3 hours | Clean separation, auto-loaded by Claude Code |
| P1 | Phase 4: SDK DisallowedTools gating | 30 min | Defense-in-depth: block agent-browser when disabled |
| P2 | Phase 5: Swarm auth phase (`--auth`) | half day | Full pipeline integration with auth before scanning |

## Open Questions

1. **Skill installation**: Should `agent-browser` be bundled/embedded, or require separate installation? If separate, the skill should include setup instructions and the agent should check if it's available before attempting browser commands.

2. **Browser lifecycle in swarm**: Should the browser daemon persist across all swarm phases, or start fresh for each phase that needs it? Persistent = faster + maintains state, fresh = cleaner isolation.

3. **Fallback when agent-browser is not installed**: The auth phase should gracefully degrade — if agent-browser isn't available, fall back to the existing session-config extraction from source analysis or manual header injection.

4. **CAPTCHA handling**: agent-browser can't solve CAPTCHAs. If the login flow has a CAPTCHA, the agent should detect it and either: (a) skip auth phase and warn the user, or (b) use the auth vault approach where credentials were captured from a real browser session via `--auto-connect`.

5. **Token refresh**: For long-running swarm scans, session tokens may expire. Should there be a mid-scan re-auth mechanism? The agent-browser session persists via `--session-name`, so re-running the auth flow is possible, but needs orchestration in the swarm runner.
