# Autopilot V2: Shannon-Inspired Enhancements

Goal: Evolve Vigolium's autopilot mode to match Shannon's depth while keeping Vigolium's hybrid approach (AI directs + native scanner executes).

Reference: Shannon (https://github.com/keygraph/shannon) — autonomous white-box AI pentester by Keygraph.

## Design Philosophy: Option B (Hybrid)

Shannon is **prompt-heavy, code-light** — 13 LLM agents do ALL scanning (4,000+ lines of prompt per vuln class, no native scanner modules). Everything runs through LLM inference.

Vigolium takes the **hybrid approach**: use LLM specialists for what they're uniquely good at (reading code to find custom sinks, browser-based exploitation verification) and let the native Go scanner handle repetitive payload testing.

```
Shannon:    LLM → craft payload → send request → read response → decide → repeat
Vigolium:   LLM → analyze code → generate extensions → native scan → LLM verify
```

This is cheaper, faster, more deterministic, and plays to existing strengths.

---

## Feature 1: MCP Server Support in ACP Sessions

**Priority: High — foundation for Features 2 and 5**

### What

Enable passing MCP server configurations to ACP agent sessions. The plumbing exists (`NewSessionRequest.McpServers`) but is hardcoded to an empty slice.

### Why

Browser automation (Feature 2) and any future MCP tools require this. Shannon assigns per-agent MCP servers via `buildMcpServers()` — we need the same capability.

### Architecture

```
vigolium-configs.yaml
  agent:
    agents:
      autopilot:
        mcp_servers:                          ← NEW config field
          - name: playwright
            command: npx
            args: ["@anthropic-ai/mcp-playwright"]

Config (AgentDef.McpServers)
  → acp_runner.go: runACP()
    → NewSessionRequest.McpServers            ← populate from AgentDef
      → ACP agent receives MCP tools
```

### Changes

| File | Change |
|------|--------|
| `internal/config/agent.go` | Add `McpServers []McpServerConfig` to `AgentDef` struct. Fields: `Name`, `Command`, `Args`, `Env` |
| `pkg/agent/acp_runner.go` ~L195 | Map `AgentDef.McpServers` → `[]acp.McpServer` instead of empty slice |
| `pkg/cli/agent_autopilot.go` | Add `--mcp-server name=command,arg1,arg2` flag for ad-hoc MCP injection |
| `internal/config/agent.go` | Add `McpServerConfig` struct with YAML tags |

### Notes

- MCP servers are per-agent, not global — different specialists may need different tools
- Environment variable allowlisting (Shannon pattern): only pass whitelisted env vars to MCP subprocesses to prevent secret leakage
- When `--mcp-server` flag is used, merge with config-defined servers (flag takes precedence on name collision)

---

## Feature 2: Browser Automation via Playwright MCP

**Priority: High — biggest capability gap**

### What

Enable agents to use Playwright for DOM XSS testing, SPA navigation, form-based login, multi-step auth flows, and screenshot-based evidence collection.

### Why

Vigolium is HTTP-only today. Cannot test:
- DOM XSS (requires JavaScript execution)
- JavaScript-rendered SPAs
- Interactive login flows (form submission, OAuth redirects)
- CSRF tokens extracted from rendered pages
- Client-side storage manipulation

Shannon uses 5 isolated Playwright MCP instances — we need at least 1.

### Architecture

Builds directly on Feature 1. No new Go code beyond Feature 1 — Playwright MCP is external.

```
vigolium-configs.yaml:
  agent:
    agents:
      autopilot:
        mcp_servers:
          - name: playwright
            command: npx
            args: ["@anthropic-ai/mcp-playwright"]
```

### Changes

| File | Change |
|------|--------|
| `public/presets/prompts/autopilot/autopilot-system.md` | Add "Browser-Based Testing" section with guidance on when to use Playwright vs `vigolium scan-url` |
| `pkg/agent/acp_client.go` `RequestPermission()` | Consider domain allowlisting for Playwright navigation (optional safety measure) |

### Prompt Additions

Add to `autopilot-system.md`:

```markdown
## Browser-Based Testing (when Playwright MCP is available)

Use the browser for:
- DOM XSS verification (inject payload, check if alert/console fires)
- JavaScript-rendered pages that return empty HTML
- Form-based login flows (fill username/password, click submit)
- Multi-step workflows (add to cart → checkout → payment)
- CSRF token extraction from rendered forms
- Screenshot evidence of successful exploitation

Use `vigolium scan-url` for:
- API endpoints (JSON responses)
- Header injection, server-side vulns (SQLi, SSRF, SSTI)
- Anything that doesn't require JavaScript rendering

Evidence collection:
- Take screenshots after successful exploitation
- Save screenshots to session directory
- Reference screenshot paths in findings
```

### Notes

- For Feature 3 (multi-agent), each parallel exploit agent should get its own Playwright instance to prevent session contamination (Shannon uses `playwright-agent1` through `playwright-agent5`)
- Playwright MCP handles its own browser lifecycle — no Go-side browser management needed

---

## Feature 3: Multi-Agent Specialization with Hybrid Pipeline

**Priority: Medium-High — core architecture change, ship incrementally**

### What

Replace the single generalist autopilot agent with a phased pipeline of specialists. Each specialist focuses on one vulnerability class. Unlike Shannon (where agents do ALL scanning), our specialists focus on what LLMs are uniquely good at: **code analysis** and **exploitation verification**. The native scanner handles bulk detection.

### Why

Shannon's 13 specialized agents with 300-450 lines of domain expertise per vuln class find more than a single generalist. But Shannon pays for this with cost (all scanning is LLM inference). Our hybrid approach gets specialization benefits at lower cost.

### Pipeline Architecture

```
Phase 1: Recon Agent (single, sequential)
  Input:  --source code + --target URL
  Does:   Discovery scan + source code analysis (routes, tech stack, auth)
  Output: recon_deliverable.json (endpoint list, tech stack, auth flows)
  Tools:  Terminal (vigolium scan --only discovery), ReadTextFile
  ↓
Phase 2: Vulnerability Analysis Agents (parallel, per vuln class)
  Input:  Source code + recon deliverable
  Does:   Static code analysis to find class-specific sinks
  Output: vuln_queue.json + custom JS extensions per class
  Tools:  ReadTextFile only (no scanning, no network)

  Specialists:
    ├── injection-analyst  → SQL/cmd injection sinks → extensions
    ├── xss-analyst        → XSS sinks, DOM sources → extensions
    ├── auth-analyst       → Auth bypass patterns → extensions
    ├── ssrf-analyst       → SSRF sinks, URL handlers → extensions
    └── authz-analyst      → IDOR patterns, missing authz checks → extensions
  ↓
Phase 3: Native Scan (no LLM, Go modules)
  Input:  HTTP records from recon + extensions from Phase 2
  Does:   Run ALL native scanner modules + specialist extensions
  Output: Findings in database
  Tools:  None (pure Go execution via runner callback)
  ↓
Phase 4: Exploitation Verification Agents (parallel, conditional)
  Input:  Native scan findings + vuln queue + Playwright MCP
  Does:   Attempt real exploitation of flagged findings
  Output: exploitation_evidence.json per class
  Tools:  Terminal (vigolium scan-url), Playwright MCP, ReadTextFile

  Gate: Only runs if corresponding vuln queue OR native findings exist for this class

  Specialists:
    ├── injection-exploiter  → SQLi/RCE proof via curl/terminal
    ├── xss-exploiter        → DOM XSS proof via Playwright
    ├── auth-exploiter       → Auth bypass proof via Playwright (login flows)
    ├── ssrf-exploiter       → SSRF proof via curl/terminal
    └── authz-exploiter      → IDOR proof via multi-session Playwright
  ↓
Phase 5: Report Agent (single, sequential)
  Input:  All exploitation evidence + native findings
  Does:   Assemble final report, deduplicate, classify confidence
  Output: Structured findings (confirmed with PoC vs detection-only)
```

### How It Differs From Shannon

| Aspect | Shannon | Vigolium Autopilot V2 |
|--------|---------|----------------------|
| Phase 2 (Vuln Analysis) | Identifies vulns via code review | Identifies vulns via code review **AND generates JS extensions** |
| Phase 3 (Scanning) | Doesn't exist — agents send requests | **Native Go scanner** runs all modules + extensions |
| Phase 4 (Exploitation) | Agents do all testing from scratch | Agents **verify native scanner findings** + test vuln queue items |
| Cost per scan | ~$5-15 (all LLM inference) | ~$1-3 (LLM for analysis/verify, Go for bulk scanning) |

### Prompt Template Design

**Vuln Analysis Prompts (100-150 lines each, code analysis only)**:

```
autopilot-vuln-injection.md:
  Role: Injection sink analyst
  Input: {{.SourceCode}}, {{.ReconDeliverable}}
  Task:
    1. Trace data flow from HTTP inputs to dangerous sinks (SQL queries,
       exec calls, template engines, deserialization)
    2. For each sink: identify parameter, sanitization (or lack of),
       database type, query construction pattern
    3. Generate JS scanner extensions targeting each specific sink
       (error-based + time-based + boolean-based variants)
    4. Output vuln queue JSON with witness payloads
  Output Schema: vuln_queue (JSON)
  Tools: ReadTextFile only
  Key Guidance:
    - Do NOT send any HTTP requests
    - Focus on source-to-sink tracing
    - Generate extensions that reference exact parameter names from code
    - Include multiple detection strategies per sink
```

```
autopilot-vuln-xss.md:
  Role: XSS sink analyst
  Input: {{.SourceCode}}, {{.ReconDeliverable}}
  Task:
    1. Find reflection points: template rendering, innerHTML assignments,
       document.write, React dangerouslySetInnerHTML, Angular bypassSecurity
    2. Analyze output encoding at each reflection point
    3. Map context (HTML body, attribute, JS string, URL, CSS)
    4. Generate JS extensions with context-appropriate payloads
    5. Flag DOM sources (location.hash, postMessage, document.referrer)
       that need browser verification
  Output Schema: vuln_queue (JSON)
  Tools: ReadTextFile only
```

**Exploit Verification Prompts (150-200 lines each, active testing)**:

```
autopilot-exploit-injection.md:
  Role: Injection exploitation verifier
  Input: {{.NativeScanFindings}}, {{.VulnQueue}}, {{.ReconDeliverable}}
  Task:
    1. For each finding/queue item: attempt actual data extraction
    2. Try escalation: error-based → UNION → blind boolean → time-based
    3. For command injection: attempt command execution proof
    4. Document exact working payload, full request, response excerpt
    5. Classify: EXPLOITED / BLOCKED / FALSE_POSITIVE
  Output Schema: exploitation_evidence (JSON)
  Tools: Terminal (vigolium scan-url, vigolium scan-request), curl-like commands
  Key Guidance:
    - Start with witness payloads from vuln queue
    - Adapt based on error messages and WAF behavior
    - For SQLi: try to extract at least one row of data
    - For command injection: try `id` or `whoami` as proof
```

```
autopilot-exploit-xss.md:
  Role: XSS exploitation verifier
  Input: {{.NativeScanFindings}}, {{.VulnQueue}}, {{.ReconDeliverable}}
  Task:
    1. For reflected XSS findings: verify payload executes in browser
    2. For DOM XSS (from vuln queue): navigate to page, inject via
       URL fragment/parameter, verify execution
    3. For stored XSS: submit payload, navigate to reflection page, verify
    4. Take screenshot as evidence
    5. Classify: EXPLOITED / BLOCKED / FALSE_POSITIVE
  Output Schema: exploitation_evidence (JSON)
  Tools: Playwright MCP (required), Terminal (vigolium commands)
  Key Guidance:
    - DOM XSS REQUIRES browser — cannot verify via HTTP alone
    - Check CSP headers before attempting — note bypass if needed
    - Screenshot MUST show payload execution (alert, console, DOM change)
```

**Shared Prompt Fragments** (reusable via Go template `{{template "..."}}`):

```
_autopilot-scope.md:
  Only test endpoints reachable via {{.TargetURL}}
  Do not attempt attacks requiring internal network access

_autopilot-evidence-format.md:
  Evidence JSON schema:
  { finding_ref, status, payload, request, response, impact, screenshots, confidence }

_autopilot-tools.md:
  Available terminal commands: vigolium scan-url, scan-request, finding, traffic, module ls
  Available MCP tools: playwright (when configured)
```

### New Files

| File | Purpose |
|------|---------|
| `pkg/agent/autopilot_pipeline.go` | Pipeline orchestrator: runs phases sequentially, specialists in parallel via errgroup. Calls `engine.Run()` per specialist with different prompt templates. Uses `ACPPool` warm sessions. |
| `pkg/agent/exploitation_gate.go` | Reads vuln queue JSON + queries DB for native findings matching vuln class. Returns `ExploitationDecision{ShouldExploit bool, FindingCount int, QueueCount int}` |
| `pkg/agent/types.go` (additions) | `AutopilotPhase` enum, `VulnQueue` struct, `ExploitationEvidence` struct, `ReconDeliverable` struct |
| `pkg/agent/parser.go` (additions) | `ParseVulnQueue()`, `ParseExploitationEvidence()`, `ParseReconDeliverable()` |
| `pkg/cli/agent_autopilot.go` (additions) | `--parallel` flag to opt into multi-agent mode. `--specialists injection,xss,auth` to select which classes. Default: all 5. |
| `public/presets/prompts/autopilot/autopilot-recon.md` | Recon agent prompt |
| `public/presets/prompts/autopilot/autopilot-vuln-injection.md` | Injection sink analyst |
| `public/presets/prompts/autopilot/autopilot-vuln-xss.md` | XSS sink analyst |
| `public/presets/prompts/autopilot/autopilot-vuln-auth.md` | Auth bypass analyst |
| `public/presets/prompts/autopilot/autopilot-vuln-ssrf.md` | SSRF sink analyst |
| `public/presets/prompts/autopilot/autopilot-vuln-authz.md` | IDOR/authz analyst |
| `public/presets/prompts/autopilot/autopilot-exploit-injection.md` | Injection exploiter |
| `public/presets/prompts/autopilot/autopilot-exploit-xss.md` | XSS exploiter |
| `public/presets/prompts/autopilot/autopilot-exploit-auth.md` | Auth exploiter |
| `public/presets/prompts/autopilot/autopilot-exploit-ssrf.md` | SSRF exploiter |
| `public/presets/prompts/autopilot/autopilot-exploit-authz.md` | Authz exploiter |
| `public/presets/prompts/autopilot/autopilot-report.md` | Report assembler |
| `public/presets/prompts/autopilot/shared/` | Shared prompt fragments (scope, evidence format, tools) |

### Orchestrator Pseudocode

```go
func (r *AutopilotPipelineRunner) Run(ctx context.Context, opts AutopilotPipelineOpts) (*AutopilotResult, error) {
    sessionDir := EnsureSessionDir(opts.SessionsDir, opts.RunID)

    // Phase 1: Recon (sequential)
    reconResult, err := r.engine.Run(ctx, Options{
        PromptTemplate: "autopilot-recon",
        SourcePath:     opts.SourcePath,
        TargetURL:      opts.TargetURL,
        Autopilot:      true, // terminal enabled for discovery commands
    })
    saveCheckpoint(sessionDir, "recon", reconResult)
    reconDeliverable := ParseReconDeliverable(reconResult.Output)

    // Phase 2: Vuln Analysis (parallel, NO terminal — code analysis only)
    vulnSpecs := []string{"injection", "xss", "auth", "ssrf", "authz"}
    var vulnQueues map[string]*VulnQueue
    var allExtensions []string

    g, gctx := errgroup.WithContext(ctx)
    for _, spec := range opts.EnabledSpecialists {
        g.Go(func() error {
            result, err := r.engine.Run(gctx, Options{
                PromptTemplate: "autopilot-vuln-" + spec,
                SourcePath:     opts.SourcePath,
                TargetURL:      opts.TargetURL,
                Autopilot:      false, // NO terminal — read-only code analysis
                Extra:          map[string]string{"ReconDeliverable": reconDeliverable.Raw},
            })
            queue := ParseVulnQueue(result.Output)
            extensions := ExtractExtensions(result.Output)
            // merge into shared state (mutex-protected)
            return nil
        })
    }
    g.Wait()
    saveCheckpoint(sessionDir, "vuln-analysis", vulnQueues)

    // Phase 3: Native Scan (no LLM)
    // Write extensions to sessionDir/extensions/
    // Invoke scan callback with extension dir + HTTP records from recon
    scanResult := opts.ScanCallback(ctx, ScanRequest{
        ExtensionDir: sessionDir + "/extensions",
        Records:      reconDeliverable.Records,
    })
    saveCheckpoint(sessionDir, "native-scan", scanResult)

    // Phase 4: Exploitation Verification (parallel, conditional)
    g, gctx = errgroup.WithContext(ctx)
    for _, spec := range opts.EnabledSpecialists {
        decision := r.gate.Check(spec, vulnQueues[spec], scanResult.Findings)
        if !decision.ShouldExploit {
            continue
        }
        g.Go(func() error {
            result, err := r.engine.Run(gctx, Options{
                PromptTemplate: "autopilot-exploit-" + spec,
                TargetURL:      opts.TargetURL,
                Autopilot:      true, // terminal + Playwright enabled
                Extra: map[string]string{
                    "VulnQueue":         vulnQueues[spec].JSON(),
                    "NativeScanFindings": filterFindings(scanResult, spec).JSON(),
                    "ReconDeliverable":  reconDeliverable.Raw,
                },
            })
            evidence := ParseExploitationEvidence(result.Output)
            return nil
        })
    }
    g.Wait()
    saveCheckpoint(sessionDir, "exploitation", allEvidence)

    // Phase 5: Report (sequential)
    reportResult, _ := r.engine.Run(ctx, Options{
        PromptTemplate: "autopilot-report",
        Extra: map[string]string{
            "AllEvidence":    mergedEvidence.JSON(),
            "NativeFindings": scanResult.Findings.JSON(),
        },
    })

    return &AutopilotResult{...}, nil
}
```

### Incremental Shipping Strategy

1. **V1**: Ship recon + injection specialist only (1 vuln class end-to-end)
2. **V2**: Add XSS + auth specialists (the two that benefit most from Playwright)
3. **V3**: Add SSRF + authz specialists
4. **V4**: Optimize — warm session pooling, parallel MCP instances, cost tracking

### Backward Compatibility

- `vigolium agent autopilot` (no `--parallel` flag) → existing single-agent mode, unchanged
- `vigolium agent autopilot --parallel` → new multi-agent pipeline
- `vigolium agent autopilot --parallel --specialists injection,xss` → subset of specialists

---

## Feature 4: Structured Exploitation Evidence

**Priority: Medium — depends on Feature 3 for full value, data model can land independently**

### What

Add `exploitation_evidence` output schema so exploit agents produce structured, machine-readable PoC evidence instead of freeform text.

### Why

Shannon only reports vulnerabilities with working PoCs. Today Vigolium autopilot outputs unstructured text — findings can't be programmatically classified as "proven" vs "detected."

### Data Model

```go
// pkg/agent/types.go

type ExploitationEvidence struct {
    FindingRef   string   `json:"finding_ref"`    // links to finding UUID or vuln queue item
    Status       string   `json:"status"`         // "exploited" | "blocked" | "false_positive"
    VulnClass    string   `json:"vuln_class"`     // "injection" | "xss" | "auth" | "ssrf" | "authz"
    Payload      string   `json:"payload"`        // exact payload that worked
    Request      string   `json:"request"`        // full HTTP request (curl format or raw)
    Response     string   `json:"response"`       // relevant response excerpt
    Impact       string   `json:"impact"`         // what was achieved
    Screenshots  []string `json:"screenshots"`    // paths to screenshot files
    Confidence   string   `json:"confidence"`     // "proven" | "likely" | "unconfirmed"
    Notes        string   `json:"notes"`          // bypass techniques used, WAF evasion, etc.
}
```

### Changes

| File | Change |
|------|--------|
| `pkg/agent/types.go` | Add `ExploitationEvidence` struct |
| `pkg/agent/parser.go` | Add `ParseExploitationEvidence()` — parse JSON array from agent output |
| `pkg/agent/engine.go` ~L206 | Handle `exploitation_evidence` schema in output parsing switch |
| `pkg/database/` | Optional: `exploitation_evidence` table linked to findings via `finding_uuid` |
| `pkg/output/format_html.go` | Render PoC evidence in HTML reports (payload, request/response, screenshots) |

### Integration With Triage

The existing triage loop (`pkg/agent/triage.go`) confirms/rejects findings. Exploitation evidence becomes the confirmation mechanism:
- `status: "exploited"` → auto-confirm finding, attach evidence
- `status: "blocked"` → confirm as real vuln but note mitigation
- `status: "false_positive"` → reject finding

---

## Feature 5: 2FA/TOTP Support

**Priority: Low-Medium — quick win, independent of other features**

### What

Enable agents to generate TOTP codes during scanning for targets with 2FA.

### Why

Shannon has a `generate_totp` MCP tool. Many real applications require 2FA for testing.

### Approach: Native CLI Command (Option B — simpler than MCP)

The agent already has terminal access. Adding a `vigolium auth totp` subcommand is minimal work.

```bash
$ vigolium auth totp --secret JBSWY3DPEHPK3PXP
{"code": "123456", "expires_in": 18}
```

### Changes

| File | Change |
|------|--------|
| `pkg/cli/auth.go` | Add `totp` subcommand: `--secret` flag (base32), outputs JSON `{code, expires_in}` |
| Go dependency | Add `github.com/pquerna/otp` for RFC 6238 TOTP generation |
| `internal/config/` | Add `totp_secret` field to auth/session config |
| Prompt templates | Add TOTP workflow instructions to exploit prompts |

### Config Integration

```yaml
# vigolium-configs.yaml or session-config.json
authentication:
  login_url: "https://example.com/login"
  credentials:
    username: "testuser"
    password: "testpassword"
    totp_secret: "JBSWY3DPEHPK3PXP"
```

Prompt instruction: "When you encounter a 2FA/MFA prompt, generate a code using `vigolium auth totp --secret <secret_from_config>`"

---

## Feature 6: Session Checkpointing & Resume

**Priority: Low — polish, depends on Feature 3**

### What

Structured checkpoint/resume for the multi-agent pipeline so long-running scans survive timeouts and crashes.

### Why

Shannon uses Temporal for durable workflows + git checkpoints. Vigolium autopilot has no resume capability — 30-min timeout kills everything.

### Architecture

Reuses the existing pattern from swarm mode's `SwarmCheckpoint`.

```
Session directory (enhanced):
  ~/.vigolium/agent-sessions/agt-<uuid>/
    checkpoint.json              ← phase completion state
    recon/
      deliverable.json           ← recon output
    vuln-analysis/
      injection_queue.json       ← per-class vuln queues
      xss_queue.json
      ...
    extensions/                  ← JS extensions from vuln analysis
    exploitation/
      injection_evidence.json    ← per-class exploitation evidence
      xss_evidence.json
      ...
    output.md                    ← final report
```

### Checkpoint Schema

```go
type AutopilotCheckpoint struct {
    Phase           string            `json:"phase"`             // current phase
    CompletedPhases []string          `json:"completed_phases"`
    CompletedAgents []string          `json:"completed_agents"`  // e.g., ["vuln-injection", "vuln-xss"]
    StartedAt       time.Time         `json:"started_at"`
    ResumedAt       *time.Time        `json:"resumed_at,omitempty"`
    VulnQueues      map[string]string `json:"vuln_queues"`       // class → file path
    EvidenceFiles   map[string]string `json:"evidence_files"`    // class → file path
}
```

### Changes

| File | Change |
|------|--------|
| `pkg/agent/autopilot_pipeline.go` | Write checkpoint after each phase. Load checkpoint on resume. |
| `pkg/agent/types.go` | Add `AutopilotCheckpoint` struct |
| `pkg/cli/agent_autopilot.go` | Add `--resume <session-id>` flag. Loads checkpoint, skips completed phases. |

### Timeout Handling

When timeout approaches (e.g., 5 minutes remaining):
1. Save checkpoint with current phase state
2. Save partial results (any completed specialist outputs)
3. Log resume command: `vigolium agent autopilot --resume agt-<uuid> --parallel`
4. Exit gracefully instead of hard-killing

---

## Implementation Roadmap

```
Phase 1: Foundation (1-2 weeks)
├── Feature 1: MCP Server Support           ← 1-2 days
├── Feature 2: Playwright Browser            ← 2-3 days (mostly prompt work)
└── Feature 5: TOTP Support                  ← 0.5 day

Phase 2: Core Pipeline (2-3 weeks)
├── Feature 3: Multi-Agent Pipeline          ← 1-2 weeks
│   ├── V1: Recon + injection specialist     ← ship first
│   ├── V2: Add XSS + auth specialists      ← ship second
│   └── V3: Add SSRF + authz specialists    ← ship third
└── Feature 4: Exploitation Evidence         ← 3-5 days

Phase 3: Polish (1 week)
└── Feature 6: Checkpoint/Resume             ← 2-3 days
```

### Dependencies

```
Feature 1 (MCP Support)
  └── Feature 2 (Playwright)
        └── Feature 3 Phase 4 (Exploit agents need Playwright)

Feature 3 (Pipeline)
  ├── Feature 4 (Evidence schema used by exploit agents)
  └── Feature 6 (Checkpointing the pipeline phases)

Feature 5 (TOTP) — independent, can ship anytime
```

### Risk Mitigation

- **Cost explosion**: Each specialist is an LLM session. Monitor token usage. Consider `--budget` flag that caps total spend per scan.
- **Prompt quality**: Specialist prompts need iteration. Start with injection (most well-understood vuln class), validate on DVWA/JuiceShop canary tests, then expand.
- **Playwright reliability**: Browser automation is flaky. Exploit agents should gracefully degrade to HTTP-only if Playwright fails (log warning, skip DOM XSS checks).
- **Backward compatibility**: All new features behind `--parallel` flag. Existing single-agent autopilot unchanged.

---

## Comparison: Before & After

| Capability | Current Autopilot | Autopilot V2 |
|---|---|---|
| Agent count | 1 generalist | 1 recon + 5 vuln analysts + 5 exploiters + 1 reporter |
| Browser | None | Playwright MCP |
| Exploitation proof | No | Structured PoC evidence |
| 2FA | No | TOTP via `vigolium auth totp` |
| Scanning engine | Agent invokes native scanner | Vuln analysts generate extensions → native scanner → exploiters verify |
| Resume | No | Checkpoint/resume per phase |
| Specialization | None | Per-vuln-class domain expertise in prompts |
| Cost per scan | ~$0.50-1 (single agent) | ~$1-3 (multiple specialists, but native scan is free) |
| False positive rate | Scanner detection rate | Exploitation-verified (proven or rejected) |
