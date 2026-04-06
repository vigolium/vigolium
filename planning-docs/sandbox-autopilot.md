# Sandbox: Containerized Archon Audit

Run autopilot+archon agent scans inside a disposable Docker container to isolate filesystem mutations from the host. The coding agent (Claude Code) runs inside the container with full tool access — your local filesystem is untouched. Results are extracted and ingested into the local project DB after the scan completes.

## Config

Add two new top-level sections to `vigolium-configs.yaml`:

```yaml
environments:
  default:
    - ANTHROPIC_API_KEY
    - OPENAI_API_KEY
    - VIGOLIUM_LICENSE
  ci:
    - CI_TOKEN
    - ANTHROPIC_API_KEY

sandbox:
  image: vigolium:latest
  env: default    # references an environment by name
```

- `environments` — reusable named lists of host environment variable names. Values are resolved from the host shell at runtime via `os.Getenv`. No secrets stored in config.
- `sandbox.env` — references an environment by name.
- `sandbox.image` — Docker image to use.

## CLI

```bash
vigolium sandbox --target https://example.com --source ./myapp --archon-mode deep

  --keep           Skip auto-cleanup (for debugging)
```

No subcommands. It is always autopilot+archon. All other flags pass through to `vigolium agent autopilot` directly.

## Flow

```
1. Load sandbox config from vigolium-configs.yaml
2. Resolve sandbox.env → look up environments[name] → read values from host shell via os.Getenv
3. Copy vigolium-configs.yaml into container at /root/.vigolium/
4. docker run:
   - mount source at /workspace:ro
   - pass resolved env vars via -e
   - config injected so agent/archon settings match local (model, timeout, intensity, etc.)
   - run: vigolium agent autopilot --source /workspace --target ... [passthrough flags]
   - coding agent runs inside with full Read/Write/Bash/Edit/Glob/Grep tool access
5. Stream logs live to terminal (docker logs -f)
6. On exit:
   - docker cp session dir → ./sandbox-results/{runID}/
   - parse findings + HTTP records → ingest into local project DB
   - docker rm container
   - docker image prune (cleanup dangling layers)
7. Print summary: X findings, Y records ingested, session at ./sandbox-results/{runID}/
```

## Code Layout

```
internal/config/environments.go  — Environments map[string][]string, resolve from os.Getenv
internal/config/sandbox.go       — SandboxConfig struct {Image string, Env string}
pkg/cli/sandbox.go               — Cobra command, flag passthrough
pkg/sandbox/runner.go            — RunAndCollect(): docker run/logs/wait/cp/rm/prune lifecycle
pkg/sandbox/ingest.go            — Parse session dir artifacts → local DB (findings, HTTP records)
```

## Auto-Cleanup

- **Container**: always removed unless `--keep`
- **Dangling image layers**: pruned after container removal
- **Session artifacts on host**: kept at `./sandbox-results/{runID}/` — that is the output

## Design Decisions

1. **Source mounted read-only** — agent can freely mutate the container filesystem but cannot touch host code.
2. **Config copied into container** — agent inside uses the same scanning profiles, module tags, agent backend settings as local. Zero drift.
3. **`environments` is decoupled from sandbox** — any future feature that needs host env vars references an environment name. Sandbox is the first consumer.
4. **No `--env-file` flag** — config is the single source of truth for which env vars to forward.
5. **Passthrough flags** — sandbox does not duplicate autopilot flag definitions. Everything after the sandbox-specific flags is forwarded as-is.
6. **`vigolium ingest session <path>`** — the ingestion logic in `pkg/sandbox/ingest.go` can also be exposed as a standalone CLI subcommand for manual imports (run scan on VPS, scp session dir back, ingest locally).
