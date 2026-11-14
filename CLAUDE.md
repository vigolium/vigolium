# Vigolium

Go web vulnerability scanner with a CLI, REST API, traffic ingestion, and an in-process AI runtime. Module: `github.com/vigolium/vigolium`; Go version: see `go.mod` (currently 1.27+).

## Build and test

Always build with `make build` or `make install` to preserve version injection. Never build directly to `./vigolium` or an ad-hoc path.

```bash
make build              # bin/vigolium; also installs to $GOPATH/bin
make test-unit          # Fast tests (-short)
make test               # Full test suite
make test-race          # Race detector
make test-e2e           # Docker required
make test-canary        # Docker required
make lint               # golangci-lint
make fmt                # Format code
```

For a focused change: `go test -short -run TestName ./pkg/path/...`. Run relevant tests; use race tests for concurrency changes.

## Repository map

| Location | Responsibility |
| --- | --- |
| `cmd/vigolium/`, `pkg/cli/` | Entry point and Cobra commands |
| `internal/runner/`, `pkg/core/` | Native scan phases, executor, worker pool, rate limiting |
| `pkg/modules/` | Scanner modules - 218 active + 119 passive; shared helpers in `modkit/` and `infra/` |
| `pkg/deparos/`, `pkg/spitolas/`, `pkg/harvester/` | Discovery, browser crawling, archive URL collection |
| `pkg/http/`, `pkg/httpmsg/`, `pkg/input/` | HTTP transport, request/response models, input adapters |
| `pkg/database/`, `pkg/server/` | SQLite/PostgreSQL via Bun; Fiber REST API |
| `internal/config/`, `pkg/output/` | Configuration and result rendering |
| `pkg/agent/`, `pkg/olium/`, `pkg/audit/` | Agent orchestration, in-process runtime, audit harness |
| `pkg/jsext/`, `public/presets/` | Sobek JavaScript extensions and built-in presets |

Do not read or modify `platform/`. The only exception is `platform/vigolium-workbench/` for UI work.

## Important contracts

- **Native scanning:** ingestion → scope filtering → executor → modules → output/storage. Native scans are deterministic Go code. AI dispatch uses the in-process olium runtime.
- **Modules:** implement `ActiveModule` or `PassiveModule`, register in `default_registry_active.go` or `default_registry_passive.go`, and reuse `modkit`/`infra` helpers. Passive modules analyze existing traffic without sending requests.
- **Projects:** scan data is scoped by `project_uuid`. Config precedence is global → project → scanning profile → CLI. Preserve project isolation in queries and writes.
- **Database selection:** `--db` → `VIGOLIUM_DB` → `VIGOLIUM_DB_PATH` → config → default (`VIGOLIUM_DB` keeps project scoping; `VIGOLIUM_DB_PATH` turns it off for reads). Reuse shared DB openers and scoping helpers; a pinned env path must never silently fall back to another store.
- **Inputs:** `-T` accepts target lists (URLs or Burp scope); specs and request exports use `-i`. Target lists must populate `Options.Targets` before runner creation.
- **Shared definitions:** input formats belong in `pkg/input/source/file.go`; phase names/aliases in `internal/runner/native_plan.go`. Extend these tables instead of maintaining parallel lists.
- **Machine output:** keep human logs off stdout in JSON/event modes. Reuse the shared JSON envelope and event emitter; `-j` query output and `--format jsonl` exports have distinct contracts.
- **Large datasets:** stream exports and hydrate evidence on demand. Glob merges use temporary file databases; avoid loading whole raw-traffic corpora into memory.

## Further reading

- [Architecture](docs/architecture/overview.md) and [native scan phases](docs/guides/native-scan-phases.md)
- [Module development](docs/development/developing-modules.md)
- [JavaScript extensions](docs/customization/writing-extensions.md); API types: `pkg/jsext/vigolium.d.ts`
- [Projects](docs/projects.md) and [CLI machine-output contracts](docs/coding-agent.md)

Keep this file short: repository-wide rules and navigation only. Put feature details, bug histories, and implementation rationale in relevant docs, code comments, or tests.
