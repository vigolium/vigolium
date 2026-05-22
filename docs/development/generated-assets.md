# Generated & machine-managed assets

This repo checks in a mix of hand-written code and machine-generated artifacts.
This page lists what is generated, how to regenerate it, and how it is verified.

## Diff-verifiable (checked by `make verify-generated`)

These are deterministic and must stay in sync with their source:

| Artifact | Source of truth | Regenerate with |
|---|---|---|
| `gofmt` formatting of all Go files | the Go source itself | `make fmt` |
| `go.mod` / `go.sum` | `import` statements | `make tidy` |

`make verify-generated` fails if either is out of sync, so it is safe to run in
CI as a gate. It restores `go.mod`/`go.sum` after the tidy check so it never
leaves a dirty tree.

## Build outputs (not diff-verifiable)

These are non-deterministic binary/bundle outputs. They are regenerated from
external toolchains (Bun, GoReleaser, the UI build) and are **not** verified by
`make verify-generated` because byte-for-byte reproduction is not guaranteed:

| Artifact | Path | Regenerate with |
|---|---|---|
| jsscan binaries (embedded per-platform) | `internal/resources/deparos/jsscan/`, `public/presets/deparos/jsscan/` | `make ensure-jsscan` / `make update-jsscan` |
| vigolium-audit harness binary | `pkg/audit/bin/_bin/` | `make update-audit` |
| Workbench UI bundle & report template | `public/ui/`, `public/static-reports/template.html` | `make update-ui` |
| Release metadata | `build/dist/metadata.json` | `make generate-metadata` |

`make deps` builds the jsscan binaries needed to compile the tree (they are
embedded via `//go:embed`), which is why CI runs it before any `go build`.

## Linting

Generated files are excluded from `golangci-lint` via the `exclusions.generated:
lax` setting in `.golangci.yml`, plus an explicit skip for the vendored
`pkg/spitolas/rod/` browser-automation package (which is also excluded from
`go vet`/tests in the Makefile and CI).
