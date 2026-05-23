# Building & Testing

Vigolium is a Go project (module `github.com/vigolium/vigolium`, **Go 1.26+**).
All build and test workflows go through the `Makefile` — it injects version
metadata and manages embedded assets that a bare `go build` would skip.

> **Always build with `make`.** Never run `go build` to `./vigolium` or an
> ad-hoc path: it bypasses version injection (`-ldflags`) and can leave a stale
> binary in the working tree. Use `make build` (→ `bin/vigolium`) or
> `make install` (→ `$GOPATH/bin`).

## Prerequisites

| Tool | Why |
|------|-----|
| Go 1.26+ | Language toolchain (`go-version` is pinned in `go.mod`) |
| [Bun](https://bun.sh) | Compiles the JS analysis engine embedded via `//go:embed` (`make ensure-jsscan`) |
| Docker | Only for e2e/canary tests against vulnerable apps |
| `golangci-lint` v2 | Linting (`make lint`); installed automatically by some targets |

The **jsscan** binary is generated, not committed. A fresh checkout will not
compile until it exists, so run `make ensure-jsscan` once (or just `make build`,
which depends on it transitively). The **vigolium-audit** harness binary is
managed the same way via `make ensure-audit`.

## Build targets

```bash
make build              # → bin/vigolium (+ installs to $GOPATH/bin); injects version
make build-ingestor     # → bin/vigolium-ingestor (standalone traffic ingestor)
make build-all          # main + ingestor + linux/darwin/windows cross-builds
make install            # install vigolium to $GOPATH/bin
make ensure-jsscan      # build & embed the bun-compiled jsscan binaries
make ensure-audit       # fetch/build the embedded vigolium-audit harness
```

## Test tiers

```bash
make test               # all tests (auto-installs gotestsum)
make test-unit          # fast unit tests only (-short, no external deps)
make test-race          # all tests with the race detector
make test-e2e           # Docker-based e2e (-tags=e2e), in test/e2e/
make test-canary        # against DVWA / VAmPI / Juice Shop (Docker, -tags=canary)
make test-integration   # XSS benchmark tests (-tags=integration)
make test-coverage      # produce coverage.out
make coverage-gate      # enforce the COVERAGE_MIN floor against coverage.out
```

Run a single test:

```bash
go test -v -run TestName ./pkg/path/to/package/...
```

Run a single tagged test:

```bash
go test -v -tags=e2e -run TestName ./test/e2e/...
```

Vulnerable apps for e2e/canary are managed with Docker Compose under
`test/testdata/vulnerable-apps/`:

```bash
make apps-up            # start the vulnerable app stack
make apps-down          # tear it down
```

## Lint, format, tidy

```bash
make fmt                # gofmt the tree
make lint               # golangci-lint run (the CI gate)
make tidy               # go mod tidy
make verify-generated   # check gofmt + go.mod are clean (mirrors CI)
```

Linter config lives in `.golangci.yml` (golangci-lint v2). The enabled set is
deliberately conservative and kept green so `make lint` can gate CI:
`errcheck, govet, ineffassign, staticcheck, unused, misspell, errorlint`.
`gosec` and `bodyclose` are documented as deferred — see the comments in
`.golangci.yml` before enabling them.

## CI

`.github/workflows/ci.yml` runs lint, `go vet`, race-disabled unit tests with a
coverage floor (`coverage-gate`, `COVERAGE_MIN`), plus informational
`govulncheck`, SBOM (CycloneDX), and dependency-review jobs. The vendored
`pkg/spitolas/rod` package and everything under `platform/` are excluded from
vet/test (see `GOLIST_EXCLUDE` in the Makefile and the `grep -Ev` filter in CI).

## Common gotchas

- **"package jsscan: no embedded binary"** → run `make ensure-jsscan`.
- **Stale `./vigolium` in the repo root** → it's gitignored; delete it and use
  `make build` (→ `bin/vigolium`).
- **`platform/` is external tooling** — don't build or modify it (except the
  Next.js UI in `platform/vigolium-workbench/`).

See also: [project-structure.md](project-structure.md) and
[developing-modules.md](developing-modules.md).
