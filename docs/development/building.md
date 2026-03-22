# Building Vigolium

This document covers how to build Vigolium from source, required dependencies, platform-specific considerations, and available build targets.

## Prerequisites

### Required

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Go** | 1.26+ | Compiler and toolchain |
| **git** | any | Version extraction, dependency management |
| **make** | any | Build orchestration |

### Optional

| Dependency | Purpose |
|------------|---------|
| **Docker** | Running E2E and canary tests against vulnerable applications |
| **curl** | Downloading Chromium archives for embedded builds (`make deps-chrome`) |
| **Python 3** | Swagger spec validation (`make swagger`) |
| **golangci-lint** | Linting (`make lint`) |

### System Libraries

No system-level C libraries are required. The project compiles with `CGO_ENABLED=0` and uses pure Go implementations for all core functionality, including SQLite (via `sqliteshim` / `modernc.org/sqlite`).

## Quick Start

```bash
# Clone the repository
git clone https://github.com/vigolium/vigolium.git
cd vigolium

# Download Go modules and copy required binaries
make deps

# Build the main binary (output: bin/vigolium, also installs to $GOPATH/bin)
make build
```

## Build Targets

### Binaries

| Command | Output | Description |
|---------|--------|-------------|
| `make build` | `bin/vigolium` | Main CLI binary, installed to `$GOPATH/bin` |
| `make build-ingestor` | `bin/vigolium-ingestor` | Standalone ingestor client |
| `make build-embedded` | `bin/vigolium` | Build with Chromium embedded in the binary (requires `make deps-chrome` first) |
| `make build-all` | multiple | Cross-compile for Linux, macOS, and Windows (includes ingestor) |

### Platform-Specific Cross-Compilation

| Command | Target |
|---------|--------|
| `make build-linux` | Linux amd64 |
| `make build-darwin` | macOS amd64 + arm64 (universal) |
| `make build-windows` | Windows amd64 |

### Dependencies

| Command | Description |
|---------|-------------|
| `make deps` | Download Go modules, copy jsscan binaries, check Chromium archives |
| `make deps-chrome` | Download Chromium browser archives from upstream URLs |
| `make deps-chrome-update` | Update a browser version/URL in `versions.go` |

### Code Quality

| Command | Description |
|---------|-------------|
| `make fmt` | Format Go source files |
| `make lint` | Run `golangci-lint` |
| `make tidy` | Run `go mod tidy` |

### Housekeeping

| Command | Description |
|---------|-------------|
| `make clean` | Remove build artifacts |
| `make install` | Install binaries to `$GOPATH/bin` |

## Testing

### Test Tiers

| Command | Tag | Requirements | Description |
|---------|-----|--------------|-------------|
| `make test` | (none) | Go only | Run all tests (auto-installs `gotestsum`) |
| `make test-unit` | `-short` | Go only | Fast unit tests, no external dependencies |
| `make test-race` | (none) | Go only | All tests with the race detector enabled |
| `make test-e2e` | `e2e` | Docker | End-to-end tests against vulnerable apps |
| `make test-canary` | `canary` | Docker | Canary tests against DVWA, VAmPI, Juice Shop |
| `make test-integration` | `integration` | Go only | XSS benchmark / integration tests |
| `make test-benchmark-whitebox` | `canary` | Docker | Data-driven whitebox benchmarks (DVWA, VAmPI, Juice Shop) |
| `make test-benchmark-blackbox` | `blackbox` | Internet | Data-driven blackbox benchmarks (external demo sites) |
| `make test-benchmark-all` | both | Docker + Internet | All whitebox + blackbox benchmarks |
| `make test-benchmark-crapi` | `canary` | Docker + `make crapi-up` | crAPI benchmark tests |
| `make test-benchmark-coverage` | `canary` | None | Generate module coverage report |
| `make test-coverage` | (none) | Go only | Generate HTML coverage report |
| `make test-ci` | (none) | Go only | Tests with JUnit XML output for CI |

See [Benchmark Testing](benchmark-testing.md) for the full guide on the data-driven benchmark system.

### Running a Single Test

```bash
go test -v -run TestFunctionName ./pkg/path/to/package/...
```

With build tags:

```bash
go test -v -tags=e2e -run TestName ./test/e2e/...
```

### Vulnerable Applications (Docker)

E2E and canary tests run against containerized vulnerable apps managed via Docker Compose in `test/testdata/vulnerable-apps/`.

| Command | App | URL |
|---------|-----|-----|
| `make apps-up` | All apps | -- |
| `make apps-down` | All apps | -- |
| `make crapi-up` | OWASP crAPI | `http://127.0.0.1:8888` |
| `make juiceshop-up` | Juice Shop | `http://127.0.0.1:3000` |
| `make vampi-up` | VAmPI | `http://127.0.0.1:3005` |

## Build Tags

| Tag | Purpose |
|-----|---------|
| `embed_chromium` | Embed Chromium browser archives into the binary |
| `e2e` | Enable E2E tests |
| `canary` | Enable canary tests and whitebox benchmarks |
| `blackbox` | Enable blackbox benchmark tests (external sites) |
| `integration` | Enable integration/benchmark tests |

### Embedded vs Runtime Browser

By default, Vigolium downloads Chromium at runtime on first use (`~/.cache/spitolas/chromium-<version>/`). To ship a self-contained binary with Chromium baked in:

```bash
make deps-chrome       # download archives first
make build-embedded    # build with -tags=embed_chromium
```

Embedded Chromium is available for Linux (amd64, arm64) and macOS (arm64). Windows always downloads at runtime.

## Docker Build

A multi-stage Dockerfile is at `build/Dockerfile`:

```bash
make docker            # build Docker image
make docker-push       # push to registry (set DOCKER_REGISTRY env var)
```

The full image (`build/Dockerfile`) uses `debian:bookworm-slim` as the runtime base and includes Chromium, source-aware tools, and Python. A minimal variant (`build/Dockerfile.minimal`) uses `alpine:3.21`, runs as a non-root user (`vigolium`, UID 1000), and contains only the binary, CA certificates, and timezone data. See [Running with Docker](docker.md) for the full guide.

## Version Information

The build injects version metadata via ldflags:

| Variable | Source |
|----------|--------|
| `Version` | Extracted from `pkg/cli/version.go` |
| `Commit` | `git rev-parse --short HEAD` |
| `BuildTime` | UTC timestamp at build time |

These are visible via `vigolium version`.

## Platform Support

| OS | Architecture | Build | Embedded Chromium |
|----|-------------|-------|-------------------|
| Linux | amd64 | Supported | Ungoogled-Chromium |
| Linux | arm64 | Supported | Ungoogled-Chromium |
| macOS | amd64 | Supported | Chromium snapshot |
| macOS | arm64 | Supported | Chromium snapshot |
| Windows | amd64 | Supported | Auto-download only |
| Windows | arm64 | Not supported | -- |

## jsscan Dependency

The JavaScript analysis engine (`jsscan`) ships as a pre-built binary per platform, stored in `internal/resources/deparos/jsscan/`. These are pulled from the sibling [jsscan](https://github.com/osmedeus/jsscan) repository:

```bash
# Clone jsscan next to vigolium and build it, then:
make deps   # copies binaries from ../jsscan/bin/
```

Required binaries:
- `jsscan-darwin-amd64`
- `jsscan-darwin-arm64`
- `jsscan-linux-amd64`
- `jsscan-linux-arm64`
- `jsscan-windows-amd64.exe`

The `make deps` target handles copying automatically if the sibling project exists.

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/gofiber/fiber/v3` | REST API server |
| `github.com/uptrace/bun` | Database ORM (SQLite + PostgreSQL) |
| `github.com/go-rod/rod` | Browser automation (spidering) |
| `github.com/grafana/sobek` | JavaScript extension engine |
| `github.com/projectdiscovery/nuclei/v3` | SPA template scanning |
| `go.uber.org/zap` | Structured logging |
| `github.com/redis/go-redis/v9` | Optional Redis queue backend |

Full dependency list is in `go.mod`.
