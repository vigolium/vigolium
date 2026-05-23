.PHONY: build build-embedded build-all build-ingestor snapshot release public public-release prepare-public-scripts clean test test-unit test-integration test-e2e test-e2e-api test-e2e-agent test-e2e-postgres test-canary sanity-check smoke-autopilot-auth test-e2e-vampi test-e2e-dvwa test-e2e-juiceshop test-e2e-browser-fallback test-e2e-piolium test-benchmark test-benchmark-whitebox test-benchmark-blackbox test-benchmark-all test-benchmark-crapi test-benchmark-vuln-java test-benchmark-vuln-nginx test-benchmark-coverage test-agent-benchmark test-agent-parsing test-agent-quality test-agent-handoff test-agent-benchmark-e2e benchmark-agent-generate test-coverage coverage-gate coverage-combined test-coverage-check test-race test-ci test-xbow test-xbow-ssti test-xbow-xss test-xbow-sqli test-xbow-lfi test-xbow-cmdi test-xbow-ssrf test-xbow-xxe xbow-build lint verify-generated fmt tidy deps deps-chrome deps-chrome-update install install-gotestsum swagger help postgres-up postgres-down postgres-logs postgres-status crapi-up crapi-down crapi-logs crapi-status juiceshop-up juiceshop-down juiceshop-logs juiceshop-status vampi-up vampi-down vampi-logs vampi-status vulnerable-java-up vulnerable-java-down vulnerable-java-logs vulnerable-java-status vulnerable-nginx-up vulnerable-nginx-down vulnerable-nginx-logs vulnerable-nginx-status apps-up apps-down docker docker-build docker-build-prod docker-run docker-push docker-publish update-jsscan ensure-jsscan sync-audit update-audit ensure-audit build-audit update-ui ssh-testbed-keygen ssh-testbed-up ssh-testbed-down ssh-testbed-status ssh-testbed-logs generate-metadata prepare-release-scripts cdn-sync bump-version npm-build npm-pack npm-publish

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod
BINARY_NAME=vigolium
INGESTOR_NAME=vigolium-ingestor
BINARY_DIR=bin

# Package-selection filter shared by test/vet/race/fmt/govulncheck (here and in
# .github/workflows/ci.yml). Excludes vendored rod browser tests and everything
# under platform/ (external tooling). platform/ harbours node_modules trees that
# can contain stray buildable Go packages (e.g. flatted/golang) which would
# otherwise be discovered by `go list ./...`; /node_modules/ is listed too as
# defence in depth. Used inline as `$$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')`
# so `go list` stays lazy (it needs generated embeds present).
GOLIST_EXCLUDE=/pkg/spitolas/rod|/platform/|/node_modules/

# Minimum total statement coverage enforced by `coverage-gate` (used by
# test-ci and test-coverage-check). A regression tripwire held at/just below the
# current baseline; ratchet it upward as coverage improves.
# Override on the CLI: `make test-coverage-check COVERAGE_MIN=35`.
COVERAGE_MIN ?= 45

# Test selector for the no-Docker e2e leg of `coverage-combined`. These tiers
# (server/agent REST handlers + the hermetic scan-runner orchestration tests)
# run without Docker, so they're safe to fold into a CI-friendly report.
# Override to widen/narrow the e2e contribution.
COVERAGE_E2E_RUN ?= TestAPI_|TestAgentAPI_|TestScanRunnerHermetic

# Console output prefix (cyan color)
PREFIX=\033[36m[*]\033[0m

# Gotestsum configuration - check GOPATH/bin first, then use go test fallback
GOPATH_BIN=$(shell go env GOPATH)/bin
GOTESTSUM_PATH=$(shell command -v gotestsum 2>/dev/null || echo $(GOPATH_BIN)/gotestsum)
GOTESTSUM_EXISTS=$(shell test -x $(GOTESTSUM_PATH) && echo yes || echo no)

ifeq ($(GOTESTSUM_EXISTS),yes)
    TESTCMD=@$(GOTESTSUM_PATH)
    TESTFLAGS=--format testdox --format-hide-empty-pkg --hide-summary=skipped,output --
else
    TESTCMD=$(GOTEST)
    TESTFLAGS=-v
endif

# Build flags
VERSION=$(shell grep -E '^[[:space:]]*Version[[:space:]]+=' pkg/cli/version.go | cut -d '"' -f 2)
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
CLI_PKG=github.com/vigolium/vigolium/pkg/cli
LDFLAGS_INNER=-s -w -X $(CLI_PKG).Version=$(VERSION) -X $(CLI_PKG).Commit=$(COMMIT_HASH) -X $(CLI_PKG).BuildTime=$(BUILD_TIME)
LDFLAGS=-ldflags "$(LDFLAGS_INNER)"
INGESTOR_LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME)"

# R2 CDN prefix for `make release` — nightly release uploads. Served at
# cdn.vigolium.com/vigolium-nightly-release/ via build/scripts/nightly-install.sh.
R2_PREFIX=vigolium-nightly-release
INSTALL_BASE_URL=https://cdn.vigolium.com/$(R2_PREFIX)

# R2 CDN prefix for `make public-release` — public/stable release uploads. Served
# at cdn.vigolium.com/vigolium-release/ via build/scripts/install.sh.
R2_PUBLIC_PREFIX=vigolium-release
PUBLIC_INSTALL_BASE_URL=https://cdn.vigolium.com/$(R2_PUBLIC_PREFIX)
PUBLIC_DIST_DIR=build/dist-public
PUBLIC_TARGETS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
# Version without leading 'v' — matches the install.sh tarball-name convention.
PUBLIC_VERSION=$(patsubst v%,%,$(VERSION))

# Default target
all: build

# Build main binary and install to GOBIN
build: ensure-audit
	@if [ -z "$$(ls $(JSSCAN_RES_DST_DIR)/ 2>/dev/null)" ]; then \
		echo "$(PREFIX) First build on this machine — jsscan binaries not found, running 'make deps' to prepare dependencies..."; \
		$(MAKE) deps; \
	fi
	@echo "$(PREFIX) Building $(BINARY_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/vigolium
	@echo "$(PREFIX) Installing $(BINARY_NAME) to $(GOPATH_BIN)..."
	@mkdir -p $(GOPATH_BIN)
	@rm -f $(GOPATH_BIN)/$(BINARY_NAME)
	@cp $(BINARY_DIR)/$(BINARY_NAME) $(GOPATH_BIN)/$(BINARY_NAME)
	@echo "$(PREFIX) Build complete! Binary: $(BINARY_DIR)/$(BINARY_NAME) and $(GOPATH_BIN)/$(BINARY_NAME)"

# Build with embedded Chromium (requires 'make deps-chrome' first)
build-embedded: ensure-audit
	@echo "$(PREFIX) Building $(BINARY_NAME) with embedded Chromium..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -tags=embed_chromium -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/vigolium
	@echo "$(PREFIX) Installing $(BINARY_NAME) to $(GOPATH_BIN)..."
	@mkdir -p $(GOPATH_BIN)
	@rm -f $(GOPATH_BIN)/$(BINARY_NAME)
	@cp $(BINARY_DIR)/$(BINARY_NAME) $(GOPATH_BIN)/$(BINARY_NAME)
	@echo "$(PREFIX) Build complete! Binary: $(BINARY_DIR)/$(BINARY_NAME) and $(GOPATH_BIN)/$(BINARY_NAME)"

# Build for multiple platforms (includes ingestor)
build-all: build build-ingestor build-linux build-darwin build-windows

# Build ingestor binary
build-ingestor:
	@echo "$(PREFIX) Building $(INGESTOR_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(INGESTOR_LDFLAGS) -o $(BINARY_DIR)/$(INGESTOR_NAME) ./cmd/vigolium-ingestor
	@echo "$(PREFIX) Installing $(INGESTOR_NAME) to $(GOPATH_BIN)..."
	@mkdir -p $(GOPATH_BIN)
	@rm -f $(GOPATH_BIN)/$(INGESTOR_NAME)
	@cp $(BINARY_DIR)/$(INGESTOR_NAME) $(GOPATH_BIN)/$(INGESTOR_NAME)

build-linux:
	@echo "$(PREFIX) Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/vigolium
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(INGESTOR_LDFLAGS) -o $(BINARY_DIR)/$(INGESTOR_NAME)-linux-amd64 ./cmd/vigolium-ingestor

build-darwin:
	@echo "$(PREFIX) Building for macOS..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/vigolium
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/vigolium
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(INGESTOR_LDFLAGS) -o $(BINARY_DIR)/$(INGESTOR_NAME)-darwin-amd64 ./cmd/vigolium-ingestor
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(INGESTOR_LDFLAGS) -o $(BINARY_DIR)/$(INGESTOR_NAME)-darwin-arm64 ./cmd/vigolium-ingestor

build-windows:
	@echo "$(PREFIX) Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/vigolium
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(INGESTOR_LDFLAGS) -o $(BINARY_DIR)/$(INGESTOR_NAME)-windows-amd64.exe ./cmd/vigolium-ingestor

# Install gotestsum (idempotent - silent if already installed)
install-gotestsum:
	@if [ ! -x "$(GOPATH_BIN)/gotestsum" ]; then \
		echo "$(PREFIX) Installing gotestsum..."; \
		go install gotest.tools/gotestsum@latest; \
	fi

# Run all tests (install gotestsum first; see GOLIST_EXCLUDE for what's filtered)
test: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running all tests..."
	$(TESTCMD) $(TESTFLAGS) $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run tests with race detector (see GOLIST_EXCLUDE for what's filtered)
test-race: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running tests with race detector..."
	$(TESTCMD) $(TESTFLAGS) -race $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run unit tests (excludes integration, e2e; see GOLIST_EXCLUDE for what's filtered)
test-unit: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running unit tests..."
	$(TESTCMD) $(TESTFLAGS) -short $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run integration tests (Brutelogic XSS gym benchmark)
test-integration: install-gotestsum
	@echo "$(PREFIX) Running integration tests (requires internet)..."
	$(TESTCMD) $(TESTFLAGS) -tags=integration ./test/benchmark/...

# Run benchmark tests (alias for test-integration)
test-benchmark: test-integration

# Run E2E tests (requires Docker)
test-e2e: install-gotestsum
	@echo "$(PREFIX) Running E2E tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 60m ./test/e2e/...

# Run API E2E tests only (server endpoint tests, no Docker needed)
test-e2e-api: install-gotestsum
	@echo "$(PREFIX) Running API E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestAPI_ ./test/e2e/...

# Run Agent API E2E tests only (agent endpoint tests, no Docker needed)
test-e2e-agent: install-gotestsum
	@echo "$(PREFIX) Running Agent API E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestAgentAPI_ ./test/e2e/...

# Run PostgreSQL E2E tests (requires 'make postgres-up' first)
test-e2e-postgres: install-gotestsum
	@echo "$(PREFIX) Running PostgreSQL E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestPg_ ./test/e2e/...

# Run canary tests - DVWA, VAmPI, Juice Shop (requires Docker, slower)
test-canary: install-gotestsum
	@echo "$(PREFIX) Running canary tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary ./test/e2e/...

# Run canary tests against PostgreSQL (requires 'make postgres-up' first).
# Per-test: drops+recreates the shared PG schema for isolation.
test-canary-postgres: export VIGOLIUM_TEST_DB_DRIVER=postgres
test-canary-postgres: install-gotestsum
	@echo "$(PREFIX) Running canary tests against PostgreSQL..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary ./test/e2e/...

# One-shot pre-deploy validation: spin up PG, run PG e2e + canary against it,
# then tear down (even on test failure). Run locally before prod deploys.
test-pg-full: install-gotestsum
	@echo "$(PREFIX) Full PostgreSQL validation cycle (e2e + canary)..."
	@$(MAKE) postgres-up
	@bash -c 'trap "$(MAKE) postgres-down" EXIT; \
		set -e; \
		$(MAKE) test-e2e-postgres; \
		$(MAKE) test-canary-postgres'

# Sanity-check: real-target end-to-end smoke test of the REST API + storage
# upload flow documented in docs/api-references/scan-with-storage.md.
# Boots a local server with the cloudrun GCS credentials, runs native +
# audit + autopilot scans against ginandjuice.shop / VAmPI / juice-shop with
# upload_results=true, and verifies bundles land at the documented keys.
#
# Required: jq, tar, gzip, uuidgen, python3 on PATH; network access to the
# real targets and the shared GCS bucket. Agent phases skip cleanly if no LLM
# provider (~/.codex/auth.json, $ANTHROPIC_API_KEY, or $OPENAI_API_KEY) is set.
sanity-check: build
	@echo "$(PREFIX) Running sanity-check (real-target API + storage smoke test)..."
	@bash test/smoke-test-scripts/sanity-check.sh

# Smoke test: agentic-scan auth preflight against local Juice Shop.
# Verifies `vigolium agent autopilot --credentials --auth-required` end-to-end:
# boots juice-shop, clones the source, runs autopilot with a pinned --scan-uuid,
# and asserts the prepared session config + hydrated headers landed on disk and
# in the AgenticScan row.
#
# Required: ~/.codex/auth.json (codex-oauth provider); docker + git + jq + curl
# on PATH. Leaves juice-shop running for fast re-runs (tear down with
# `make juiceshop-down`).
smoke-autopilot-auth: build
	@echo "$(PREFIX) Running smoke-autopilot-auth (juice-shop autopilot + --credentials)..."
	@bash test/smoke-test-scripts/smoke-autopilot-juiceshop-auth.sh

# Run E2E VAmPI tests only (SQLi testing)
test-e2e-vampi: install-gotestsum
	@echo "$(PREFIX) Running VAmPI E2E tests (SQLi)..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestVAmPI ./test/e2e/

# Run E2E DVWA tests only (XSS, SQLi, LFI)
test-e2e-dvwa: install-gotestsum
	@echo "$(PREFIX) Running DVWA E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestDVWA ./test/e2e/

# Run E2E Juice Shop tests only
test-e2e-juiceshop: install-gotestsum
	@echo "$(PREFIX) Running Juice Shop E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestJuiceShop ./test/e2e/

# Run browser fallback E2E tests (Docker multi-arch, verifies system chromium fallback)
test-e2e-browser-fallback: install-gotestsum
	@echo "$(PREFIX) Running browser fallback E2E tests (Docker multi-arch)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 20m -run TestBrowserFallback ./test/e2e/

# Run piolium audit E2E tests (requires `pi` + piolium installed; see docs/agentic-scan/piolium-audit.md).
# Override provider/model via VIGOLIUM_E2E_PI_PROVIDER / VIGOLIUM_E2E_PI_MODEL.
test-e2e-piolium: install-gotestsum
	@echo "$(PREFIX) Running piolium audit E2E tests (requires pi + piolium)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 10m -run TestE2EPioliumAudit ./test/e2e/

# Run whitebox benchmark tests (Docker-based, data-driven from YAML definitions)
test-benchmark-whitebox: install-gotestsum
	@echo "$(PREFIX) Running whitebox benchmark tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary ./test/benchmark/whitebox/...

# Run blackbox benchmark tests (external sites, soft assertions)
test-benchmark-blackbox: install-gotestsum
	@echo "$(PREFIX) Running blackbox benchmark tests (requires internet)..."
	$(TESTCMD) $(TESTFLAGS) -tags=blackbox ./test/benchmark/blackbox/...

# Run all benchmark tests (whitebox + blackbox)
test-benchmark-all: test-benchmark-whitebox test-benchmark-blackbox

# Run crAPI benchmark tests only (requires 'make crapi-up' first)
test-benchmark-crapi: install-gotestsum
	@echo "$(PREFIX) Running crAPI benchmark tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestWhitebox_CrAPI ./test/benchmark/whitebox/...

# Run vulnerable-java benchmark tests only (requires 'make vulnerable-java-up' first)
test-benchmark-vuln-java: install-gotestsum
	@echo "$(PREFIX) Running vulnerable-java benchmark tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestWhitebox_VulnerableJava ./test/benchmark/whitebox/...

# Run vulnerable-nginx benchmark tests only (requires 'make vulnerable-nginx-up' first)
test-benchmark-vuln-nginx: install-gotestsum
	@echo "$(PREFIX) Running vulnerable-nginx benchmark tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestWhitebox_VulnerableNginx ./test/benchmark/whitebox/...

# Generate module benchmark coverage report
test-benchmark-coverage: install-gotestsum
	@echo "$(PREFIX) Generating benchmark coverage report..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -run TestBenchmark_CoverageReport ./test/benchmark/coverage/...

# XBOW validation benchmarks (requires XBOW_SOURCE_DIR, Docker)
XBOW_SOURCE_DIR ?= /Users/j3ssie/Desktop/research/validation-benchmarks

# Run all xbow benchmarks
test-xbow: install-gotestsum
	@echo "$(PREFIX) Running xbow validation benchmarks (requires Docker + XBOW_SOURCE_DIR)..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 30m ./test/benchmark/xbow/...

# Run xbow SSTI benchmarks
test-xbow-ssti: install-gotestsum
	@echo "$(PREFIX) Running xbow SSTI benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_SSTI ./test/benchmark/xbow/...

# Run xbow XSS benchmarks
test-xbow-xss: install-gotestsum
	@echo "$(PREFIX) Running xbow XSS benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_XSS ./test/benchmark/xbow/...

# Run xbow SQLi benchmarks
test-xbow-sqli: install-gotestsum
	@echo "$(PREFIX) Running xbow SQLi benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_SQLi ./test/benchmark/xbow/...

# Run xbow LFI benchmarks
test-xbow-lfi: install-gotestsum
	@echo "$(PREFIX) Running xbow LFI benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_LFI ./test/benchmark/xbow/...

# Run xbow Command Injection benchmarks
test-xbow-cmdi: install-gotestsum
	@echo "$(PREFIX) Running xbow CmdI benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_CmdI ./test/benchmark/xbow/...

# Run xbow SSRF benchmarks
test-xbow-ssrf: install-gotestsum
	@echo "$(PREFIX) Running xbow SSRF benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_SSRF ./test/benchmark/xbow/...

# Run xbow XXE benchmarks
test-xbow-xxe: install-gotestsum
	@echo "$(PREFIX) Running xbow XXE benchmarks..."
	XBOW_SOURCE_DIR=$(XBOW_SOURCE_DIR) $(TESTCMD) $(TESTFLAGS) -tags=xbow -timeout 15m -run TestXbow_XXE ./test/benchmark/xbow/...

# Agent benchmark tests (Layers 1-3: parsing, quality, handoff — no Docker, no LLM)
test-agent-benchmark: install-gotestsum
	@echo "$(PREFIX) Running agent benchmark tests (Layers 1-3)..."
	$(TESTCMD) $(TESTFLAGS) -tags=agent_benchmark -timeout 10m ./test/benchmark/agent/...

# Agent parsing tests only (Layer 1: ParseFindings/ParseHTTPRecords against cached output)
test-agent-parsing: install-gotestsum
	@echo "$(PREFIX) Running agent parsing benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=agent_benchmark -timeout 5m -run TestParsing ./test/benchmark/agent/...

# Agent quality tests only (Layer 2: finding CWEs, vuln types, severity distribution)
test-agent-quality: install-gotestsum
	@echo "$(PREFIX) Running agent quality benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=agent_benchmark -timeout 5m -run TestQuality ./test/benchmark/agent/...

# Agent handoff tests only (Layer 3: HTTP record conversion via ToHTTPRequestResponse)
test-agent-handoff: install-gotestsum
	@echo "$(PREFIX) Running agent handoff benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=agent_benchmark -timeout 5m -run TestHandoff ./test/benchmark/agent/...

# Agent E2E benchmark tests (Layer 4: cached records scanned against Docker apps)
test-agent-benchmark-e2e: install-gotestsum
	@echo "$(PREFIX) Running agent E2E benchmarks (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags="agent_benchmark canary" -timeout 20m ./test/benchmark/agent/...

# Generate agent benchmark fixtures (real LLM calls — expensive, run once)
benchmark-agent-generate: install-gotestsum
	@echo "$(PREFIX) Generating agent benchmark fixtures (requires configured agent)..."
	$(TESTCMD) $(TESTFLAGS) -tags=agent_generate -timeout 30m ./test/benchmark/agent/...

# Pre-build all xbow containers (optional, saves time on first run)
xbow-build:
	@echo "$(PREFIX) Pre-building xbow benchmark containers..."
	@for dir in $(XBOW_SOURCE_DIR)/benchmarks/XBEN-*/; do \
		echo "  Building $$dir..."; \
		docker compose -f "$$dir/docker-compose.yml" build --build-arg FLAG=test 2>/dev/null || true; \
	done
	@echo "$(PREFIX) XBOW containers pre-built"

# Run tests with coverage
test-coverage: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running tests with coverage..."
	$(TESTCMD) $(TESTFLAGS) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(PREFIX) Coverage report saved to coverage.html"

# Test with JUnit XML output (for CI). Emits a coverage profile and enforces
# the COVERAGE_MIN floor after the run so a coverage regression fails the build.
test-ci: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running tests for CI..."
	@$(GOPATH_BIN)/gotestsum --junitfile test-results.xml --format testdox --format-hide-empty-pkg --hide-summary=skipped,output -- -v -race -coverprofile=coverage.out ./...
	@$(MAKE) --no-print-directory coverage-gate

# coverage-gate fails when total statement coverage in coverage.out is below
# COVERAGE_MIN. Factored out so test-ci, test-coverage-check, and the GitHub
# workflow can all enforce the same floor against an existing profile.
coverage-gate:
	@test -f coverage.out || { echo "$(PREFIX) coverage.out not found — run a coverage-producing target first"; exit 1; }
	@total=$$($(GOCMD) tool cover -func=coverage.out | awk 'END{gsub(/%/,"",$$NF); print $$NF}'); \
	awk -v t="$$total" -v min="$(COVERAGE_MIN)" 'BEGIN{ \
		if (t+0 < min+0) { printf "\033[31m[!]\033[0m total coverage %.1f%% is below floor %s%%\n", t, min; exit 1 } \
		printf "$(PREFIX) total coverage %.1f%% (floor %s%%)\n", t, min }'

# Standalone coverage floor check over the unit-test scope. Runs the -short
# suite once with coverage and enforces COVERAGE_MIN via coverage-gate.
test-coverage-check: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Checking coverage floor ($(COVERAGE_MIN)%)..."
	@$(GOCMD) test -short -coverprofile=coverage.out $$($(GOCMD) list ./... | grep -Ev '$(GOLIST_EXCLUDE)') > /dev/null
	@$(MAKE) --no-print-directory coverage-gate

# coverage-combined produces a REPORT-ONLY combined coverage number — it is NOT
# enforced (the COVERAGE_MIN tripwire stays on the fast -short unit profile via
# `coverage-gate`). It folds the unit slice together with the no-Docker e2e tier
# so the headline reflects code exercised end-to-end (REST handlers, the
# scan-runner orchestration in internal/runner) that per-package unit coverage
# can't credit. No Docker required.
#
# The unit leg uses normal per-package coverage (the same fast profile the gate
# uses). ONLY the e2e leg uses -coverpkg, so it records a 0/1 block for EVERY
# in-scope package — that profile defines the full statement universe. covmerge
# folds the two by max-per-block (a logical OR for `set` mode), so a statement
# covered by either leg counts. The two printed numbers use DIFFERENT
# denominators: per-package unit is over packages-with-tests; whole-tree combined
# is over every package (the e2e leg's untested-package blocks are in the base).
# `set -e` makes any failing leg or merge abort the target (no silent stale report).
coverage-combined: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Combined coverage (unit + no-Docker e2e; report only, not gated)..."
	@set -e; \
	pkgs=$$($(GOCMD) list ./... | grep -Ev '$(GOLIST_EXCLUDE)'); \
	cpkg=$$(echo "$$pkgs" | paste -sd, -); \
	echo "$(PREFIX)   unit leg (per-package -short)..."; \
	$(GOCMD) test -short -coverprofile=coverage-unit.out $$pkgs > /dev/null; \
	echo "$(PREFIX)   no-Docker e2e leg (-coverpkg across the tree)..."; \
	errlog=$$(mktemp); \
	if ! $(GOCMD) test -tags=e2e -coverpkg="$$cpkg" -coverprofile=coverage-e2e.out -run '$(COVERAGE_E2E_RUN)' ./test/e2e/ >/dev/null 2>"$$errlog"; then \
		grep -v 'no packages being tested depend on matches for pattern' "$$errlog" >&2 || true; \
		rm -f "$$errlog"; \
		echo "$(PREFIX) e2e coverage leg FAILED (see above)" >&2; exit 1; \
	fi; \
	rm -f "$$errlog"; \
	$(GOCMD) run ./test/tools/covmerge -o coverage-combined.out coverage-unit.out coverage-e2e.out; \
	$(GOCMD) tool cover -html=coverage-combined.out -o coverage-combined.html; \
	unit=$$($(GOCMD) tool cover -func=coverage-unit.out | awk 'END{gsub(/%/,"",$$NF); print $$NF}'); \
	total=$$($(GOCMD) tool cover -func=coverage-combined.out | awk 'END{gsub(/%/,"",$$NF); print $$NF}'); \
	printf "$(PREFIX) coverage: %s%% per-package unit  |  %s%% whole-tree unit+e2e (report only, not gated)\n" "$$unit" "$$total"; \
	echo "$(PREFIX) HTML report → coverage-combined.html"

# --- SSH Testbed ---
SSH_TESTBED_DIR=test/ssh-testbed

# Generate dummy SSH keypair for testbed
ssh-testbed-keygen:
	@mkdir -p $(SSH_TESTBED_DIR)/keys
	@if [ -f $(SSH_TESTBED_DIR)/keys/testbed_key ]; then \
		echo "$(PREFIX) SSH keypair already exists at $(SSH_TESTBED_DIR)/keys/testbed_key"; \
	else \
		ssh-keygen -t ed25519 -f $(SSH_TESTBED_DIR)/keys/testbed_key -N "" -C "testbed"; \
		cp $(SSH_TESTBED_DIR)/keys/testbed_key.pub $(SSH_TESTBED_DIR)/keys/authorized_keys; \
		echo "$(PREFIX) SSH keypair generated at $(SSH_TESTBED_DIR)/keys/"; \
	fi

# Start SSH testbed containers (generates keys if missing)
ssh-testbed-up: ssh-testbed-keygen
	@echo "$(PREFIX) Starting SSH testbed containers..."
	docker compose -f $(SSH_TESTBED_DIR)/docker-compose.yml up -d --build
	@echo "$(PREFIX) SSH testbed ready:"
	@echo "  Ubuntu 24.04: ssh -i $(SSH_TESTBED_DIR)/keys/testbed_key -p 2222 deploy@localhost"
	@echo "  Debian 12:    ssh -i $(SSH_TESTBED_DIR)/keys/testbed_key -p 2223 deploy@localhost"

# Stop SSH testbed containers
ssh-testbed-down:
	@echo "$(PREFIX) Stopping SSH testbed containers..."
	docker compose -f $(SSH_TESTBED_DIR)/docker-compose.yml down -v

# Show SSH testbed status
ssh-testbed-status:
	docker compose -f $(SSH_TESTBED_DIR)/docker-compose.yml ps

# Follow SSH testbed logs
ssh-testbed-logs:
	docker compose -f $(SSH_TESTBED_DIR)/docker-compose.yml logs -f

# Vulnerable app directories
VULN_APPS_DIR=test/testdata/vulnerable-apps
POSTGRES_DIR=test/testdata/postgres
CRAPI_DIR=$(VULN_APPS_DIR)/crapi
JUICESHOP_DIR=$(VULN_APPS_DIR)/juice-shop
VAMPI_DIR=$(VULN_APPS_DIR)/vampi
VULN_JAVA_DIR=$(VULN_APPS_DIR)/vulnerable-java
VULN_NGINX_DIR=$(VULN_APPS_DIR)/vulnerable-nginx

# Start all vulnerable apps
apps-up: juiceshop-up vampi-up crapi-up vulnerable-java-up vulnerable-nginx-up
	@echo "$(PREFIX) All vulnerable apps started"

# Stop all vulnerable apps
apps-down: juiceshop-down vampi-down crapi-down vulnerable-java-down vulnerable-nginx-down
	@echo "$(PREFIX) All vulnerable apps stopped"

# --- PostgreSQL (for E2E tests) ---

postgres-up:
	@echo "$(PREFIX) Starting PostgreSQL for E2E tests..."
	docker compose -f $(POSTGRES_DIR)/docker-compose.yaml up -d --wait
	@echo "$(PREFIX) PostgreSQL ready on localhost:5433 (user: vigolium_test)"
	@echo ""
	@echo "$(PREFIX) DSN: postgres://vigolium_test:vigolium_test_pass@localhost:5433/vigolium_test?sslmode=disable"
	@echo "$(PREFIX) Point vigolium at it with:"
	@echo "    vigolium config set database.driver postgres"
	@echo "    vigolium config set database.postgres.host localhost"
	@echo "    vigolium config set database.postgres.port 5433"
	@echo "    vigolium config set database.postgres.user vigolium_test"
	@echo "    vigolium config set database.postgres.password vigolium_test_pass"
	@echo "    vigolium config set database.postgres.database vigolium_test"
	@echo "    vigolium config set database.postgres.sslmode disable"

postgres-down:
	@echo "$(PREFIX) Stopping PostgreSQL..."
	docker compose -f $(POSTGRES_DIR)/docker-compose.yaml down -v

postgres-logs:
	docker compose -f $(POSTGRES_DIR)/docker-compose.yaml logs -f

postgres-status:
	docker compose -f $(POSTGRES_DIR)/docker-compose.yaml ps

# --- OWASP crAPI ---

crapi-up:
	@echo "$(PREFIX) Starting OWASP crAPI..."
	docker compose -f $(CRAPI_DIR)/docker-compose.yaml up -d
	@echo "$(PREFIX) crAPI is starting up. Web UI: http://127.0.0.1:8888  Mail: http://127.0.0.1:8025"
	@echo "$(PREFIX) Run 'make crapi-status' to check health"

crapi-down:
	@echo "$(PREFIX) Stopping OWASP crAPI..."
	docker compose -f $(CRAPI_DIR)/docker-compose.yaml down -v

crapi-logs:
	docker compose -f $(CRAPI_DIR)/docker-compose.yaml logs -f

crapi-status:
	docker compose -f $(CRAPI_DIR)/docker-compose.yaml ps

# --- OWASP Juice Shop ---

juiceshop-up:
	@echo "$(PREFIX) Starting OWASP Juice Shop..."
	docker compose -f $(JUICESHOP_DIR)/docker-compose.yaml up -d
	@echo "$(PREFIX) Juice Shop: http://127.0.0.1:3000"

juiceshop-down:
	@echo "$(PREFIX) Stopping OWASP Juice Shop..."
	docker compose -f $(JUICESHOP_DIR)/docker-compose.yaml down -v

juiceshop-logs:
	docker compose -f $(JUICESHOP_DIR)/docker-compose.yaml logs -f

juiceshop-status:
	docker compose -f $(JUICESHOP_DIR)/docker-compose.yaml ps

# --- VAmPI ---

vampi-up:
	@echo "$(PREFIX) Starting VAmPI..."
	docker compose -f $(VAMPI_DIR)/docker-compose.yaml up -d
	@echo "$(PREFIX) VAmPI secure: http://127.0.0.1:3005  VAmPI vulnerable: http://127.0.0.1:3006"

vampi-down:
	@echo "$(PREFIX) Stopping VAmPI..."
	docker compose -f $(VAMPI_DIR)/docker-compose.yaml down -v

vampi-logs:
	docker compose -f $(VAMPI_DIR)/docker-compose.yaml logs -f

vampi-status:
	docker compose -f $(VAMPI_DIR)/docker-compose.yaml ps

# --- DataDog Vulnerable Java Application ---

vulnerable-java-up:
	@echo "$(PREFIX) Starting DataDog Vulnerable Java Application..."
	docker compose -f $(VULN_JAVA_DIR)/docker-compose.yaml up -d
	@echo "$(PREFIX) Vulnerable Java App: http://127.0.0.1:8000"

vulnerable-java-down:
	@echo "$(PREFIX) Stopping DataDog Vulnerable Java Application..."
	docker compose -f $(VULN_JAVA_DIR)/docker-compose.yaml down -v

vulnerable-java-logs:
	docker compose -f $(VULN_JAVA_DIR)/docker-compose.yaml logs -f

vulnerable-java-status:
	docker compose -f $(VULN_JAVA_DIR)/docker-compose.yaml ps

# --- detectify Vulnerable Nginx ---

vulnerable-nginx-up:
	@echo "$(PREFIX) Starting detectify Vulnerable Nginx..."
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml up -d
	@echo "$(PREFIX) Vulnerable Nginx: http://127.0.0.1:5000"

vulnerable-nginx-down:
	@echo "$(PREFIX) Stopping detectify Vulnerable Nginx..."
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml down -v

vulnerable-nginx-logs:
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml logs -f

vulnerable-nginx-status:
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml ps

# jsscan binary management
JSSCAN_SRC_DIR=platform/jsscan/bin
JSSCAN_DST_DIR=internal/resources/deparos/jsscan

# jsscan embedded resources (internal/resources)
JSSCAN_RES_SRC_DIR=platform/jsscan/bin
JSSCAN_RES_DST_DIR=internal/resources/deparos/jsscan
JSSCAN_RES_BINS=jsscan-darwin-amd64 jsscan-darwin-arm64 jsscan-linux-amd64 jsscan-linux-arm64 jsscan-windows-amd64.exe

# Build jsscan from source and copy binaries
update-jsscan:
	@echo "$(PREFIX) Building jsscan from source..."
	cd platform/jsscan && bun install --linker isolated && bun run build:bin
	@echo "$(PREFIX) Copying jsscan binaries to $(JSSCAN_DST_DIR)..."
	@mkdir -p $(JSSCAN_DST_DIR)
	@cp -R $(JSSCAN_SRC_DIR)/* $(JSSCAN_DST_DIR)/
	@echo "$(PREFIX) jsscan binaries updated"

# Pre-test step: build jsscan from source if any binary is missing or is an LFS pointer
ensure-jsscan:
	@needs_build=0; \
	for bin in $(JSSCAN_RES_BINS); do \
		f="$(JSSCAN_RES_DST_DIR)/$$bin"; \
		if [ ! -f "$$f" ] || [ $$(wc -c < "$$f" | tr -d ' ') -lt 1024 ]; then \
			needs_build=1; \
			break; \
		fi; \
	done; \
	if [ $$needs_build -eq 1 ]; then \
		echo "$(PREFIX) jsscan binaries missing or invalid, building from source..."; \
		cd platform/jsscan && bun install --linker isolated && bun run build:bin; \
		cd ../..; \
		mkdir -p $(JSSCAN_RES_DST_DIR); \
		cp $(JSSCAN_SRC_DIR)/* $(JSSCAN_RES_DST_DIR)/; \
		echo "$(PREFIX) jsscan binaries built and copied"; \
	fi

# vigolium-audit security audit binary management.
# Source lives under platform/vigolium-audit/. `bun run build` produces a host
# binary at platform/vigolium-audit/build/dist/vigolium-audit-<os>-<arch>; we
# copy it to pkg/audit/bin/_bin/vigolium-audit, which is consumed by go:embed
# at vigolium build time. Cross-compile note: the embed is host-only — to
# cross-compile vigolium, stage the matching vigolium-audit-<os>-<arch> blob
# at the same path before running the cross GOOS/GOARCH build.
AUDIT_TS_DIR=platform/vigolium-audit
AUDIT_BIN_DST_DIR=pkg/audit/bin/_bin
AUDIT_BIN_HOST=$(AUDIT_BIN_DST_DIR)/vigolium-audit

# Upstream vigolium-audit checkout, expected as a sibling of the vigolium repo.
# Override on the command line, e.g. `make sync-audit AUDIT_UPSTREAM=...`.
AUDIT_UPSTREAM ?= ../vigolium-audit

# Sync platform/vigolium-audit/ from a sibling vigolium-audit checkout. Manual —
# there is no automated mirror. Excludes node_modules, build artifacts, the
# generated content bundle, and .git so the vendored copy stays minimal.
# Warns and exits 0 when AUDIT_UPSTREAM does not exist (so CI invocations
# don't fail just because the sibling checkout isn't present).
sync-audit:
	@set -e; \
	if [ ! -d "$(AUDIT_UPSTREAM)" ]; then \
		echo "\033[33m[!] vigolium-audit upstream not found at $(AUDIT_UPSTREAM); skipping sync.\033[0m"; \
		echo "    Clone vigolium-audit as a sibling of this repo, or override with"; \
		echo "    'make sync-audit AUDIT_UPSTREAM=/path/to/vigolium-audit'."; \
		exit 0; \
	fi; \
	echo "$(PREFIX) Syncing $(AUDIT_UPSTREAM)/ → $(AUDIT_TS_DIR)/"; \
	mkdir -p $(AUDIT_TS_DIR); \
	rsync -a --delete \
		--exclude='node_modules' \
		--exclude='build/dist' \
		--exclude='.git' \
		--exclude='.DS_Store' \
		--exclude='src/content-bundle.json' \
		--exclude='src/content/sdk-variants/' \
		"$(AUDIT_UPSTREAM)/" "$(AUDIT_TS_DIR)/"; \
	echo "$(PREFIX) Sync complete. Rebuilding embedded binary..."; \
	$(MAKE) update-audit

# Cross-compile targets the bun build can produce. Mirrors vigolium-audit's
# build.ts ALL_TARGETS list. The host's matching artifact is staged at
# $(AUDIT_BIN_HOST) for go:embed; the rest stay under the dist dir for
# cross-compile workflows that swap _bin/vigolium-audit manually.
AUDIT_BIN_TARGETS=darwin-arm64 darwin-x64 linux-arm64 linux-x64
AUDIT_DIST_DIR=$(AUDIT_TS_DIR)/build/dist

# Build vigolium-audit binary for every supported os/arch and stage the host's
# artifact at $(AUDIT_BIN_HOST) for embedding into vigolium. Run once
# per machine after a fresh clone, or whenever you sync new source
# under platform/vigolium-audit/.
update-audit:
	@echo "$(PREFIX) Building vigolium-audit for all targets ($(AUDIT_TS_DIR))..."
	@cd $(AUDIT_TS_DIR) && bun install && VIGOLIUM_AUDIT_BUILD_NO_INSTALL=1 bun run build:all
	@mkdir -p $(AUDIT_BIN_DST_DIR)
	@set -e; \
	for target in $(AUDIT_BIN_TARGETS); do \
		bin="$(AUDIT_DIST_DIR)/vigolium-audit-$$target"; \
		if [ ! -x "$$bin" ]; then \
			echo "\033[31m[!] vigolium-audit binary not produced at $$bin\033[0m"; \
			exit 1; \
		fi; \
		echo "  $$target  $$(wc -c < "$$bin" | tr -d ' ') bytes"; \
	done
	@host_arch=$$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/'); \
	host_os=$$(uname | tr '[:upper:]' '[:lower:]'); \
	host_bin="$(AUDIT_DIST_DIR)/vigolium-audit-$$host_os-$$host_arch"; \
	cp "$$host_bin" $(AUDIT_BIN_HOST); \
	chmod +x $(AUDIT_BIN_HOST); \
	echo "$(PREFIX) Staged $(AUDIT_BIN_HOST) (vigolium-audit-$$host_os-$$host_arch)"; \
	echo "$(PREFIX) Cross-compile artifacts available under $(AUDIT_DIST_DIR)/"

# Pre-build step: compile vigolium-audit when the embedded binary is missing
# or is the .gitkeep stub. The `go:embed all:_bin` pattern accepts an empty/
# stub _bin directory at build time — this guard ensures the runtime extract
# finds a real binary instead of failing with ErrBinaryMissing.
ensure-audit:
	@f="$(AUDIT_BIN_HOST)"; \
	size=0; \
	if [ -f "$$f" ]; then size=$$(wc -c < "$$f" | tr -d ' '); fi; \
	if [ -z "$$size" ] || [ "$$size" -lt 1048576 ]; then \
		echo "$(PREFIX) vigolium-audit binary missing or stub, building from source..."; \
		$(MAKE) update-audit; \
	fi

# Alias for ensure-audit used by build targets — kept short for readability.
build-audit: update-audit

# Copy fresh UI builds into embedded public/ paths
update-ui:
	@echo "$(PREFIX) Updating static report template..."
	@rm -f public/static-reports/template.html
	@cp platform/static-reports/dist/template.html public/static-reports/template.html
	@echo "$(PREFIX) Building workbench UI..."
	@cd platform/vigolium-workbench && bun run build
	@echo "$(PREFIX) Updating dashboard UI..."
	@rm -rf public/ui/
	@mkdir -p public/ui/
	@cp -r platform/vigolium-workbench/dist/* public/ui/
	@echo "$(PREFIX) UI assets updated"

# Sync platform sub-repos to standalone repos
sync-platform:
	@bash build/scripts/sync-platform.sh

# Docker parameters
DOCKER_IMAGE=vigolium
DOCKER_PROD_IMAGE=vigolium-prod
DOCKER_TAG?=$(VERSION)
DOCKER_REGISTRY?=
DOCKER_HUB_IMAGE?=j3ssie/vigolium

# Build Docker image
docker: docker-build

docker-build:
	@echo "$(PREFIX) Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		-f build/Dockerfile .
	@echo "$(PREFIX) Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Build production Docker image from build/Dockerfile.prod. Pulls the
# published binary via install.sh and runs `vigolium doctor --fix` at image
# build time so the resulting container has every runtime dependency baked in.
docker-build-prod:
	@echo "$(PREFIX) Building production Docker image $(DOCKER_PROD_IMAGE):$(DOCKER_TAG)..."
	docker build \
		-t $(DOCKER_PROD_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_PROD_IMAGE):latest \
		-f build/Dockerfile.prod .
	@echo "$(PREFIX) Production Docker image built: $(DOCKER_PROD_IMAGE):$(DOCKER_TAG)"

# Build the production image and drop into an interactive bash shell inside it.
# Use this to poke around the production image (verify tooling, run vigolium
# subcommands ad-hoc). Container is removed on exit (--rm).
docker-run: docker-build-prod
	@echo "$(PREFIX) Launching interactive shell in $(DOCKER_PROD_IMAGE):latest..."
	docker run --rm -it --entrypoint bash $(DOCKER_PROD_IMAGE):latest

# Push Docker image to registry
docker-push:
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "\033[31m[!] DOCKER_REGISTRY is not set. Usage: make docker-push DOCKER_REGISTRY=ghcr.io/user\033[0m"; \
		exit 1; \
	fi
	@echo "$(PREFIX) Tagging and pushing to $(DOCKER_REGISTRY)..."
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	@echo "$(PREFIX) Pushed $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)"

# Build the Docker image and publish it to Docker Hub as j3ssie/vigolium
# (override the repo with DOCKER_HUB_IMAGE=). Pushes both the version tag
# and :latest. Requires `docker login` to have been run beforehand.
docker-publish: docker-build
	@echo "$(PREFIX) Tagging and publishing to Docker Hub: $(DOCKER_HUB_IMAGE)..."
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_HUB_IMAGE):$(DOCKER_TAG)
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_HUB_IMAGE):latest
	docker push $(DOCKER_HUB_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_HUB_IMAGE):latest
	@echo "$(PREFIX) Published $(DOCKER_HUB_IMAGE):$(DOCKER_TAG) and $(DOCKER_HUB_IMAGE):latest"

# GoReleaser snapshot (local build without publishing)
GORELEASER_VERSION=$(patsubst v%,%,$(VERSION))

snapshot:
	@echo "$(PREFIX) Building snapshot release..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) goreleaser --verbose release --snapshot --clean

# Bump the single source-of-truth version in pkg/cli/version.go. npm versions
# are immutable, so every release needs a new number here before npm-publish.
# Default bumps the patch and keeps the prerelease label
# (v0.1.3-alpha -> v0.1.4-alpha). Override with PART=minor|major|pre|release,
# LABEL=<label>, or SET=<explicit version>. DRY_RUN=1 previews only.
bump-version:
	@PART="$(PART)" LABEL="$(LABEL)" SET="$(SET)" DRY_RUN="$(DRY_RUN)" bash build/scripts/bump-version.sh

# Stamp the nightly install script with the same prefix/version used for upload.
prepare-release-scripts:
	@echo "$(PREFIX) Updating release scripts..."
	@perl -0pi -e 's|^BASE_URL="[^"]*"|BASE_URL="$(INSTALL_BASE_URL)"|m' build/scripts/nightly-install.sh
	@echo "$(PREFIX) Release scripts updated for $(INSTALL_BASE_URL)"

# Stamp the public install script with the public/stable R2 prefix so the
# uploaded copy at cdn.vigolium.com/vigolium-release/install.sh resolves
# binaries from the matching prefix. Mutates build/scripts/install.sh in place.
prepare-public-scripts:
	@echo "$(PREFIX) Updating public release scripts..."
	@perl -0pi -e 's|^BASE_URL="[^"]*"|BASE_URL="$(PUBLIC_INSTALL_BASE_URL)"|m' build/scripts/install.sh
	@echo "$(PREFIX) Public release scripts updated for $(PUBLIC_INSTALL_BASE_URL)"

# Generate build/dist/metadata.json from the Go version file
generate-metadata:
	@mkdir -p build/dist
	@echo "$(PREFIX) Generating metadata.json (version=$(VERSION), commit=$(COMMIT_HASH))..."
	@printf '{\n  "version": "%s",\n  "commit": "%s",\n  "build_time": "%s"\n}\n' \
		"$(VERSION)" "$(COMMIT_HASH)" "$(BUILD_TIME)" > build/dist/metadata.json

# GoReleaser release and upload to R2
release: prepare-release-scripts
	@echo "$(PREFIX) Building release..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) goreleaser --verbose release --snapshot --clean
	@$(MAKE) generate-metadata
	@echo "$(PREFIX) Cleaning old files on R2..."
	@mc rm --recursive --force r2/vigolium-dist/$(R2_PREFIX)/ || true
	@echo "$(PREFIX) Uploading to R2..."
	@set -e; \
		archives=$$(ls build/dist/*.tar.gz 2>/dev/null | wc -l | tr -d ' '); \
		if [ "$$archives" -eq 0 ]; then \
			echo "\033[31m[!] No tar.gz archives found in build/dist/ — goreleaser output appears to have been wiped before upload.\033[0m"; \
			echo "\033[31m    Re-run 'make release' or investigate what is removing files from build/dist/.\033[0m"; \
			exit 1; \
		fi; \
		for f in build/dist/checksums.txt build/dist/metadata.json build/scripts/nightly-install.sh build/scripts/bootstrap.sh; do \
			if [ ! -f "$$f" ]; then \
				echo "\033[31m[!] Missing required upload artifact: $$f\033[0m"; \
				exit 1; \
			fi; \
		done; \
		mc cp build/dist/*.tar.gz r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/dist/checksums.txt r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/dist/metadata.json r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/scripts/nightly-install.sh r2/vigolium-dist/$(R2_PREFIX)/install.sh; \
		mc cp build/scripts/bootstrap.sh r2/vigolium-dist/$(R2_PREFIX)/
	@echo "$(PREFIX) Release uploaded successfully!"

# Build cross-platform binaries, tar, checksum, and upload to the public/stable
# R2 prefix (cdn.vigolium.com/vigolium-release/). Mirrors `release` but keeps a
# separate output dir so the two targets do not stomp on each other.
public:
	@echo "\033[31m[!] Use 'make public-release' for public release uploads.\033[0m"
	@exit 1

public-release: prepare-public-scripts
	@echo "$(PREFIX) Building public artifacts for: $(PUBLIC_TARGETS)"
	@rm -rf $(PUBLIC_DIST_DIR)
	@mkdir -p $(PUBLIC_DIST_DIR)
	@for target in $(PUBLIC_TARGETS); do \
		GOOS=$${target%/*}; GOARCH=$${target#*/}; \
		bin_name="vigolium"; \
		pkg_name="vigolium_$(PUBLIC_VERSION)_$${GOOS}_$${GOARCH}"; \
		stage_dir="$(PUBLIC_DIST_DIR)/$${pkg_name}"; \
		echo "$(PREFIX)   -> $${GOOS}/$${GOARCH}"; \
		mkdir -p $${stage_dir}; \
		GOOS=$${GOOS} GOARCH=$${GOARCH} CGO_ENABLED=0 \
			$(GOBUILD) $(LDFLAGS) \
			-o $${stage_dir}/$${bin_name} ./cmd/vigolium \
			|| exit 1; \
		COPYFILE_DISABLE=1 tar --no-xattrs -czf $(PUBLIC_DIST_DIR)/$${pkg_name}.tar.gz -C $${stage_dir} $${bin_name} \
			|| exit 1; \
		rm -rf $${stage_dir}; \
	done
	@echo "$(PREFIX) Writing checksums.txt..."
	@cd $(PUBLIC_DIST_DIR) && \
		(command -v shasum >/dev/null 2>&1 && shasum -a 256 *.tar.gz > checksums.txt \
		 || sha256sum *.tar.gz > checksums.txt)
	@echo "$(PREFIX) Writing metadata.json..."
	@printf '{\n  "version": "%s",\n  "commit": "%s",\n  "build_time": "%s"\n}\n' \
		"$(VERSION)" "$(COMMIT_HASH)" "$(BUILD_TIME)" > $(PUBLIC_DIST_DIR)/metadata.json
	@echo "$(PREFIX) Cleaning old files at r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/..."
	@mc rm --recursive --force r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/ || true
	@echo "$(PREFIX) Uploading public artifacts to R2..."
	mc cp $(PUBLIC_DIST_DIR)/*.tar.gz r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	mc cp $(PUBLIC_DIST_DIR)/checksums.txt r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	mc cp $(PUBLIC_DIST_DIR)/metadata.json r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	mc cp build/scripts/install.sh r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	@echo "$(PREFIX) Public release uploaded to $(PUBLIC_INSTALL_BASE_URL)/"

# Sync scripts to R2 CDN without rebuilding
cdn-sync: prepare-release-scripts generate-metadata
	@echo "$(PREFIX) Syncing scripts and metadata to R2 CDN..."
	mc cp build/scripts/nightly-install.sh r2/vigolium-dist/$(R2_PREFIX)/install.sh
	mc cp build/scripts/bootstrap.sh r2/vigolium-dist/$(R2_PREFIX)/
	mc cp build/dist/metadata.json r2/vigolium-dist/$(R2_PREFIX)/
	@echo "$(PREFIX) CDN sync complete"

# --- npm distribution -----------------------------------------------------
# Publish the vigolium binary to npm as @vigolium/vigolium. The binary ships
# gzipped inside per-platform optional-dependency packages (codex-style: one
# npm name, version-suffixed platform builds). See build/npm/build.mjs.
NPM_OUT_DIR=build/dist-npm

# "yes" when the goreleaser binaries are missing OR were built at a different
# version than pkg/cli/version.go ($(VERSION)) — i.e. stale after a version
# bump. Detected by grepping the ldflag-injected version string in each built
# binary (no execution, cross-platform). Recursive (=) so it only runs when
# referenced by the npm-build/npm-pack guards, not on every `make` invocation.
NPM_NEEDS_BUILD=$(shell bins=$$(ls build/dist/vigolium_*_*/vigolium 2>/dev/null); if [ -z "$$bins" ]; then echo yes; else r=no; for b in $$bins; do grep -qaF -- "$(VERSION)" "$$b" 2>/dev/null || r=yes; done; echo $$r; fi)

# Stage the npm packages from goreleaser output. Runs `make snapshot` first if
# the binaries are missing OR stale (built at a different version than
# pkg/cli/version.go), so a version bump never ships a mismatched binary.
npm-build:
	@if [ "$(NPM_NEEDS_BUILD)" = "yes" ]; then \
		echo "$(PREFIX) Binaries missing or stale for $(VERSION) — running 'make snapshot'..."; \
		$(MAKE) snapshot; \
	fi
	@echo "$(PREFIX) Staging npm packages (version $(GORELEASER_VERSION))..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) node build/npm/build.mjs

# Stage + produce inspectable .tgz tarballs (npm pack) for each package.
npm-pack:
	@if [ "$(NPM_NEEDS_BUILD)" = "yes" ]; then \
		echo "$(PREFIX) Binaries missing or stale for $(VERSION) — running 'make snapshot'..."; \
		$(MAKE) snapshot; \
	fi
	@echo "$(PREFIX) Staging + packing npm tarballs (version $(GORELEASER_VERSION))..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) node build/npm/build.mjs --pack
	@echo "$(PREFIX) Tarballs written to $(NPM_OUT_DIR)/"

# Publish to npm: platform packages FIRST (so the main package's
# optionalDependencies resolve), then the main package. Every run pins the
# `latest` dist-tag to the version being published (the main package is
# published as `latest` and `latest` is re-asserted + verified afterward), so
# `npm i -g @vigolium/vigolium` always installs this version.
#
# Auth is handled by your ~/.npmrc line:
#   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
# npm reads ~/.npmrc automatically (default userconfig, cwd-independent) and
# interpolates ${NPM_TOKEN} from the environment — just keep NPM_TOKEN
# exported. Set DRY_RUN=1 to preview (no token needed; --dry-run only packs).
npm-publish: npm-build
	@echo "$(PREFIX) Publishing @vigolium/vigolium ($(GORELEASER_VERSION)) to npm [latest -> $(GORELEASER_VERSION)]..."
	@set -e; \
		if [ "$(DRY_RUN)" = "1" ]; then \
			DRY="--dry-run"; \
			echo "$(PREFIX) DRY RUN — nothing will be published"; \
		else \
			DRY=""; \
			if [ -z "$${NPM_TOKEN:-}" ]; then \
				echo "\033[31m[!] NPM_TOKEN not set; ~/.npmrc auth will fail. Export it or use DRY_RUN=1.\033[0m"; \
				exit 1; \
			fi; \
		fi; \
		for d in $(NPM_OUT_DIR)/vigolium-*/; do \
			ptag=$$(basename "$$d" | sed 's/^vigolium-//'); \
			echo "$(PREFIX)   publishing platform package [$$ptag]"; \
			( cd "$$d" && npm publish --access public --tag "$$ptag" $$DRY ) \
				|| { echo "\033[31m[!] publish failed: $$ptag\033[0m"; exit 11; }; \
		done; \
		echo "$(PREFIX)   publishing $(NPM_OUT_DIR)/vigolium/ (main) [tag=latest]"; \
		( cd $(NPM_OUT_DIR)/vigolium && npm publish --access public --tag latest $$DRY ) \
			|| { echo "\033[31m[!] publish failed: main\033[0m"; exit 12; }; \
		if [ "$(DRY_RUN)" != "1" ]; then \
			echo "$(PREFIX)   pointing 'latest' dist-tag at $(GORELEASER_VERSION)"; \
			npm dist-tag add @vigolium/vigolium@$(GORELEASER_VERSION) latest \
				|| { echo "\033[31m[!] dist-tag add failed\033[0m"; exit 13; }; \
			resolved=""; \
			for i in 1 2 3 4 5 6; do \
				resolved=$$(npm dist-tag ls @vigolium/vigolium --prefer-online 2>/dev/null \
					| sed -n 's/^latest: //p'); \
				[ "$$resolved" = "$(GORELEASER_VERSION)" ] && break; \
				echo "$(PREFIX)   latest still '$$resolved' (npm registry cache lag) — retry $$i/6 in 10s"; \
				sleep 10; \
			done; \
			if [ "$$resolved" != "$(GORELEASER_VERSION)" ]; then \
				echo "\033[31m[!] latest resolved to '$$resolved', expected '$(GORELEASER_VERSION)' after retries\033[0m"; \
				echo "\033[31m    Publish likely succeeded — verify: npm dist-tag ls @vigolium/vigolium\033[0m"; \
				exit 14; \
			fi; \
			echo "$(PREFIX)   verified: latest -> $$resolved"; \
		fi
	@echo "$(PREFIX) npm publish complete"

# Clean build artifacts
clean:
	@echo "$(PREFIX) Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)/
	rm -f coverage.out coverage.html test-results.xml coverage-unit.out coverage-e2e.out coverage-combined.out coverage-combined.html

# Install to GOPATH/bin
install: build
	@echo "$(PREFIX) Installed $(BINARY_NAME) to $(GOPATH_BIN)"

# Format code
fmt:
	@echo "$(PREFIX) Formatting code..."
	$(GOFMT) ./...

# Lint code
lint:
	@echo "$(PREFIX) Running linter..."
	golangci-lint run

# Verify checked-in, machine-managed sources are in sync with their generators.
# Covers the deterministic artifacts: gofmt output and the go.mod/go.sum manifest.
# (Binary assets — jsscan, the audit harness, UI bundles — are non-deterministic
# build outputs regenerated by `make deps`, `make update-audit`, `make update-ui`;
# they are not diff-verifiable here. See docs/development/generated-assets.md.)
verify-generated:
	@echo "$(PREFIX) Verifying formatting is clean..."
	@unformatted="$$(gofmt -l $$(go list -f '{{.Dir}}' ./... | grep -Ev '$(GOLIST_EXCLUDE)'))"; \
	if [ -n "$$unformatted" ]; then \
		echo "$(PREFIX) These files are not gofmt-clean — run 'make fmt':"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "$(PREFIX) Verifying go.mod/go.sum are tidy..."
	@cp go.mod go.mod.verify.bak; cp go.sum go.sum.verify.bak; \
	$(GOMOD) tidy; \
	status=0; \
	if ! diff -q go.mod go.mod.verify.bak >/dev/null || ! diff -q go.sum go.sum.verify.bak >/dev/null; then \
		echo "$(PREFIX) go.mod/go.sum are not tidy — run 'make tidy' and commit the result."; \
		status=1; \
	fi; \
	mv go.mod.verify.bak go.mod; mv go.sum.verify.bak go.sum; \
	exit $$status
	@echo "$(PREFIX) Generated/managed sources are in sync."

# Tidy dependencies
tidy:
	@echo "$(PREFIX) Tidying dependencies..."
	$(GOMOD) tidy

# Helper scripts
SCRIPTS_DIR := internal/resources/scripts

# Download dependencies, build jsscan, and check Chromium
deps: update-jsscan
	@echo "$(PREFIX) Downloading Go dependencies..."
	$(GOMOD) download
	@$(SCRIPTS_DIR)/deps-check.sh

# Chromium browser archive management (logic in helper scripts)

deps-chrome: ## Download all browser archives (versions.go + Chrome for Testing from CfT API)
	@$(SCRIPTS_DIR)/chrome-download.sh

deps-chrome-cft: ## Download only Chrome for Testing (stable). Usage: make deps-chrome-cft [PLATFORM=linux64]
	@$(SCRIPTS_DIR)/chrome-download-cft.sh $(PLATFORM)

deps-chrome-update: ## Update browser version+URL. Usage: make deps-chrome-update NAME=chromium PLATFORM=linux64 VERSION=144.0.xxx URL=https://...
	@$(SCRIPTS_DIR)/chrome-update.sh "$(NAME)" "$(PLATFORM)" "$(VERSION)" "$(URL)"

# Swagger paths
SWAGGER_CANONICAL=docs/development/api-swagger.json
SWAGGER_EMBEDDED=pkg/server/swagger_spec.json

# Generate / sync Swagger spec: copy canonical spec into the embedded location
swagger:
	@echo "$(PREFIX) Syncing Swagger spec from $(SWAGGER_CANONICAL) to $(SWAGGER_EMBEDDED)..."
	@if [ ! -f "$(SWAGGER_CANONICAL)" ]; then \
		echo "\033[31m[!] $(SWAGGER_CANONICAL) not found. Create the spec first.\033[0m"; \
		exit 1; \
	fi
	@cp $(SWAGGER_CANONICAL) $(SWAGGER_EMBEDDED)
	@echo "$(PREFIX) Validating JSON..."
	@python3 -m json.tool $(SWAGGER_EMBEDDED) > /dev/null 2>&1 || { echo "\033[31m[!] Invalid JSON in swagger spec\033[0m"; exit 1; }
	@echo "$(PREFIX) Swagger spec synced successfully"

# Help
help:
	@echo ""
	@echo "\033[32m Vigolium $(VERSION) - Advanced Web Application Security Scanner\033[0m"
	@echo "\033[36m                 Commit: $(COMMIT_HASH) | Built: $(BUILD_TIME)\033[0m"
	@echo "\033[34m     ──────────────────────────────────────────────────\033[0m"
	@echo ""
	@echo "\033[33m  BUILD & INSTALL\033[0m"
	@echo "    make build            Build vigolium binary (no embedded Chromium)"
	@echo "    make build-embedded   Build with embedded Chromium (requires 'make deps-chrome')"
	@echo "    make build-all        Build for all platforms including vigolium-ingestor"
	@echo "    make build-ingestor   Build vigolium-ingestor binary"
	@echo "    make install          Install binaries to \$$GOPATH/bin"
	@echo "    make clean            Clean build artifacts"
	@echo ""
	@echo "\033[33m  TEST\033[0m"
	@echo "    make test             Run all tests"
	@echo "    make test-race        Run all tests with race detector"
	@echo "    make test-unit        Run unit tests (fast, no external deps)"
	@echo "    make test-integration Run integration tests (XSS gym benchmark)"
	@echo "    make test-benchmark   Run benchmark tests (alias for test-integration)"
	@echo "    make test-e2e         Run E2E tests (requires Docker)"
	@echo "    make test-e2e-api     Run API E2E tests only (server endpoints)"
	@echo "    make test-e2e-agent   Run Agent API E2E tests only (agent endpoints)"
	@echo "    make test-e2e-postgres  Run PostgreSQL E2E tests (requires make postgres-up)"
	@echo "    make test-canary      Run canary tests: DVWA, VAmPI, Juice Shop (Docker)"
	@echo "    make test-e2e-vampi   Run VAmPI canary tests only (SQLi)"
	@echo "    make test-e2e-dvwa    Run DVWA canary tests only (XSS, SQLi, LFI)"
	@echo "    make test-e2e-juiceshop  Run Juice Shop canary tests only"
	@echo "    make test-e2e-browser-fallback  Browser fallback test (Docker multi-arch)"
	@echo "    make test-e2e-piolium  Piolium audit e2e (requires pi + piolium installed)"
	@echo "    make smoke-autopilot-auth  Smoke: agent autopilot --credentials against juice-shop"
	@echo "    make test-xbow        Run all xbow validation benchmarks (Docker + XBOW_SOURCE_DIR)"
	@echo "    make test-xbow-ssti   Run xbow SSTI benchmarks"
	@echo "    make test-xbow-xss    Run xbow XSS benchmarks"
	@echo "    make test-xbow-sqli   Run xbow SQLi benchmarks"
	@echo "    make test-xbow-lfi    Run xbow LFI benchmarks"
	@echo "    make test-xbow-cmdi   Run xbow Command Injection benchmarks"
	@echo "    make test-xbow-ssrf   Run xbow SSRF benchmarks"
	@echo "    make test-xbow-xxe    Run xbow XXE benchmarks"
	@echo "    make xbow-build       Pre-build all xbow benchmark containers"
	@echo "    make test-agent-benchmark  Run agent benchmarks: parsing + quality + handoff"
	@echo "    make test-agent-parsing    Run agent parsing benchmarks only (Layer 1)"
	@echo "    make test-agent-quality    Run agent quality benchmarks only (Layer 2)"
	@echo "    make test-agent-handoff    Run agent handoff benchmarks only (Layer 3)"
	@echo "    make test-agent-benchmark-e2e  Run agent E2E benchmarks (Docker required)"
	@echo "    make benchmark-agent-generate  Generate agent fixtures (real LLM, expensive)"
	@echo "    make test-coverage    Run tests with coverage report"
	@echo "    make coverage-combined  Combined unit + no-Docker e2e coverage (report only, not gated)"
	@echo "    make test-coverage-check  Enforce the COVERAGE_MIN coverage floor (default $(COVERAGE_MIN)%)"
	@echo "    make test-ci          Run tests with JUnit XML output"
	@echo ""
	@echo "\033[33m  DEVELOPMENT\033[0m"
	@echo "    make fmt              Format code"
	@echo "    make lint             Run golangci-lint"
	@echo "    make tidy             Tidy go.mod dependencies"
	@echo "    make deps             Download dependencies + ensure jsscan binaries"
	@echo "    make deps-chrome      Download Chromium browser archives from versions.go"
	@echo "    make deps-chrome-update  Update browser version+URL (NAME= PLATFORM= VERSION= URL=)"
	@echo "    make swagger          Sync Swagger spec to embedded copy"
	@echo "    make update-ui        Copy fresh UI builds into public/ (report template + dashboard)"
	@echo ""
	@echo "\033[33m  VULNERABLE APPS (Docker)\033[0m"
	@echo "    make apps-up          Start all vulnerable apps"
	@echo "    make apps-down        Stop all vulnerable apps"
	@echo "    make crapi-up         Start OWASP crAPI (http://127.0.0.1:8888)"
	@echo "    make crapi-down       Stop and remove OWASP crAPI containers"
	@echo "    make crapi-logs       Follow OWASP crAPI logs"
	@echo "    make crapi-status     Show OWASP crAPI service status"
	@echo "    make juiceshop-up     Start Juice Shop (http://127.0.0.1:3000)"
	@echo "    make juiceshop-down   Stop and remove Juice Shop container"
	@echo "    make juiceshop-logs   Follow Juice Shop logs"
	@echo "    make juiceshop-status Show Juice Shop service status"
	@echo "    make vampi-up         Start VAmPI (http://127.0.0.1:3005, :3006)"
	@echo "    make vampi-down       Stop and remove VAmPI containers"
	@echo "    make vampi-logs       Follow VAmPI logs"
	@echo "    make vampi-status     Show VAmPI service status"
	@echo "    make vulnerable-java-up    Start DataDog Vulnerable Java App (http://127.0.0.1:8000)"
	@echo "    make vulnerable-java-down  Stop Vulnerable Java App"
	@echo "    make vulnerable-nginx-up   Start detectify Vulnerable Nginx (http://127.0.0.1:5000)"
	@echo "    make vulnerable-nginx-down Stop Vulnerable Nginx"
	@echo ""
	@echo "\033[33m  SSH TESTBED (Docker)\033[0m"
	@echo "    make ssh-testbed-keygen   Generate dummy SSH keypair"
	@echo "    make ssh-testbed-up       Start SSH testbed (Ubuntu :2222, Debian :2223)"
	@echo "    make ssh-testbed-down     Stop and remove SSH testbed containers"
	@echo "    make ssh-testbed-status   Show SSH testbed container status"
	@echo "    make ssh-testbed-logs     Follow SSH testbed container logs"
	@echo ""
	@echo "\033[33m  DATABASE (Docker)\033[0m"
	@echo "    make postgres-up      Start PostgreSQL for E2E tests (localhost:5433)"
	@echo "    make postgres-down    Stop and remove PostgreSQL test container"
	@echo "    make test-benchmark-vuln-java   Run vulnerable-java benchmarks"
	@echo "    make test-benchmark-vuln-nginx  Run vulnerable-nginx benchmarks"
	@echo ""
	@echo "\033[33m  DOCKER\033[0m"
	@echo "    make docker           Build Docker image (vigolium:VERSION)"
	@echo "    make docker-build     Build Docker image (same as docker)"
	@echo "    make docker-build-prod  Build production image (vigolium-prod, from Dockerfile.prod)"
	@echo "    make docker-run       Build prod image and drop into an interactive bash shell"
	@echo "    make docker-push      Push to registry (set DOCKER_REGISTRY=ghcr.io/user)"
	@echo "    make docker-publish   Build and publish to Docker Hub ($(DOCKER_HUB_IMAGE))"
	@echo ""
	@echo "\033[33m  RELEASE\033[0m"
	@echo "    make snapshot         Build local snapshot release (no publish)"
	@echo "    make release          Build and upload nightly artifacts to R2 (cdn.vigolium.com/vigolium-nightly-release/)"
	@echo "    make public-release   Build cross-platform tarballs and upload to the public/stable R2 prefix (cdn.vigolium.com/vigolium-release/)"
	@echo "    make cdn-sync         Sync nightly scripts (install.sh, bootstrap.sh) to R2 CDN"
	@echo "    make bump-version     Bump pkg/cli/version.go (PART=patch|minor|major|pre|release, DRY_RUN=1)"
	@echo "    make npm-build        Stage @vigolium/vigolium npm packages into build/dist-npm/"
	@echo "    make npm-pack         npm-build + produce inspectable .tgz tarballs"
	@echo "    make npm-publish      Publish to npm; auth via ~/.npmrc (NPM_TOKEN env var)"
	@echo "                          (always pins latest->version; DRY_RUN=1 to preview)"
	@echo ""
