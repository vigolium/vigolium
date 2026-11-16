.PHONY: build build-prof build-embedded build-all snapshot release public public-release github-release prepare-public-scripts clean test test-unit test-integration test-spitolas-browser test-browser-conformance test-e2e test-e2e-api test-e2e-agent test-e2e-rest-scan test-e2e-postgres test-canary sanity-check test-e2e-vampi test-e2e-dvwa test-e2e-juiceshop test-e2e-browser-fallback test-e2e-piolium test-benchmark test-benchmark-whitebox test-benchmark-blackbox test-benchmark-all test-benchmark-crapi test-benchmark-vuln-java test-benchmark-vuln-nginx test-benchmark-coverage bench-diff test-agent-benchmark test-agent-parsing test-agent-quality test-agent-handoff test-agent-benchmark-e2e benchmark-agent-generate test-coverage coverage-gate coverage-combined test-coverage-check test-race test-ci test-xbow test-xbow-ssti test-xbow-xss test-xbow-sqli test-xbow-lfi test-xbow-cmdi test-xbow-ssrf test-xbow-xxe xbow-build lint verify-generated fmt tidy deps deps-chrome deps-chrome-update install install-gotestsum swagger help postgres-up postgres-down postgres-logs postgres-status crapi-up crapi-down crapi-logs crapi-status juiceshop-up juiceshop-down juiceshop-logs juiceshop-status vampi-up vampi-down vampi-logs vampi-status vulnerable-java-up vulnerable-java-down vulnerable-java-logs vulnerable-java-status vulnerable-nginx-up vulnerable-nginx-down vulnerable-nginx-logs vulnerable-nginx-status apps-up apps-down docker docker-build docker-build-prod docker-run docker-push docker-buildx-setup docker-publish update-jstangle ensure-jstangle sync-audit update-audit ensure-audit ensure-audit-dist restage-host-audit build-audit update-ui ssh-testbed-keygen ssh-testbed-up ssh-testbed-down ssh-testbed-status ssh-testbed-logs generate-metadata prepare-release-scripts release-verify release-sign release-prune cdn-sync bump-version npm-build npm-pack npm-publish
# Phony targets defined in their own sections below (declared here so a stray
# same-named file can never shadow them).
.PHONY: all build-linux build-darwin build-windows deps-chrome-cft sync-platform sync-skills \
	test-canary-postgres test-pg-full test-e2e-autonomous test-e2e-scorecard test-e2e-expect test-e2e-expect-lab test-e2e-expect-live e2e-expect-lab \
	access-lab-up access-lab-down access-lab-logs access-lab-status schema \
	setup-agent-codex test-smoke-autopilot test-smoke-autopilot-rest test-smoke-autopilot-prior test-smoke-autopilot-ginandjuice \
	test-smoke-autopilot-crapi test-smoke-autopilot-juiceshop

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod
GORUN=$(GOCMD) run
BINARY_NAME=vigolium
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
# Shared version stamps. Factored out so a new -X symbol is added once and reaches
# every build variant — a stamp that lands in only one is invisible until someone
# reads --version output from the other. VERSION_SUFFIX lets a variant mark itself.
LDFLAGS_STAMP=-X $(CLI_PKG).Version=$(VERSION)$(VERSION_SUFFIX) -X $(CLI_PKG).Commit=$(COMMIT_HASH) -X $(CLI_PKG).BuildTime=$(BUILD_TIME)
LDFLAGS_INNER=-s -w $(LDFLAGS_STAMP)
LDFLAGS=-ldflags "$(LDFLAGS_INNER)"

# R2 CDN prefix for `make release` — nightly release uploads. Served at
# cdn.vigolium.com/vigolium-nightly-release/ via build/scripts/nightly-install.sh.
R2_PREFIX=vigolium-nightly-release
INSTALL_BASE_URL=https://cdn.vigolium.com/$(R2_PREFIX)

# R2 CDN prefix for `make public-release` — public/stable release uploads. Served
# at cdn.vigolium.com/vigolium-release/ via build/scripts/install.sh.
R2_PUBLIC_PREFIX=vigolium-release
PUBLIC_INSTALL_BASE_URL=https://cdn.vigolium.com/$(R2_PUBLIC_PREFIX)
PUBLIC_DIST_DIR=build/dist-public
# windows/arm64 is intentionally absent: the embedded vigolium-audit and
# jstangle helpers are Bun-compiled and Bun has no bun-windows-arm64 target.
# Windows on ARM runs the amd64 artifact under emulation.
PUBLIC_TARGETS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
# Version without leading 'v' — matches the install.sh tarball-name convention.
PUBLIC_VERSION=$(patsubst v%,%,$(VERSION))

# Default target
all: build

# Build main binary and install to GOBIN
build: ensure-audit
	@if [ -z "$$(ls $(JSTANGLE_RES_DST_DIR)/ 2>/dev/null)" ]; then \
		echo "$(PREFIX) First build on this machine — jstangle binaries not found, running 'make deps' to prepare dependencies..."; \
		$(MAKE) deps; \
	fi
	@$(MAKE) --no-print-directory pack-jstangle-host
	@echo "$(PREFIX) Building $(BINARY_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/vigolium
	@echo "$(PREFIX) Installing $(BINARY_NAME) to $(GOPATH_BIN)..."
	@mkdir -p $(GOPATH_BIN)
	@rm -f $(GOPATH_BIN)/$(BINARY_NAME)
	@cp $(BINARY_DIR)/$(BINARY_NAME) $(GOPATH_BIN)/$(BINARY_NAME)
	@echo "$(PREFIX) Build complete! Binary: $(BINARY_DIR)/$(BINARY_NAME) and $(GOPATH_BIN)/$(BINARY_NAME)"

# Build with embedded Chromium (requires 'make deps-chrome' first)
build-embedded: ensure-audit pack-jstangle-host
	@echo "$(PREFIX) Building $(BINARY_NAME) with embedded Chromium..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -tags=embed_chromium -o $(BINARY_DIR)/$(BINARY_NAME) ./cmd/vigolium
	@echo "$(PREFIX) Installing $(BINARY_NAME) to $(GOPATH_BIN)..."
	@mkdir -p $(GOPATH_BIN)
	@rm -f $(GOPATH_BIN)/$(BINARY_NAME)
	@cp $(BINARY_DIR)/$(BINARY_NAME) $(GOPATH_BIN)/$(BINARY_NAME)
	@echo "$(PREFIX) Build complete! Binary: $(BINARY_DIR)/$(BINARY_NAME) and $(GOPATH_BIN)/$(BINARY_NAME)"

# Build a profiling binary: `build` without -s -w, so Go symbols survive and CPU
# profilers can attribute samples (the stripped release binary reports every frame
# as "??? (in vigolium)"). Writes bin/vigolium-prof and deliberately does NOT
# install to $(GOPATH_BIN) — profiling means running a real scan, which must not
# require swapping out the binary you ship.
#
#   make build-prof
#   sample $$(pgrep -n -f 'vigolium-prof scan') 15 -f /tmp/scan.sample
build-prof: VERSION_SUFFIX=-prof
build-prof: ensure-audit pack-jstangle-host
	@echo "$(PREFIX) Building $(BINARY_NAME)-prof (symbols retained, not installed)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS_STAMP)" -o $(BINARY_DIR)/$(BINARY_NAME)-prof ./cmd/vigolium
	@echo "$(PREFIX) Profiling binary: $(BINARY_DIR)/$(BINARY_NAME)-prof"

# Build for multiple platforms
build-all: build build-linux build-darwin build-windows

build-linux:
	@echo "$(PREFIX) Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/vigolium

build-darwin:
	@echo "$(PREFIX) Building for macOS..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/vigolium
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/vigolium

build-windows:
	@echo "$(PREFIX) Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/vigolium

# Install gotestsum (idempotent - silent if already installed)
install-gotestsum:
	@if [ ! -x "$(GOPATH_BIN)/gotestsum" ]; then \
		echo "$(PREFIX) Installing gotestsum..."; \
		go install gotest.tools/gotestsum@latest; \
	fi

# Run all tests (install gotestsum first; see GOLIST_EXCLUDE for what's filtered)
test: install-gotestsum ensure-jstangle
	@echo "$(PREFIX) Running all tests..."
	$(TESTCMD) $(TESTFLAGS) $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run tests with race detector (see GOLIST_EXCLUDE for what's filtered)
# Race-sensitive packages (goroutine shutdown, ctx-aware polling, shared
# counters) whose tests are meant to run here: pkg/spitolas/internal/network
# (capture writer receipt/drain, capture timing), pkg/spitolas/internal/condition
# (ctx-aware wait polling), pkg/spitolas/internal/browser (launch/tab-creation
# cancellation, dialog handling), pkg/spitolas/internal/crawler and
# pkg/spitolas/internal/form (stats, policy gates, upload fixtures).
test-race: install-gotestsum ensure-jstangle
	@echo "$(PREFIX) Running tests with race detector..."
	$(TESTCMD) $(TESTFLAGS) -race -timeout 30m $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run unit tests (excludes integration, e2e; see GOLIST_EXCLUDE for what's filtered)
test-unit: install-gotestsum ensure-jstangle
	@echo "$(PREFIX) Running unit tests..."
	$(TESTCMD) $(TESTFLAGS) -short $$(go list ./... | grep -Ev '$(GOLIST_EXCLUDE)')

# Run integration tests (Brutelogic XSS gym benchmark)
test-integration: install-gotestsum
	@echo "$(PREFIX) Running integration tests (requires internet)..."
	$(TESTCMD) $(TESTFLAGS) -tags=integration ./test/benchmark/...

# Run benchmark tests (alias for test-integration)
test-benchmark: test-integration

# Run spitolas browser integration tests (launch a real headless browser against a
# local httptest server; no Docker). Covers native service-worker network capture
# and browser teardown / zombie-process guards.
test-spitolas-browser: install-gotestsum
	@echo "$(PREFIX) Running spitolas browser integration tests (real headless browser)..."
	$(TESTCMD) $(TESTFLAGS) -tags=integration -timeout 15m ./pkg/spitolas/internal/browser/...

# Browser conformance: the integration contracts of the browser crawler —
# launcher and security flags, dialog and submit-guard policy, form fill
# outcomes and form scoping, POST-submission attribution, crawler gates, wait
# conditions — against a real headless browser and local httptest fixtures (no
# Docker, no internet). These files are //go:build integration, so the -short
# unit run never executes them. Fails up front when no browser can be
# launched, so a host without one is never reported green. -p 1 keeps the
# packages from competing for the CPU, which the timing-sensitive cases need.
# The crawler package alone runs over 20m of real crawls over the Crawljax site
# fixtures (test/spitolas/testdata/html/site), hence the 45m binary timeout.
CONFORMANCE_PKGS=./pkg/spitolas/internal/browser/... ./pkg/spitolas/internal/form/... ./pkg/spitolas/internal/crawler/... ./pkg/spitolas/internal/condition/...
test-browser-conformance: install-gotestsum
	@echo "$(PREFIX) Checking that a headless browser can be launched..."
	@out="$$($(GOTEST) -tags=integration -count=1 -run '^TestConformancePrecheck$$' ./pkg/spitolas/internal/browser/ 2>&1)" || { \
		echo "$$out" | tail -n 5; \
		echo "$(PREFIX) No launchable headless browser. Install Google Chrome or Chromium, or run 'vigolium doctor --fix --only chrome' to fetch Chrome for Testing, then re-run."; \
		exit 1; }
	@echo "$(PREFIX) Running browser conformance tests (real headless browser)..."
	$(TESTCMD) $(TESTFLAGS) -tags=integration -p 1 -count=1 -timeout 45m $(CONFORMANCE_PKGS)

# Run E2E tests (requires Docker)
test-e2e: install-gotestsum
	@echo "$(PREFIX) Running E2E tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 90m ./test/e2e/... ./test/e2e-expect/...

# Run API E2E tests only (server endpoint tests, no Docker needed)
test-e2e-api: install-gotestsum
	@echo "$(PREFIX) Running API E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestAPI_ ./test/e2e/...

# Run Agent API E2E tests only (agent endpoint tests, no Docker needed)
test-e2e-agent: install-gotestsum
	@echo "$(PREFIX) Running Agent API E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestAgentAPI_ ./test/e2e/...

# Run the REST scan-trigger E2E tests: boot the API server in-process and drive a
# native scan AND an agentic (autopilot/swarm) scan entirely through the REST API
# against a hermetic 127.0.0.1 target. No Docker, no LLM provider required — the
# agentic legs assert the launch/track/cancel wiring (a real provider-backed run
# lives in `make test-smoke-autopilot`). Regression guard for server mis-wiring
# that turns scan-triggering endpoints into 500s/panics.
test-e2e-rest-scan: install-gotestsum
	@echo "$(PREFIX) Running REST scan-trigger E2E tests (native + agentic via API)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 10m -run TestAPI_REST_ ./test/e2e/...

# Run PostgreSQL E2E tests (requires 'make postgres-up' first)
test-e2e-postgres: install-gotestsum
	@echo "$(PREFIX) Running PostgreSQL E2E tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -run TestPg_ ./test/e2e/...

# Run canary tests - DVWA, VAmPI, Juice Shop (requires Docker, slower).
# The full canary suite (nuclei known-issue-scan + dynamic assessment against
# several live targets) exceeds Go's default 10m binary timeout, so raise it
# to match test-e2e.
test-canary: install-gotestsum
	@echo "$(PREFIX) Running canary tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -timeout 60m ./test/e2e/...

# Expectation e2e kit (test/e2e-expect). Two halves, both under the e2e tag:
#   lab  — scan/fuzz/probe/lifecycle against an in-process lab of planted bugs,
#          benign twins and hostile servers, asserting on findings AND on what
#          each server saw on the wire (scope, pace, budgets, hangs, leaks).
#   live — TestLive_*: native scans, module-scoped and stateless scans, and
#          `vigolium run <phase>` against Docker targets (Juice Shop, VAmPI).
# Known defects live in knownDefects (scan_test.go); golden results in
# test/e2e-expect/testdata/expect.json (regenerate: E2E_EXPECT_ARGS='-args -update-expect').
# E2E_EXPECT_BIN=bin/vigolium reuses a built binary for the CLI scenarios.
test-e2e-expect: install-gotestsum
	@echo "$(PREFIX) Running expectation e2e kit (lab + live Docker targets)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 90m ./test/e2e-expect/... $(E2E_EXPECT_ARGS)

test-e2e-expect-lab: install-gotestsum
	@echo "$(PREFIX) Running expectation e2e kit, lab half (no Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 30m -short ./test/e2e-expect/... $(E2E_EXPECT_ARGS)

test-e2e-expect-live: install-gotestsum
	@echo "$(PREFIX) Running expectation e2e kit, live half (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 90m -run 'TestLive_' ./test/e2e-expect/... $(E2E_EXPECT_ARGS)

# Serve the expectation lab standalone for hands-on testing (Ctrl-C prints the ledger).
e2e-expect-lab:
	go run ./test/tools/lab $(LAB_ARGS)

# Run canary tests against PostgreSQL (requires 'make postgres-up' first).
# Per-test: drops+recreates the shared PG schema for isolation.
test-canary-postgres: export VIGOLIUM_TEST_DB_DRIVER=postgres
test-canary-postgres: install-gotestsum
	@echo "$(PREFIX) Running canary tests against PostgreSQL..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -timeout 60m ./test/e2e/...

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
# Boots a local server configured with GCS storage credentials, runs native +
# audit + autopilot scans against ginandjuice.shop / VAmPI / juice-shop with
# upload_results=true, and verifies bundles land at the documented keys.
#
# Required: jq, tar, gzip, uuidgen, python3 on PATH; network access to the
# real targets and the shared GCS bucket. Agent phases skip cleanly if no LLM
# provider (~/.codex/auth.json, $ANTHROPIC_API_KEY, or $OPENAI_API_KEY) is set.
sanity-check: build
	@echo "$(PREFIX) Running sanity-check (real-target API + storage smoke test)..."
	@bash test/sanity-check/sanity-check.sh

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

# Run autonomous full-chain scan canary tests: point the scanner at a live app's
# base URL only and let it discover the surface (content discovery + browser
# spidering) and assess it (dynamic-assessment) with the full module set, then
# assert it found routes it was never told about AND findings on them. Requires
# Docker; the Juice Shop SPA case also needs a Chromium runtime (skips gracefully
# without one).
test-e2e-autonomous: install-gotestsum
	@echo "$(PREFIX) Running autonomous full-chain scan canary tests..."
	$(TESTCMD) $(TESTFLAGS) -tags=canary -timeout 30m -run TestAutonomousScan ./test/e2e/

# Run the ground-truth coverage scorecards: seed each app's source-verified
# vulnerable surface (DVWA/VAmPI/Juice Shop/vulnerable-java), run the full module
# set, and report CATCH/MISS per known vuln vs the catalog extracted from the
# app's own source (reverse-engineered endpoints for vulnerable-java). Includes
# authenticated cases: Juice Shop (Bearer token) and crAPI (a multi-session
# --auth-file bundle) that reach the protected surface and catch the numeric-ID
# BOLA/IDOR via idor-detection (single identity) and authz-compare (second
# identity). Requires Docker; the crAPI case also needs its stack up
# (`make crapi-up`) and skips cleanly otherwise (VIGOLIUM_CRAPI_URL overrides).
test-e2e-scorecard: install-gotestsum
	@echo "$(PREFIX) Running ground-truth coverage scorecard canary tests..."
	@echo "$(PREFIX) (verbose: each scan logs its replicable 'vigolium scan ...' command + per-vuln CATCH/MISS)"
	@echo "$(PREFIX) (includes TestCoverageScorecard_RESTNativeScan_DVWA — the same DVWA scan driven through the REST API)"
	$(GOTEST) -v -tags=canary -timeout 40m -run TestCoverageScorecard ./test/e2e/

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

# Compare two benchmark result files (BENCH_OUT JSON lines, e.g. the nightly
# `benchmark-results` artifacts of two commits). Exits 1 on a regression:
# passed -> failed, fewer findings, or a case missing from HEAD.
#   make bench-diff BASE=old.jsonl HEAD=new.jsonl [BENCH_DIFF_FLAGS=-strict-requests]
bench-diff:
	@test -n "$(BASE)" -a -n "$(HEAD)" || { echo "usage: make bench-diff BASE=old.jsonl HEAD=new.jsonl"; exit 2; }
	go run ./test/tools/benchdiff -base "$(BASE)" -head "$(HEAD)" $(BENCH_DIFF_FLAGS)

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
test-coverage: install-gotestsum ensure-jstangle
	@echo "$(PREFIX) Running tests with coverage..."
	$(TESTCMD) $(TESTFLAGS) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(PREFIX) Coverage report saved to coverage.html"

# Test with JUnit XML output (for CI). Emits a coverage profile and enforces
# the COVERAGE_MIN floor after the run so a coverage regression fails the build.
test-ci: install-gotestsum ensure-jstangle
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
test-coverage-check: install-gotestsum ensure-jstangle
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
coverage-combined: install-gotestsum ensure-jstangle
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
ACCESS_LAB_DIR=$(VULN_APPS_DIR)/access-lab

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
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml up -d --build
	@echo "$(PREFIX) Vulnerable Nginx: http://$$(docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml port nginx 5000)"

vulnerable-nginx-down:
	@echo "$(PREFIX) Stopping detectify Vulnerable Nginx..."
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml down -v

vulnerable-nginx-logs:
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml logs -f

vulnerable-nginx-status:
	docker compose -f $(VULN_NGINX_DIR)/docker-compose.yaml ps

# --- access-lab (durable-autopilot auth/IDOR/BAC demo) ---

access-lab-up:
	@echo "$(PREFIX) Starting access-lab (deliberately vulnerable)..."
	docker compose -f $(ACCESS_LAB_DIR)/docker-compose.yml up -d --build
	@echo "$(PREFIX) access-lab: http://127.0.0.1:9899  (wiener/peter, carlos/hunter2, admin/admin123)"

access-lab-down:
	@echo "$(PREFIX) Stopping access-lab..."
	docker compose -f $(ACCESS_LAB_DIR)/docker-compose.yml down -v

access-lab-logs:
	docker compose -f $(ACCESS_LAB_DIR)/docker-compose.yml logs -f

access-lab-status:
	docker compose -f $(ACCESS_LAB_DIR)/docker-compose.yml ps

# Point vigolium at the codex (OpenAI) OAuth agent backend. Assumes you have
# already run `codex login` (or `codex exec -m gpt-5.4 'hola'`
# works). Defaults to the cheaper gpt-5.4 model to keep smoke-test
# cost down. This only writes config — it does not make a paid call.
setup-agent-codex:
	@echo "$(PREFIX) Configuring the codex (openai-codex-oauth) agent backend..."
	@echo "$(PREFIX) Prereq: 'codex exec -m gpt-5.4 hola' must already work (run 'codex login' first)."
	vigolium config set agent.olium.provider openai-codex-oauth
	vigolium config set agent.olium.oauth_cred_path ~/.codex/auth.json
	vigolium config set agent.olium.model gpt-5.4
	@echo "$(PREFIX) done. Verify with: vigolium ol -p 'what model are you running'"

# Durable-autopilot SMOKE tests (not deterministic e2e tests): run the REAL
# agent (a live, PAID LLM run under your configured agent.olium credentials)
# against a vulnerable target, logging in and hunting IDOR / BAC / XSS / mass-
# assignment — the auth-gated, multi-step, browser classes a native scan can't
# reach. Print the exact agent command + the actual input before running.
#
#   !!! COSTS MONEY. Requires `make setup-agent-codex` (or another configured
#   !!! agent.olium provider) first. Bounded by MAX_DURATION (default 15m).
#
# Override via env, e.g.:
#   MODEL=gpt-5.5 MODE=shadow MAX_DURATION=8m make test-smoke-autopilot
test-smoke-autopilot: build
	@echo "$(PREFIX) Durable-autopilot access-lab SMOKE test (REAL, PAID agent run)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=access-lab bash test/smoke-test/smoke-autopilot.sh

# Same REAL, PAID autopilot run as test-smoke-autopilot, but driven through the
# REST API instead of the CLI: the script boots `vigolium server`, POSTs
# /api/agent/run/autopilot, and polls /api/agent/status/:id to completion — the
# operator/workbench path end-to-end. Same cost profile; TRANSPORT overridable.
test-smoke-autopilot-rest: build
	@echo "$(PREFIX) Durable-autopilot access-lab SMOKE test via the REST API (REAL, PAID agent run)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=access-lab TRANSPORT=rest bash test/smoke-test/smoke-autopilot.sh

# Prior-context / --burp-bridge-url simulation: seed the throwaway DB with a
# native scan first, then run autopilot --no-prescan --prior-context full so it
# mines that prior traffic instead of starting from scratch. Asserts the
# "Prior context:" brief fired. Same cost profile as test-smoke-autopilot.
test-smoke-autopilot-prior: build
	@echo "$(PREFIX) Autopilot prior-context / --burp-bridge-url SMOKE test (REAL, PAID; seeds the DB first)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=access-lab SEED_PRIOR=1 bash test/smoke-test/smoke-autopilot.sh

# Live PortSwigger demo shop (external target, carlos/hunter2). Outward-facing +
# paid — only run against a target you are authorized to test.
test-smoke-autopilot-ginandjuice: build
	@echo "$(PREFIX) Durable-autopilot SMOKE test against ginandjuice.shop (REAL, PAID, EXTERNAL)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=ginandjuice bash test/smoke-test/smoke-autopilot.sh

# Local OWASP crAPI (brings the stack up; provisions a login account best-effort).
test-smoke-autopilot-crapi: build crapi-up
	@echo "$(PREFIX) Provisioning a crAPI account (best-effort) ..."
	@curl -s -m 15 -X POST http://127.0.0.1:8888/identity/api/auth/signup \
		-H 'Content-Type: application/json' \
		-d '{"name":"smoke","email":"smoke@crapi.test","number":"4088888888","password":"Smoke123!"}' >/dev/null 2>&1 || true
	@echo "$(PREFIX) Durable-autopilot SMOKE test against crAPI (REAL, PAID agent run)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=crapi CREDS=smoke@crapi.test/Smoke123! bash test/smoke-test/smoke-autopilot.sh

# Local OWASP Juice Shop (brings it up; registers a login account best-effort).
test-smoke-autopilot-juiceshop: build juiceshop-up
	@echo "$(PREFIX) Registering a Juice Shop account (best-effort) ..."
	@curl -s -m 15 -X POST http://127.0.0.1:3000/api/Users \
		-H 'Content-Type: application/json' \
		-d '{"email":"smoke@juice-sh.op","password":"Smoke123!","passwordRepeat":"Smoke123!"}' >/dev/null 2>&1 || true
	@echo "$(PREFIX) Durable-autopilot SMOKE test against Juice Shop (REAL, PAID agent run)..."
	VIGOLIUM_BIN=$(CURDIR)/bin/vigolium PROFILE=juiceshop CREDS=smoke@juice-sh.op/Smoke123! bash test/smoke-test/smoke-autopilot.sh

# jstangle binary management
# update-jstangle and ensure-jstangle are already declared .PHONY at the top.
.PHONY: verify-jstangle-fresh build-jstangle-current build-jstangle-target ensure-jstangle-dist pack-jstangle pack-jstangle-host
JSTANGLE_SRC_DIR=platform/jstangle/bin
JSTANGLE_DST_DIR=internal/resources/deparos/jstangle

# jstangle embedded resources (internal/resources)
JSTANGLE_RES_SRC_DIR=platform/jstangle/bin
JSTANGLE_RES_DST_DIR=internal/resources/deparos/jstangle
JSTANGLE_RES_BINS=jstangle-darwin-amd64 jstangle-darwin-arm64 jstangle-linux-amd64 jstangle-linux-arm64 jstangle-windows-amd64.exe
JSTANGLE_RES_TARGETS=darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64

# Helpers are embedded zstd-compressed (<blob>.zst) with a pin file (<blob>.pin)
# recording the sha256/size of the uncompressed executable; the raw blobs stay
# in place for the --capabilities and fingerprint gates. blobpack is
# content-addressed, so re-running it on an unchanged blob only re-hashes it.
BLOBPACK=$(GORUN) ./internal/tools/blobpack

# Build every release helper from source and copy binaries.
update-jstangle:
	@echo "$(PREFIX) Building jstangle from source..."
	cd platform/jstangle && bun install --linker isolated --ignore-scripts && bun run build:bin
	@echo "$(PREFIX) Copying jstangle binaries to $(JSTANGLE_DST_DIR)..."
	@mkdir -p $(JSTANGLE_DST_DIR)
	@cp -R $(JSTANGLE_SRC_DIR)/* $(JSTANGLE_DST_DIR)/
	@$(MAKE) --no-print-directory pack-jstangle
	@echo "$(PREFIX) jstangle release binaries updated"

# Build and stage only the current host helper. Ordinary tests and development
# do not need to spend time producing four binaries that cannot run locally.
build-jstangle-current:
	@set -e; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; esac; \
	name="jstangle-$$os-$$arch"; \
	cd platform/jstangle; \
	bun install --linker isolated --ignore-scripts; \
	bun run build:bin:host; \
	cd ../..; \
	mkdir -p $(JSTANGLE_RES_DST_DIR); \
	cp "$(JSTANGLE_SRC_DIR)/$$name" "$(JSTANGLE_RES_DST_DIR)/$$name"; \
	$(MAKE) --no-print-directory pack-jstangle JSTANGLE_TARGET=$$os-$$arch

# Build and stage the jstangle helper for ONE target triple, e.g.
#     make build-jstangle-target JSTANGLE_TARGET=windows-amd64
# The cross-compile CI job needs the target platform's binary present to satisfy
# its go:embed (internal/resources/deparos/embed_jstangle_<os>_<arch>.go) but has
# no reason to spend time on the other four.
build-jstangle-target:
	@set -e; \
	target="$(JSTANGLE_TARGET)"; \
	if [ -z "$$target" ]; then \
		echo "\033[31m[!] usage: make build-jstangle-target JSTANGLE_TARGET=<os>-<arch>\033[0m"; \
		exit 1; \
	fi; \
	name="jstangle-$$target"; \
	case "$$target" in windows-*) name="$$name.exe" ;; esac; \
	cd platform/jstangle; \
	bun install --linker isolated --ignore-scripts; \
	mkdir -p bin; \
	bun run scripts/build-binaries.ts --target=$$target; \
	cd ../..; \
	mkdir -p $(JSTANGLE_RES_DST_DIR); \
	cp "$(JSTANGLE_SRC_DIR)/$$name" "$(JSTANGLE_RES_DST_DIR)/$$name"; \
	$(MAKE) --no-print-directory pack-jstangle JSTANGLE_TARGET=$$target; \
	echo "$(PREFIX) Staged $$name for cross-compile"

# Compress staged jstangle helpers for go:embed: JSTANGLE_TARGET=<os>-<arch>
# packs one (failing if its raw blob is missing), otherwise every raw blob
# present is packed. The source fingerprint is recorded in the pin when the
# blob carries it, which keeps it visible in the vigolium binary for the npm
# release gate (build/npm/build.mjs) now that the blob bytes are compressed.
pack-jstangle:
	@set -e; \
	source_hash=$$(cd platform/jstangle 2>/dev/null && bun scripts/source-fingerprint.ts 2>/dev/null || true); \
	targets="$(JSTANGLE_TARGET)"; \
	[ -n "$$targets" ] || targets="$(JSTANGLE_RES_TARGETS)"; \
	for target in $$targets; do \
		name="jstangle-$$target"; \
		case "$$target" in windows-*) name="$$name.exe" ;; esac; \
		raw="$(JSTANGLE_RES_DST_DIR)/$$name"; \
		if [ ! -f "$$raw" ]; then \
			if [ -n "$(JSTANGLE_TARGET)" ]; then \
				echo "\033[31m[!] $$raw is missing; build it with 'make build-jstangle-target JSTANGLE_TARGET=$$target'\033[0m"; \
				exit 1; \
			fi; \
			continue; \
		fi; \
		$(BLOBPACK) -in "$$raw" -platform "$$(echo $$target | tr - /)" $${source_hash:+-marker "$$source_hash"}; \
	done

# Pack the host helper only when its raw blob exists. Every `make build`
# runs this so a checkout whose raw helper predates compression (or a CI
# cache that restored only the raw blob) still has the .zst go:embed needs.
pack-jstangle-host:
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; esac; \
	if [ -f "$(JSTANGLE_RES_DST_DIR)/jstangle-$$os-$$arch" ]; then \
		$(MAKE) --no-print-directory pack-jstangle JSTANGLE_TARGET=$$os-$$arch; \
	fi

# Pre-test step: compare the executable's compiled source fingerprint and
# protocol contract with the current TypeScript tree. A source edit that keeps
# the same flags must still invalidate the helper.
ensure-jstangle:
	@set -e; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; esac; \
	host_bin="$(JSTANGLE_RES_DST_DIR)/jstangle-$$os-$$arch"; \
	source_hash=$$(cd platform/jstangle && bun scripts/source-fingerprint.ts); \
	needs_build=0; \
	if [ ! -x "$$host_bin" ] || [ $$(wc -c < "$$host_bin" 2>/dev/null || echo 0) -lt 1024 ]; then \
		needs_build=1; \
	else \
		caps=$$("$$host_bin" --capabilities 2>/dev/null || true); \
		printf '%s' "$$caps" | grep -Fq '"protocolVersion":2' || needs_build=1; \
		printf '%s' "$$caps" | grep -Fq "\"sourceHash\":\"$$source_hash\"" || needs_build=1; \
		printf '%s' "$$caps" | grep -Fq '"profiles"' || needs_build=1; \
	fi; \
	if [ $$needs_build -eq 1 ]; then \
		echo "$(PREFIX) jstangle host helper missing or stale; rebuilding..."; \
		$(MAKE) --no-print-directory build-jstangle-current; \
	else \
		echo "$(PREFIX) jstangle host helper is fresh ($$source_hash)"; \
		$(MAKE) --no-print-directory pack-jstangle JSTANGLE_TARGET=$$os-$$arch; \
	fi

verify-jstangle-fresh:
	@$(MAKE) --no-print-directory ensure-jstangle

# Release gate: every embedded jstangle blob must be built from the CURRENT
# TypeScript tree, not just the host's.
#
# `ensure-jstangle` only checks and rebuilds the HOST blob, because that is all
# tests and local development can run. Nothing else verified the other four, and
# no release target depended on jstangle at all — so a change under
# platform/jstangle/ that ran through `make test` would rebuild only the host
# blob, and the release would ship four stale blobs alongside one fresh one.
# That shipped in 0.4.9: jstangle-darwin-arm64 carried the new source while
# linux-amd64, linux-arm64, darwin-amd64 and windows-amd64 were months behind,
# so the release's jstangle work reached macOS arm64 users only.
#
# The blobs for other platforms cannot be executed here, so freshness is read
# the one way that works cross-platform: bun compiles the source fingerprint
# into the executable as a literal string (the same value `--capabilities`
# reports), so a plain byte search for the current fingerprint confirms which
# tree a blob was built from without running it.
ensure-jstangle-dist:
	@set -e; \
	source_hash=$$(cd platform/jstangle && bun scripts/source-fingerprint.ts); \
	stale=""; \
	for name in $(JSTANGLE_RES_BINS); do \
		bin="$(JSTANGLE_RES_DST_DIR)/$$name"; \
		if [ ! -f "$$bin" ] || ! LC_ALL=C grep -q -a -F "$$source_hash" "$$bin"; then \
			stale="$$stale $$name"; \
		fi; \
	done; \
	if [ -n "$$stale" ]; then \
		echo "$(PREFIX) jstangle blobs missing or stale for$$stale — rebuilding all targets..."; \
		$(MAKE) --no-print-directory update-jstangle; \
		for name in $(JSTANGLE_RES_BINS); do \
			bin="$(JSTANGLE_RES_DST_DIR)/$$name"; \
			if [ ! -f "$$bin" ] || ! LC_ALL=C grep -q -a -F "$$source_hash" "$$bin"; then \
				echo "\033[31m[!] $$name still does not carry the current source fingerprint ($$source_hash) after a rebuild.\033[0m"; \
				echo "\033[31m    Refusing to release a binary with a stale embedded jstangle.\033[0m"; \
				exit 1; \
			fi; \
		done; \
	fi; \
	$(MAKE) --no-print-directory pack-jstangle; \
	for name in $(JSTANGLE_RES_BINS); do \
		pin="$(JSTANGLE_RES_DST_DIR)/$$name.pin"; \
		if ! grep -q -F "\"source_hash\": \"$$source_hash\"" "$$pin" 2>/dev/null; then \
			echo "\033[31m[!] $$pin does not pin the current source fingerprint ($$source_hash).\033[0m"; \
			echo "\033[31m    The embedded (compressed) jstangle would not match the raw blob checked above.\033[0m"; \
			exit 1; \
		fi; \
	done; \
	echo "$(PREFIX) jstangle blobs for all targets built from current source ($$source_hash)"

# vigolium-audit security audit binary management.
# Source lives under platform/vigolium-audit/. `bun run build` produces a host
# binary at platform/vigolium-audit/build/dist/vigolium-audit-<os>-<arch>; we
# copy it to pkg/audit/bin/_bin/vigolium-audit, which is consumed by go:embed
# at vigolium build time. Cross-compile note: the embed is host-only — to
# cross-compile vigolium, stage the matching vigolium-audit-<os>-<arch> blob
# at the same path before running the cross GOOS/GOARCH build.
AUDIT_TS_DIR=platform/vigolium-audit
AUDIT_BIN_DST_DIR=pkg/audit/bin/_bin
# Base path of the staged helper: stage-audit-blob.sh writes
# $(AUDIT_BIN_HOST).zst and $(AUDIT_BIN_HOST).pin (never the raw executable,
# which `go:embed all:_bin` would embed uncompressed).
AUDIT_BIN_HOST=$(AUDIT_BIN_DST_DIR)/vigolium-audit
AUDIT_HOST_GOOS=$(shell uname -s | tr '[:upper:]' '[:lower:]')
AUDIT_HOST_GOARCH=$(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

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
# windows is x64-only: Bun has no bun-windows-arm64 compile target.
AUDIT_BIN_TARGETS=darwin-arm64 darwin-x64 linux-arm64 linux-x64 windows-x64
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
		case "$$target" in windows-*) bin="$$bin.exe" ;; esac; \
		if [ ! -x "$$bin" ]; then \
			echo "\033[31m[!] vigolium-audit binary not produced at $$bin\033[0m"; \
			exit 1; \
		fi; \
		echo "  $$target  $$(wc -c < "$$bin" | tr -d ' ') bytes"; \
	done
	@bash build/scripts/stage-audit-blob.sh $(AUDIT_HOST_GOOS) $(AUDIT_HOST_GOARCH)
	@echo "$(PREFIX) Cross-compile artifacts available under $(AUDIT_DIST_DIR)/"

# Pre-build step: make sure _bin holds the HOST's packed helper. The
# `go:embed all:_bin` pattern accepts an empty/stub _bin directory at build
# time — this guard ensures the runtime extract finds a real binary instead of
# failing with ErrBinaryMissing. A raw _bin/vigolium-audit left by a checkout
# that predates compression is repacked (or dropped when it is not a host
# blob); a missing or foreign-platform pin is restaged from the dist blob, and
# only rebuilt from source when that is absent too.
ensure-audit:
	@set -e; \
	f="$(AUDIT_BIN_HOST)"; \
	host="$(AUDIT_HOST_GOOS)/$(AUDIT_HOST_GOARCH)"; \
	if [ -f "$$f" ]; then \
		echo "$(PREFIX) Repacking raw $$f (the helper is now embedded zstd-compressed)..."; \
		$(BLOBPACK) -in "$$f" -out "$$f" -platform "$$host" || rm -f "$$f.zst" "$$f.pin"; \
		rm -f "$$f"; \
	fi; \
	pinned() { [ -s "$$f.zst" ] && grep -q -F "\"platform\": \"$$host\"" "$$f.pin" 2>/dev/null; }; \
	if ! pinned; then \
		echo "$(PREFIX) vigolium-audit helper missing, stub or not built for $$host; staging..."; \
		$(MAKE) --no-print-directory restage-host-audit; \
		pinned || $(MAKE) update-audit; \
	fi

# Alias for ensure-audit used by build targets — kept short for readability.
build-audit: update-audit

# Ensure ALL cross-compile vigolium-audit blobs exist under the dist dir.
# The release path cross-compiles every target from one tree; the goreleaser
# per-target pre-hook (build/scripts/stage-audit-blob.sh) stages the matching
# blob into _bin/ before each build, so all four source blobs must be present.
# Rebuilds via update-audit only when a target is missing (cheap when warm).
ensure-audit-dist:
	@missing=0; \
	for target in $(AUDIT_BIN_TARGETS); do \
		bin="$(AUDIT_DIST_DIR)/vigolium-audit-$$target"; \
		case "$$target" in windows-*) bin="$$bin.exe" ;; esac; \
		if [ ! -x "$$bin" ]; then missing=1; fi; \
	done; \
	if [ "$$missing" = "1" ]; then \
		echo "$(PREFIX) vigolium-audit cross-compile blobs missing, building all targets..."; \
		$(MAKE) update-audit; \
	else \
		echo "$(PREFIX) vigolium-audit cross-compile blobs present in $(AUDIT_DIST_DIR)"; \
	fi

# Restore the host-platform vigolium-audit blob into the shared go:embed path.
# The per-target staging (stage-audit-blob.sh) overwrites _bin/vigolium-audit
# with each cross target's blob, so a release leaves it on the LAST-built
# (non-host) blob. That file is gitignored, so the drift is silent — and a
# later `make build`/`make test` would embed the wrong-platform blob (caught
# only at runtime by verifyBlobForHost). Release targets call this at the end
# to leave the working tree with the host blob. No-op when the host dist blob
# is absent (fresh tree); ensure-audit-dist guarantees it exists in the release
# flow.
restage-host-audit:
	@host_bin="$(AUDIT_DIST_DIR)/vigolium-audit-$(AUDIT_HOST_GOOS)-$$(echo $(AUDIT_HOST_GOARCH) | sed 's/amd64/x64/')"; \
	if [ -f "$$host_bin" ]; then \
		bash build/scripts/stage-audit-blob.sh $(AUDIT_HOST_GOOS) $(AUDIT_HOST_GOARCH); \
		echo "$(PREFIX) Restored host vigolium-audit blob ($(AUDIT_HOST_GOOS)/$(AUDIT_HOST_GOARCH)) to $(AUDIT_BIN_HOST).zst"; \
	fi

# Opt-in lazy vigolium-audit (`-tags audit_external`): no helper is embedded;
# the binary downloads the pinned helper on first use from
# VIGOLIUM_AUDIT_BASE_URL (or AUDIT_EXTERNAL_BASE_URL baked in at link time),
# https only, sha256-verified. Default builds keep embedding because no CDN
# hosts the helpers yet. audit-external-pins writes the gitignored
# pkg/audit/bin/pins_gen.go and the upload assets
# $(AUDIT_EXTERNAL_ASSET_DIR)/vigolium-audit_<sha12>_<os>_<arch>.zst.
AUDIT_EXTERNAL_ASSET_DIR=build/dist-helpers
AUDIT_EXTERNAL_BASE_URL ?=
.PHONY: audit-external-pins build-audit-external
audit-external-pins: ensure-audit-dist
	@bash build/scripts/stage-audit-blob.sh --pins $(AUDIT_EXTERNAL_ASSET_DIR)

# Writes bin/vigolium-audit-external; not installed to $(GOPATH_BIN).
build-audit-external: audit-external-pins pack-jstangle-host
	@echo "$(PREFIX) Building $(BINARY_NAME) with -tags audit_external..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -tags audit_external -ldflags "$(LDFLAGS_INNER) -X github.com/vigolium/vigolium/pkg/audit/bin.defaultBaseURL=$(AUDIT_EXTERNAL_BASE_URL)" -o $(BINARY_DIR)/$(BINARY_NAME)-audit-external ./cmd/vigolium
	@echo "$(PREFIX) Binary: $(BINARY_DIR)/$(BINARY_NAME)-audit-external (upload $(AUDIT_EXTERNAL_ASSET_DIR)/*.zst to the base URL)"

# Regenerate the native secret-detection rule catalog (pkg/secretscan/catalog.json)
# from the pinned kingfisher rule set. Requires network + git.
# (The gitleaks/betterleaks family was removed as noisy and redundant with
# kingfisher's better-anchored provider rules.)
KINGFISHER_VERSION ?= v1.106.0

.PHONY: update-secret-rules
update-secret-rules:
	@echo "$(PREFIX) Regenerating secret catalog (kingfisher $(KINGFISHER_VERSION))..."
	@set -e; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	echo "  fetching kingfisher rules ($(KINGFISHER_VERSION))..."; \
	git clone --quiet --depth 1 --branch $(KINGFISHER_VERSION) https://github.com/mongodb/kingfisher "$$tmp/kingfisher"; \
	go run ./pkg/secretscan/secretgen \
		-kingfisher "$$tmp/kingfisher/crates/kingfisher-rules/data/rules" \
		-kingfisher-version $(KINGFISHER_VERSION) \
		-out pkg/secretscan/catalog.json \
		-examples-out pkg/secretscan/testdata/examples.json
	@echo "$(PREFIX) Wrote pkg/secretscan/catalog.json + pkg/secretscan/testdata/examples.json"

# Copy fresh UI builds into embedded public/ paths.
# Only public/static-reports/template.html is generated here; its sibling
# report-template.html is hand-maintained and read straight out of the embed
# by pkg/output/format_report.go.
update-ui:
	@echo "$(PREFIX) Building static report template..."
	@cd platform/static-reports && bun install && bun run build
	@cp platform/static-reports/dist/template.html public/static-reports/template.html
	@echo "$(PREFIX) Building workbench UI..."
	@cd platform/vigolium-workbench && bun install && bun run build
	@echo "$(PREFIX) Updating dashboard UI..."
	@if [ ! -f platform/vigolium-workbench/dist/index.html ]; then \
		echo "\033[31m[!] workbench dist/ has no index.html - refusing to replace public/ui/\033[0m"; \
		exit 1; \
	fi
	@rm -rf public/ui/
	@mkdir -p public/ui/
	@cp -r platform/vigolium-workbench/dist/* public/ui/
	@echo "$(PREFIX) UI assets updated"

# Sync platform sub-repos to standalone repos
sync-platform:
	@bash build/scripts/sync-platform.sh

# Standalone skills checkout (github.com/vigolium/skills), expected as a sibling
# of the vigolium repo. Override on the command line, e.g.
# `make sync-skills SKILLS_UPSTREAM=/path/to/skills`.
SKILLS_UPSTREAM ?= ../skills
SKILLS_SRC=public/skills

# Mirror public/skills/ into the standalone skills repo. Unlike sync-platform
# (which does every sub-repo, then commits and pushes), this touches only the
# skills tree and leaves the commit to you. Run `make skill-flags` first if the
# CLI flag surface changed, so flags.generated.md ships current.
# Warns and exits 0 when the checkout is absent, so CI invocations don't fail
# just because the sibling clone isn't present.
sync-skills:
	@set -e; \
	if [ ! -d "$(SKILLS_UPSTREAM)" ]; then \
		echo "\033[33m[!] skills checkout not found at $(SKILLS_UPSTREAM); skipping sync.\033[0m"; \
		echo "    Clone github.com/vigolium/skills as a sibling of this repo, or override with"; \
		echo "    'make sync-skills SKILLS_UPSTREAM=/path/to/skills'."; \
		exit 0; \
	fi; \
	echo "$(PREFIX) Syncing $(SKILLS_SRC)/ -> $(SKILLS_UPSTREAM)/"; \
	rsync -a --delete --exclude='.git' --exclude='.DS_Store' \
		"$(SKILLS_SRC)/" "$(SKILLS_UPSTREAM)/"; \
	echo "$(PREFIX) Sync complete. Review and commit in $(SKILLS_UPSTREAM):"; \
	git -C "$(SKILLS_UPSTREAM)" status --short || true

# Docker parameters
DOCKER_IMAGE=vigolium
DOCKER_PROD_IMAGE=vigolium-prod
DOCKER_TAG?=$(VERSION)
DOCKER_REGISTRY?=
DOCKER_HUB_IMAGE?=j3ssie/vigolium
# Target platforms for the multi-arch publish. Override to build a subset,
# e.g. DOCKER_PLATFORMS=linux/amd64.
DOCKER_PLATFORMS?=linux/amd64,linux/arm64
DOCKER_BUILDX_BUILDER?=vigolium-builder

# Build Docker image
docker: docker-build

docker-build: ensure-audit-dist
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

# Ensure a buildx builder backed by the docker-container driver exists and is
# bootstrapped. The default `docker` driver only builds for the host platform
# and cannot emit multi-arch manifests, so multi-platform publishing needs a
# dedicated builder. Idempotent: reuses the builder if it already exists.
docker-buildx-setup:
	@if ! docker buildx inspect $(DOCKER_BUILDX_BUILDER) >/dev/null 2>&1; then \
		echo "$(PREFIX) Creating buildx builder $(DOCKER_BUILDX_BUILDER)..."; \
		docker buildx create --name $(DOCKER_BUILDX_BUILDER) --driver docker-container --use >/dev/null; \
	else \
		docker buildx use $(DOCKER_BUILDX_BUILDER) >/dev/null; \
	fi
	@docker buildx inspect --bootstrap $(DOCKER_BUILDX_BUILDER) >/dev/null

# Build the Docker image for every platform in DOCKER_PLATFORMS (linux/amd64 +
# linux/arm64 by default) and publish the multi-arch manifest to Docker Hub as
# j3ssie/vigolium (override the repo with DOCKER_HUB_IMAGE=). Pushes both the
# version tag and :latest in a single buildx run — multi-platform images can't
# be loaded into the local image store, so build and push happen together.
# Requires `docker login` beforehand, and QEMU/binfmt for emulating the
# non-host architecture (bundled with Docker Desktop; on plain Linux run
# `docker run --privileged --rm tonistiigi/binfmt --install all` once).
docker-publish: ensure-audit-dist ensure-jstangle-dist docker-buildx-setup
	@echo "$(PREFIX) Building and publishing multi-arch image to Docker Hub: $(DOCKER_HUB_IMAGE) ($(DOCKER_PLATFORMS))..."
	docker buildx build \
		--platform $(DOCKER_PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_HUB_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_HUB_IMAGE):latest \
		-f build/Dockerfile \
		--push .
	@echo "$(PREFIX) Published $(DOCKER_HUB_IMAGE):$(DOCKER_TAG) and $(DOCKER_HUB_IMAGE):latest for $(DOCKER_PLATFORMS)"

# GoReleaser snapshot (local build without publishing)
GORELEASER_VERSION=$(patsubst v%,%,$(VERSION))

# --parallelism 1 is REQUIRED: the per-target pre-hook stages the matching
# vigolium-audit blob into a single shared go:embed path, so cross builds must
# run sequentially or they race and embed the wrong-arch blob.
snapshot: ensure-audit-dist ensure-jstangle-dist
	@echo "$(PREFIX) Building snapshot release..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) goreleaser --verbose release --snapshot --clean --parallelism 1
	@$(MAKE) restage-host-audit

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

# Stamp a public CDN installer copy with the public/stable R2 prefix so the
# uploaded copy at cdn.vigolium.com/vigolium-release/install.sh resolves
# binaries from the matching prefix without mutating the source npm installer.
prepare-public-scripts:
	@echo "$(PREFIX) Updating public release scripts..."
	@cp build/scripts/install.sh build/public-install.sh
	@perl -0pi -e 's|^BASE_URL="[^"]*"|BASE_URL="$(PUBLIC_INSTALL_BASE_URL)"|m; s|^INSTALL_MODE="[^"]*"|INSTALL_MODE="\$${VIGOLIUM_INSTALL_MODE:-cdn}"|m' build/public-install.sh
	@chmod +x build/public-install.sh
	@echo "$(PREFIX) Public release scripts updated for $(PUBLIC_INSTALL_BASE_URL)"

# Generate build/dist/metadata.json from the Go version file
generate-metadata:
	@mkdir -p build/dist
	@echo "$(PREFIX) Generating metadata.json (version=$(VERSION), commit=$(COMMIT_HASH))..."
	@printf '{\n  "version": "%s",\n  "commit": "%s",\n  "build_time": "%s"\n}\n' \
		"$(VERSION)" "$(COMMIT_HASH)" "$(BUILD_TIME)" > build/dist/metadata.json

# Gate a dist dir before any upload: one correctly-versioned archive per
# PUBLIC_TARGETS entry (goreleaser builds the same set; see .goreleaser.yaml),
# checksums.txt complete and verifying, metadata.json pointing at $(VERSION).
# Local only, no network. Usage: make release-verify DIST=build/dist
RELEASE_DIST?=build/dist
release-verify:
	@VERSION="$(VERSION)" TARGETS="$(PUBLIC_TARGETS)" REQUIRE="$(RELEASE_REQUIRE)" \
		bash build/scripts/release-verify.sh "$(or $(DIST),$(RELEASE_DIST))"

# Sign a dist dir's checksums.txt with the offline minisign release key,
# writing checksums.txt.minisig beside it. One signature covers every archive
# through its sha256 line. The trusted comment names the version: `vigolium
# update` refuses a signature whose comment names any other release, so an old
# signed checksums.txt cannot be replayed under a new metadata.json. The
# matching public keys live in pkg/selfupdate/keys.go (current + next slot) and
# in the installers' MINISIGN_PUBKEY. Runs after release-verify, before any
# upload. The secret key comes from VIGOLIUM_MINISIGN_SECRET_KEY (the base64
# line of the .key file, kept out of the repo in a shell env file) when set,
# else from the MINISIGN_KEY file. The fresh signature is verified with
# VIGOLIUM_MINISIGN_PUBLIC_KEY when set, else with MINISIGN_PUB if it exists.
# Usage: make release-sign DIST=build/dist [MINISIGN_KEY=…] [MINISIGN_PUB=…]
MINISIGN_KEY?=$(HOME)/.minisign/vigolium.key
MINISIGN_PUB?=$(HOME)/.minisign/vigolium.pub
release-sign:
	@command -v minisign >/dev/null 2>&1 || { echo "\033[31m[!] release-sign: minisign is required (https://jedisct1.github.io/minisign/)\033[0m" >&2; exit 1; }
	@set -e; dist="$(or $(DIST),$(RELEASE_DIST))"; \
		[ -s "$$dist/checksums.txt" ] || { echo "\033[31m[!] release-sign: missing $$dist/checksums.txt\033[0m" >&2; exit 1; }; \
		key="$(MINISIGN_KEY)"; \
		if [ -n "$$VIGOLIUM_MINISIGN_SECRET_KEY" ]; then \
			key=$$(umask 077; mktemp); trap 'rm -f "$$key"' EXIT; \
			printf 'untrusted comment: vigolium release key (from env)\n%s\n' "$$VIGOLIUM_MINISIGN_SECRET_KEY" > "$$key"; \
		fi; \
		[ -f "$$key" ] || { echo "\033[31m[!] release-sign: no secret key (set VIGOLIUM_MINISIGN_SECRET_KEY, or MINISIGN_KEY=… to a key file; tried $(MINISIGN_KEY))\033[0m" >&2; exit 1; }; \
		rm -f "$$dist/checksums.txt.minisig"; \
		echo "$(PREFIX) Signing $$dist/checksums.txt (vigolium $(VERSION))..."; \
		minisign -S -s "$$key" -m "$$dist/checksums.txt" -x "$$dist/checksums.txt.minisig" \
			-t "vigolium $(VERSION)" -c "vigolium $(VERSION) release checksums"; \
		if [ -n "$$VIGOLIUM_MINISIGN_PUBLIC_KEY" ]; then \
			minisign -V -q -P "$$VIGOLIUM_MINISIGN_PUBLIC_KEY" -m "$$dist/checksums.txt" -x "$$dist/checksums.txt.minisig"; \
			echo "$(PREFIX) Signature verified with VIGOLIUM_MINISIGN_PUBLIC_KEY"; \
		elif [ -f "$(MINISIGN_PUB)" ]; then \
			minisign -V -q -p "$(MINISIGN_PUB)" -m "$$dist/checksums.txt" -x "$$dist/checksums.txt.minisig"; \
			echo "$(PREFIX) Signature verified with $(MINISIGN_PUB)"; \
		fi

# Delete old vigolium_* archives from an R2 prefix, keeping everything in the
# new checksums.txt plus the last RELEASE_KEEP versions (rollback window).
# Never touches install.sh/bootstrap.sh/metadata.json/checksums.txt. Runs only
# AFTER a successful upload. DRY_RUN=1 previews.
# Usage: make release-prune R2_DIR=r2/vigolium-dist/$(R2_PREFIX) DIST=build/dist
RELEASE_KEEP?=3
release-prune:
	@KEEP="$(RELEASE_KEEP)" DRY_RUN="$(DRY_RUN)" \
		bash build/scripts/release-prune.sh "$(or $(R2_DIR),r2/vigolium-dist/$(R2_PREFIX))" "$(or $(DIST),$(RELEASE_DIST))"

# GoReleaser release and upload to R2. Order matters: verify locally, upload
# archives + checksums + scripts, flip the version pointer (metadata.json)
# LAST, then prune old archives. Installers resolve the version from
# metadata.json first, so until the pointer flips they keep resolving the
# previous version, whose archives are still in place. Old archives are only
# pruned after the new release is fully live. The unit suite (incl. the static
# benchmark-definition lint) runs first: a red tree never ships.
release: test-unit prepare-release-scripts ensure-audit-dist ensure-jstangle-dist
	@echo "$(PREFIX) Building release..."
	VIGOLIUM_VERSION=$(GORELEASER_VERSION) goreleaser --verbose release --snapshot --clean --parallelism 1
	@$(MAKE) restage-host-audit
	@$(MAKE) generate-metadata
	@$(MAKE) release-verify DIST=build/dist RELEASE_REQUIRE="build/scripts/nightly-install.sh build/scripts/bootstrap.sh"
	@$(MAKE) release-sign DIST=build/dist
	@echo "$(PREFIX) Uploading to R2 (archives first, version pointer last)..."
	@set -e; \
		mc cp build/dist/*.tar.gz build/dist/*.zip r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/dist/checksums.txt build/dist/checksums.txt.minisig r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/scripts/bootstrap.sh r2/vigolium-dist/$(R2_PREFIX)/; \
		mc cp build/scripts/nightly-install.sh r2/vigolium-dist/$(R2_PREFIX)/install.sh; \
		mc cp build/dist/metadata.json r2/vigolium-dist/$(R2_PREFIX)/
	@echo "$(PREFIX) Release uploaded successfully!"
	@$(MAKE) release-prune R2_DIR=r2/vigolium-dist/$(R2_PREFIX) DIST=build/dist \
		|| echo "\033[33m[!] Prune of old archives failed; the release itself is live. Re-run: make release-prune\033[0m"

# Build cross-platform binaries, tar, checksum, and upload to the public/stable
# R2 prefix (cdn.vigolium.com/vigolium-release/). Mirrors `release` but keeps a
# separate output dir so the two targets do not stomp on each other.
public:
	@echo "\033[31m[!] Use 'make public-release' for public release uploads.\033[0m"
	@exit 1

public-release: prepare-public-scripts ensure-audit-dist ensure-jstangle-dist
	@echo "$(PREFIX) Building public artifacts for: $(PUBLIC_TARGETS)"
	@rm -rf $(PUBLIC_DIST_DIR)
	@mkdir -p $(PUBLIC_DIST_DIR)
	@for target in $(PUBLIC_TARGETS); do \
		GOOS=$${target%/*}; GOARCH=$${target#*/}; \
		bin_name="vigolium"; \
		if [ "$${GOOS}" = "windows" ]; then bin_name="vigolium.exe"; fi; \
		pkg_name="vigolium_$(PUBLIC_VERSION)_$${GOOS}_$${GOARCH}"; \
		stage_dir="$(PUBLIC_DIST_DIR)/$${pkg_name}"; \
		echo "$(PREFIX)   -> $${GOOS}/$${GOARCH}"; \
		mkdir -p $${stage_dir}; \
		bash build/scripts/stage-audit-blob.sh $${GOOS} $${GOARCH} || exit 1; \
		GOOS=$${GOOS} GOARCH=$${GOARCH} CGO_ENABLED=0 \
			$(GOBUILD) $(LDFLAGS) \
			-o $${stage_dir}/$${bin_name} ./cmd/vigolium \
			|| exit 1; \
		cp LICENSE THIRD_PARTY_NOTICES.md $${stage_dir}/ || exit 1; \
		if [ "$${GOOS}" = "windows" ]; then \
			(cd $${stage_dir} && zip -q -X ../$${pkg_name}.zip $${bin_name} LICENSE THIRD_PARTY_NOTICES.md) || exit 1; \
		else \
			COPYFILE_DISABLE=1 tar --no-xattrs -czf $(PUBLIC_DIST_DIR)/$${pkg_name}.tar.gz -C $${stage_dir} $${bin_name} LICENSE THIRD_PARTY_NOTICES.md \
				|| exit 1; \
		fi; \
		rm -rf $${stage_dir}; \
	done
	@$(MAKE) restage-host-audit
	@echo "$(PREFIX) Writing checksums.txt..."
	@cd $(PUBLIC_DIST_DIR) && \
		(command -v shasum >/dev/null 2>&1 && shasum -a 256 *.tar.gz *.zip > checksums.txt \
		 || sha256sum *.tar.gz *.zip > checksums.txt)
	@echo "$(PREFIX) Writing metadata.json..."
	@printf '{\n  "version": "%s",\n  "commit": "%s",\n  "build_time": "%s"\n}\n' \
		"$(VERSION)" "$(COMMIT_HASH)" "$(BUILD_TIME)" > $(PUBLIC_DIST_DIR)/metadata.json
	@$(MAKE) release-verify DIST=$(PUBLIC_DIST_DIR) RELEASE_REQUIRE="build/public-install.sh"
	@$(MAKE) release-sign DIST=$(PUBLIC_DIST_DIR)
	# Retain older versioned archives for installed package recipes and rollbacks.
	# Same ordering as `release`: archives first, version pointer (metadata.json) last.
	@echo "$(PREFIX) Uploading public artifacts to R2 (archives first, version pointer last)..."
	mc cp $(PUBLIC_DIST_DIR)/*.tar.gz $(PUBLIC_DIST_DIR)/*.zip r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	mc cp $(PUBLIC_DIST_DIR)/checksums.txt $(PUBLIC_DIST_DIR)/checksums.txt.minisig r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	mc cp build/public-install.sh r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/install.sh
	mc cp $(PUBLIC_DIST_DIR)/metadata.json r2/vigolium-dist/$(R2_PUBLIC_PREFIX)/
	@echo "$(PREFIX) Public release uploaded to $(PUBLIC_INSTALL_BASE_URL)/"

# Run the normal public release (build cross-platform tarballs + upload to R2),
# then publish those same artifacts to a GitHub release via
# build/scripts/github-release.sh. The release tag/title is the current version
# ($(VERSION)) — the script creates + pushes that git tag if it does not exist —
# and the body is that version's section pulled from CHANGELOG.md. Existing
# releases are never replaced: downstream package managers pin archive hashes.
github-release:
	@command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) is required." >&2; exit 1; }
	@if gh release view "$(VERSION)" >/dev/null 2>&1; then \
		echo "Release $(VERSION) already exists. Bump VERSION before publishing new binaries." >&2; exit 1; \
	fi
	@$(MAKE) public-release
	@VERSION="$(VERSION)" PUBLIC_DIST_DIR="$(PUBLIC_DIST_DIR)" bash build/scripts/github-release.sh

# Generate recipes from verified public archives. No builds or publishing.
.PHONY: packages packages-test packages-linux
packages:
	python3 build/packaging/generate.py --dist "$(PUBLIC_DIST_DIR)"

packages-test:
	python3 -m unittest discover -s build/packaging -p 'test_*.py'

# Requires `make packages` and nFPM on PATH. Builds both Linux architectures.
packages-linux:
	python3 build/packaging/build_native.py

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

# Reads a publish back from registry.npmjs.org — see the script header for why
# `npm publish` exiting 0 does not mean the version exists.
NPM_VERIFY=bash build/scripts/npm-verify-publish.sh

# "yes" when the goreleaser binaries are missing OR were built for a different
# version than pkg/cli/version.go ($(VERSION)) — i.e. stale after a version bump.
#
# Detected via the goreleaser archive name, NOT by grepping the binary: goreleaser
# names each archive `vigolium_<version>_<os>_<arch>.tar.gz` from the version it
# actually built (archives.name_template in .goreleaser.yaml) and `--clean` wipes
# build/dist at the start of every run, so the archive version is an authoritative
# record of what the binaries are. The old substring grep for "$(VERSION)" in the
# binary FALSE-MATCHED: a shipped binary carries newer version strings in its
# embedded content (a v0.2.2 build literally contains "v0.2.3" 12x), so the guard
# thought stale binaries were fresh and npm-publish shipped v0.2.2 binaries under
# the 0.2.3 npm version. Recursive (=) so it only runs when referenced by the
# npm-build/npm-pack guards, not on every `make` invocation.
NPM_NEEDS_BUILD=$(shell bins=$$(ls build/dist/vigolium_*_*/vigolium 2>/dev/null); arcs=$$(ls build/dist/vigolium_$(GORELEASER_VERSION)_*.tar.gz 2>/dev/null); if [ -z "$$bins" ] || [ -z "$$arcs" ]; then echo yes; else echo no; fi)

# Stage the npm packages from goreleaser output. Runs `make snapshot` first if
# the binaries are missing OR stale (built at a different version than
# pkg/cli/version.go), so a version bump never ships a mismatched binary.
npm-build:
	@if [ "$(NPM_NEEDS_BUILD)" = "yes" ]; then \
		echo "$(PREFIX) Binaries missing or stale for $(VERSION) — running 'make snapshot'..."; \
		$(MAKE) snapshot; \
	fi
	@echo "$(PREFIX) Staging npm packages (version $(GORELEASER_VERSION))..."
	@VIGOLIUM_VERSION=$(GORELEASER_VERSION) \
		VIGOLIUM_JSTANGLE_SOURCE_HASH=$$(cd platform/jstangle && bun scripts/source-fingerprint.ts) \
		node build/npm/build.mjs

# Stage + produce inspectable .tgz tarballs (npm pack) for each package.
npm-pack:
	@if [ "$(NPM_NEEDS_BUILD)" = "yes" ]; then \
		echo "$(PREFIX) Binaries missing or stale for $(VERSION) — running 'make snapshot'..."; \
		$(MAKE) snapshot; \
	fi
	@echo "$(PREFIX) Staging + packing npm tarballs (version $(GORELEASER_VERSION))..."
	@VIGOLIUM_VERSION=$(GORELEASER_VERSION) \
		VIGOLIUM_JSTANGLE_SOURCE_HASH=$$(cd platform/jstangle && bun scripts/source-fingerprint.ts) \
		node build/npm/build.mjs --pack
	@echo "$(PREFIX) Tarballs written to $(NPM_OUT_DIR)/"

# Publish to npm: platform packages FIRST (so the main package's
# optionalDependencies resolve), then the main package. Every run pins the
# `latest` dist-tag to the version being published (the main package is
# published as `latest` and `latest` is re-asserted + verified afterward), so
# `npm i -g @vigolium/vigolium` always installs this version.
#
# `npm publish` exiting 0 is NOT proof of publication: registry.npmjs.org
# answers with 202 Accepted and processes the tarball asynchronously, and a
# queued version can silently never land. That is how 0.4.6 shipped broken —
# darwin-arm64, linux-arm64 and windows-x64 each got a clean 202, never
# appeared, and left the main package pointing at optionalDependencies that
# 404. So every publish is read back from the registry before the next one
# goes out; a platform package that never lands stops the run *before* the
# main package is published, instead of after.
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
			if [ "$(DRY_RUN)" != "1" ] \
				&& curl -sS -o /dev/null -w '%{http_code}' -H 'Cache-Control: no-cache' \
					"https://registry.npmjs.org/@vigolium/vigolium/$(GORELEASER_VERSION)-$$ptag?cb=$$$$" \
					2>/dev/null | grep -q '^200$$'; then \
				echo "$(PREFIX)     already on registry — skipping"; \
				continue; \
			fi; \
			( cd "$$d" && npm publish --access public --tag "$$ptag" $$DRY ) \
				|| { echo "\033[31m[!] publish failed: $$ptag\033[0m"; exit 11; }; \
			if [ "$(DRY_RUN)" != "1" ]; then \
				$(NPM_VERIFY) version @vigolium/vigolium "$(GORELEASER_VERSION)-$$ptag" || exit 11; \
			fi; \
		done; \
		echo "$(PREFIX)   publishing $(NPM_OUT_DIR)/vigolium/ (main) [tag=latest]"; \
		( cd $(NPM_OUT_DIR)/vigolium && npm publish --access public --tag latest $$DRY ) \
			|| { echo "\033[31m[!] publish failed: main\033[0m"; exit 12; }; \
		if [ "$(DRY_RUN)" != "1" ]; then \
			$(NPM_VERIFY) version @vigolium/vigolium "$(GORELEASER_VERSION)" || exit 12; \
			echo "$(PREFIX)   pointing 'latest' dist-tag at $(GORELEASER_VERSION)"; \
			npm dist-tag add @vigolium/vigolium@$(GORELEASER_VERSION) latest \
				|| { echo "\033[31m[!] dist-tag add failed\033[0m"; exit 13; }; \
			$(NPM_VERIFY) dist-tag @vigolium/vigolium latest "$(GORELEASER_VERSION)" || exit 14; \
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
# Covers the deterministic artifacts: gofmt output, the go.mod/go.sum manifest,
# and the OpenAPI spec (both copies) regenerated by `make swagger`.
# (Binary assets — jstangle, the audit harness, UI bundles — are non-deterministic
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
	@echo "$(PREFIX) Verifying the Swagger spec is regenerated..."
	@tmp="$$(mktemp -d)"; \
	$(GORUN) ./internal/tools/swaggergen -out "$$tmp" || { rm -rf "$$tmp"; exit 1; }; \
	status=0; \
	for f in $(SWAGGER_CANONICAL) $(SWAGGER_EMBEDDED); do \
		if ! diff -q "$$f" "$$tmp/$$f" >/dev/null; then \
			echo "$(PREFIX) $$f is stale — run 'make swagger' and commit the result."; \
			status=1; \
		fi; \
	done; \
	rm -rf "$$tmp"; \
	exit $$status
	@echo "$(PREFIX) Generated/managed sources are in sync."

# Tidy dependencies
tidy:
	@echo "$(PREFIX) Tidying dependencies..."
	$(GOMOD) tidy

# Regenerate the published JSON Schemas (docs/schema) from the registered
# command, event and error shapes (pkg/contract). TestSchemaGolden fails until
# this is re-run after a contract change; review the diff before committing.
schema:
	@echo "$(PREFIX) Regenerating docs/schema..."
	VIGOLIUM_UPDATE_SCHEMA=1 $(GOTEST) -count=1 -run '^TestSchemaGolden$$' ./pkg/cli/
	@echo "$(PREFIX) Done. Review the diff before committing."

# Regenerate the coding-agent skill's flag reference from the cobra command
# tree. The file is committed so the embedded skill bundle stays self-contained;
# re-run this whenever a flag is added, renamed, or given a shorthand.
skill-flags:
	@echo "$(PREFIX) Regenerating skill flag reference..."
	$(GORUN) ./cmd/vigolium skills gen-flags
	@echo "$(PREFIX) Done. Review the diff before committing."

# Fail when the committed flag reference no longer matches the command tree.
# The generated file is what an agent reads to find out what exists, so a stale
# copy is not a cosmetic problem: it is the difference between a flag being
# discoverable and being invisible. The check is TestFlagsGeneratedIsCurrent,
# which renders the reference in-process (it also runs in `make test-unit`);
# this target is a wrapper for running it alone.
skill-flags-check:
	@echo "$(PREFIX) Checking skill flag reference is current..."
	@$(GOTEST) -count=1 -run '^TestFlagsGeneratedIsCurrent$$' ./pkg/cli/

# Helper scripts
SCRIPTS_DIR := internal/resources/scripts

# Download dependencies, build jstangle, and check Chromium
deps: update-jstangle
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

# Regenerate the Swagger spec: components.schemas are rebuilt from the Go types
# registered in pkg/server/swagger_types.go (paths and prose are hand-written in
# $(SWAGGER_CANONICAL) and kept), then written to both the canonical and the
# embedded copy. `make verify-generated` fails when either is stale.
swagger:
	@echo "$(PREFIX) Regenerating Swagger spec ($(SWAGGER_CANONICAL), $(SWAGGER_EMBEDDED))..."
	$(GORUN) ./internal/tools/swaggergen
	@echo "$(PREFIX) Swagger spec regenerated"

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
	@echo "    make build-all        Build for all platforms (linux, darwin, windows)"
	@echo "    make install          Install binaries to \$$GOPATH/bin"
	@echo "    make clean            Clean build artifacts"
	@echo ""
	@echo "\033[33m  TEST\033[0m"
	@echo "    make test             Run all tests"
	@echo "    make test-race        Run all tests with race detector"
	@echo "    make test-unit        Run unit tests (fast, no external deps)"
	@echo "    make test-integration Run integration tests (XSS gym benchmark)"
	@echo "    make test-browser-conformance  Browser crawler integration contracts (needs a local Chrome/Chromium)"
	@echo "    make test-benchmark   Run benchmark tests (alias for test-integration)"
	@echo "    make test-e2e         Run E2E tests (requires Docker)"
	@echo "    make test-e2e-api     Run API E2E tests only (server endpoints)"
	@echo "    make test-e2e-agent   Run Agent API E2E tests only (agent endpoints)"
	@echo "    make test-e2e-rest-scan  Native + agentic scan driven through the REST API (hermetic, no Docker/LLM)"
	@echo "    make test-e2e-postgres  Run PostgreSQL E2E tests (requires make postgres-up)"
	@echo "    make test-pg-full     Full PG validation cycle: e2e + canary (auto up/down)"
	@echo "    make test-canary      Run canary tests: DVWA, VAmPI, Juice Shop (Docker)"
	@echo "    make test-e2e-expect  Expectation kit: lab (hostile, no Docker) + live Docker targets"
	@echo "    make test-e2e-expect-lab   Expectation kit, lab half only (no Docker)"
	@echo "    make test-e2e-expect-live  Expectation kit, live Docker targets only"
	@echo "    make e2e-expect-lab   Serve the expectation lab standalone (LAB_ARGS='-port-base 18000 -log')"
	@echo "    make test-e2e-vampi   Run VAmPI canary tests only (SQLi)"
	@echo "    make test-e2e-dvwa    Run DVWA canary tests only (XSS, SQLi, LFI)"
	@echo "    make test-e2e-juiceshop  Run Juice Shop canary tests only"
	@echo "    make test-e2e-autonomous  Autonomous full-chain scan canary (Docker)"
	@echo "    make test-e2e-scorecard   Ground-truth coverage scorecard canary (Docker)"
	@echo "    make test-e2e-browser-fallback  Browser fallback test (Docker multi-arch)"
	@echo "    make test-e2e-piolium  Piolium audit e2e (requires pi + piolium installed)"
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
	@echo "\033[33m  SMOKE TESTS (real targets)\033[0m"
	@echo "    make sanity-check     Real-target REST API + GCS storage smoke test (needs jq/tar/python3 + network)"
	@echo "    make setup-agent-codex  Point agent.olium at the codex OAuth backend (prereq for autopilot smoke tests)"
	@echo "    make test-smoke-autopilot  Durable-autopilot access-lab smoke test  \033[31m(REAL, PAID agent run)\033[0m"
	@echo "    make test-smoke-autopilot-rest  Same run driven through the REST API (server + /api/agent/run/autopilot)  \033[31m(REAL, PAID)\033[0m"
	@echo "    make test-smoke-autopilot-prior  Seed DB, then autopilot --prior-context (--burp-bridge-url sim)  \033[31m(REAL, PAID)\033[0m"
	@echo "    make test-smoke-autopilot-ginandjuice  Autopilot vs ginandjuice.shop  \033[31m(REAL, PAID, EXTERNAL)\033[0m"
	@echo "    make test-smoke-autopilot-crapi        Autopilot vs OWASP crAPI       \033[31m(REAL, PAID; brings crapi up)\033[0m"
	@echo "    make test-smoke-autopilot-juiceshop    Autopilot vs OWASP Juice Shop  \033[31m(REAL, PAID; brings juiceshop up)\033[0m"
	@echo "                          (MODEL=/MODE=/MAX_DURATION= override; default bound 15m)"
	@echo ""
	@echo "\033[33m  DEVELOPMENT\033[0m"
	@echo "    make fmt              Format code"
	@echo "    make lint             Run golangci-lint"
	@echo "    make tidy             Tidy go.mod dependencies"
	@echo "    make deps             Download dependencies + ensure jstangle binaries"
	@echo "    make deps-chrome      Download Chromium browser archives from versions.go"
	@echo "    make deps-chrome-cft  Download only Chrome for Testing (PLATFORM=linux64)"
	@echo "    make deps-chrome-update  Update browser version+URL (NAME= PLATFORM= VERSION= URL=)"
	@echo "    make swagger          Regenerate Swagger schemas from Go types"
	@echo "    make update-ui        Copy fresh UI builds into public/ (report template + dashboard)"
	@echo "    make skill-flags      Regenerate the coding-agent skill's flag reference"
	@echo "    make sync-platform    Sync platform sub-repos to their standalone repos"
	@echo "    make sync-skills      Mirror public/skills/ into the sibling skills repo (no commit)"
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
	@echo "    make docker-publish   Build + publish multi-arch ($(DOCKER_PLATFORMS)) to Docker Hub ($(DOCKER_HUB_IMAGE))"
	@echo ""
	@echo "\033[33m  RELEASE\033[0m"
	@echo "    make snapshot         Build local snapshot release (no publish)"
	@echo "    make release          Build and upload nightly artifacts to R2 (cdn.vigolium.com/vigolium-nightly-release/)"
	@echo "    make public-release   Build cross-platform tarballs and upload to the public/stable R2 prefix (cdn.vigolium.com/vigolium-release/)"
	@echo "    make github-release   Publish a new version to R2 and GitHub (existing GitHub releases are never replaced)"
	@echo "    make packages         Verify public archives and generate AUR, DEB/RPM, Scoop, WinGet, Nix, and Snap recipes"
	@echo "    make packages-linux   Build DEB/RPM packages from generated recipes (requires nFPM)"
	@echo "    make packages-test    Run package generation and release protection tests"
	@echo "    make cdn-sync         Sync nightly scripts (install.sh, bootstrap.sh) to R2 CDN"
	@echo "    make bump-version     Bump pkg/cli/version.go (PART=patch|minor|major|pre|release, DRY_RUN=1)"
	@echo "    make npm-build        Stage @vigolium/vigolium npm packages into build/dist-npm/"
	@echo "    make npm-pack         npm-build + produce inspectable .tgz tarballs"
	@echo "    make npm-publish      Publish to npm; auth via ~/.npmrc (NPM_TOKEN env var)"
	@echo "                          (always pins latest->version; DRY_RUN=1 to preview)"
	@echo ""
