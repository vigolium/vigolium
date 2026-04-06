.PHONY: build build-embedded build-all build-ingestor snapshot release clean test test-unit test-integration test-e2e test-e2e-api test-e2e-agent test-e2e-postgres test-canary test-e2e-vampi test-e2e-dvwa test-e2e-juiceshop test-e2e-browser-fallback test-benchmark test-benchmark-whitebox test-benchmark-blackbox test-benchmark-all test-benchmark-crapi test-benchmark-vuln-java test-benchmark-vuln-nginx test-benchmark-coverage test-sast test-sast-extraction test-sast-sarif test-sast-handoff test-sast-e2e test-agent-benchmark test-agent-parsing test-agent-quality test-agent-handoff test-agent-benchmark-e2e benchmark-agent-generate test-coverage test-race test-ci test-xbow test-xbow-ssti test-xbow-xss test-xbow-sqli test-xbow-lfi test-xbow-cmdi test-xbow-ssrf test-xbow-xxe xbow-build lint fmt tidy deps deps-chrome deps-chrome-update install install-gotestsum swagger help postgres-up postgres-down postgres-logs postgres-status crapi-up crapi-down crapi-logs crapi-status juiceshop-up juiceshop-down juiceshop-logs juiceshop-status vampi-up vampi-down vampi-logs vampi-status vulnerable-java-up vulnerable-java-down vulnerable-java-logs vulnerable-java-status vulnerable-nginx-up vulnerable-nginx-down vulnerable-nginx-logs vulnerable-nginx-status apps-up apps-down docker docker-build docker-push update-jsscan ensure-jsscan update-ui

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
VERSION=$(shell grep 'Version     =' pkg/cli/version.go | cut -d '"' -f 2)
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
CLI_PKG=github.com/vigolium/vigolium/pkg/cli
LDFLAGS=-ldflags "-s -w -X $(CLI_PKG).Version=$(VERSION) -X $(CLI_PKG).Commit=$(COMMIT_HASH) -X $(CLI_PKG).BuildTime=$(BUILD_TIME)"
INGESTOR_LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME)"

# Default target
all: build

# Build main binary and install to GOBIN
build:
	@if [ -z "$$(ls $(JSSCAN_RES_DST_DIR)/ 2>/dev/null)" ]; then \
		echo "\033[31m[!] jsscan binaries not found in $(JSSCAN_RES_DST_DIR)/. Run 'make deps' first to prepare dependencies.\033[0m"; \
		exit 1; \
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
build-embedded:
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

# Run all tests (install gotestsum first, excludes vendored rod browser tests)
test: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running all tests..."
	$(TESTCMD) $(TESTFLAGS) $$(go list ./... | grep -v '/pkg/spitolas/rod')

# Run tests with race detector (excludes vendored rod browser tests)
test-race: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running tests with race detector..."
	$(TESTCMD) $(TESTFLAGS) -race $$(go list ./... | grep -v '/pkg/spitolas/rod')

# Run unit tests (excludes integration, e2e, and vendored rod browser tests)
test-unit: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running unit tests..."
	$(TESTCMD) $(TESTFLAGS) -short $$(go list ./... | grep -v '/pkg/spitolas/rod')

# Run integration tests (Brutelogic XSS gym benchmark)
test-integration: install-gotestsum
	@echo "$(PREFIX) Running integration tests (requires internet)..."
	$(TESTCMD) $(TESTFLAGS) -tags=integration ./test/benchmark/...

# Run benchmark tests (alias for test-integration)
test-benchmark: test-integration

# Run E2E tests (requires Docker)
test-e2e: install-gotestsum
	@echo "$(PREFIX) Running E2E tests (requires Docker)..."
	$(TESTCMD) $(TESTFLAGS) -tags=e2e -timeout 15m ./test/e2e/...

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

# SAST benchmark tests (route extraction, SARIF parsing, handoff conversion)
test-sast: install-gotestsum
	@echo "$(PREFIX) Running SAST benchmark tests (Layers 1-3)..."
	$(TESTCMD) $(TESTFLAGS) -tags=sast -timeout 10m ./test/benchmark/sast/...

# SAST extraction tests only (Layer 1: ast-grep route extraction)
test-sast-extraction: install-gotestsum
	@echo "$(PREFIX) Running SAST extraction benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=sast -timeout 10m -run TestExtraction ./test/benchmark/sast/...

# SAST SARIF tests only (Layer 2: SARIF fixture parsing)
test-sast-sarif: install-gotestsum
	@echo "$(PREFIX) Running SAST SARIF benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=sast -timeout 5m -run TestSARIF ./test/benchmark/sast/...

# SAST handoff tests only (Layer 3: route-to-HRR conversion)
test-sast-handoff: install-gotestsum
	@echo "$(PREFIX) Running SAST handoff benchmarks..."
	$(TESTCMD) $(TESTFLAGS) -tags=sast -timeout 5m -run TestHandoff ./test/benchmark/sast/...

# SAST end-to-end tests (Layer 4: full pipeline, requires ast-grep binary)
test-sast-e2e: install-gotestsum
	@echo "$(PREFIX) Running SAST E2E benchmarks (requires ast-grep binary)..."
	$(TESTCMD) $(TESTFLAGS) -tags=sast_e2e -timeout 15m ./test/benchmark/sast/...

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

# Test with JUnit XML output (for CI)
test-ci: install-gotestsum ensure-jsscan
	@echo "$(PREFIX) Running tests for CI..."
	@$(GOPATH_BIN)/gotestsum --junitfile test-results.xml --format testdox --format-hide-empty-pkg --hide-summary=skipped,output -- -v -race ./...

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

# Copy fresh UI builds into embedded public/ paths
update-ui:
	@echo "$(PREFIX) Updating static report template..."
	@rm -f public/static-reports/template.html
	@cp platform/static-reports/dist/template.html public/static-reports/template.html
	@echo "$(PREFIX) Building workbench UI..."
	@cd platform/vigolium-console && bun run build:workbench
	@echo "$(PREFIX) Updating dashboard UI..."
	@rm -rf public/ui/
	@mkdir -p public/ui/
	@cp -r platform/vigolium-console/dist-workbench/* public/ui/
	@echo "$(PREFIX) UI assets updated"

# Sync platform sub-repos to standalone repos
sync-platform:
	@bash build/scripts/sync-platform.sh

# Docker parameters
DOCKER_IMAGE=vigolium
DOCKER_TAG?=$(VERSION)
DOCKER_REGISTRY?=

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

# GoReleaser snapshot (local build without publishing)
snapshot:
	@echo "$(PREFIX) Building snapshot release..."
	goreleaser release --snapshot --clean

# GoReleaser release and upload to R2
release:
	@echo "$(PREFIX) Building release..."
	goreleaser release --snapshot --clean
	@echo "$(PREFIX) Cleaning old files on R2..."
	@mc rm --recursive --force r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/ || true
	@echo "$(PREFIX) Uploading to R2..."
	mc cp build/dist/*.tar.gz r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	mc cp build/dist/checksums.txt r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	mc cp build/scripts/install.sh r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	mc cp build/scripts/bootstrap.sh r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	@echo "$(PREFIX) Release uploaded successfully!"

# Sync scripts to R2 CDN without rebuilding
cdn-sync:
	@echo "$(PREFIX) Syncing scripts to R2 CDN..."
	mc cp build/scripts/install.sh r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	mc cp build/scripts/bootstrap.sh r2/vigolium-dist/$(CLOUDFLARE_R2_VIGOLIUM_PREFIX)/
	@echo "$(PREFIX) CDN sync complete"

# Clean build artifacts
clean:
	@echo "$(PREFIX) Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)/
	rm -f coverage.out coverage.html test-results.xml

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
	@echo "    make test-xbow        Run all xbow validation benchmarks (Docker + XBOW_SOURCE_DIR)"
	@echo "    make test-xbow-ssti   Run xbow SSTI benchmarks"
	@echo "    make test-xbow-xss    Run xbow XSS benchmarks"
	@echo "    make test-xbow-sqli   Run xbow SQLi benchmarks"
	@echo "    make test-xbow-lfi    Run xbow LFI benchmarks"
	@echo "    make test-xbow-cmdi   Run xbow Command Injection benchmarks"
	@echo "    make test-xbow-ssrf   Run xbow SSRF benchmarks"
	@echo "    make test-xbow-xxe    Run xbow XXE benchmarks"
	@echo "    make xbow-build       Pre-build all xbow benchmark containers"
	@echo "    make test-sast        Run SAST benchmarks: extraction + SARIF + handoff"
	@echo "    make test-sast-extraction  Run SAST route extraction benchmarks only"
	@echo "    make test-sast-sarif       Run SAST SARIF parsing benchmarks only"
	@echo "    make test-sast-handoff     Run SAST handoff conversion benchmarks only"
	@echo "    make test-sast-e2e         Run SAST E2E pipeline benchmarks"
	@echo "    make test-agent-benchmark  Run agent benchmarks: parsing + quality + handoff"
	@echo "    make test-agent-parsing    Run agent parsing benchmarks only (Layer 1)"
	@echo "    make test-agent-quality    Run agent quality benchmarks only (Layer 2)"
	@echo "    make test-agent-handoff    Run agent handoff benchmarks only (Layer 3)"
	@echo "    make test-agent-benchmark-e2e  Run agent E2E benchmarks (Docker required)"
	@echo "    make benchmark-agent-generate  Generate agent fixtures (real LLM, expensive)"
	@echo "    make test-coverage    Run tests with coverage report"
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
	@echo "    make postgres-up      Start PostgreSQL for E2E tests (localhost:5433)"
	@echo "    make postgres-down    Stop and remove PostgreSQL test container"
	@echo "    make test-benchmark-vuln-java   Run vulnerable-java benchmarks"
	@echo "    make test-benchmark-vuln-nginx  Run vulnerable-nginx benchmarks"
	@echo ""
	@echo "\033[33m  DOCKER\033[0m"
	@echo "    make docker           Build Docker image (vigolium:VERSION)"
	@echo "    make docker-build     Build Docker image (same as docker)"
	@echo "    make docker-push      Push to registry (set DOCKER_REGISTRY=ghcr.io/user)"
	@echo ""
	@echo "\033[33m  RELEASE\033[0m"
	@echo "    make snapshot         Build local snapshot release (no publish)"
	@echo "    make release          Build and upload to R2 storage"
	@echo "    make cdn-sync         Sync scripts (install.sh, bootstrap.sh) to R2 CDN"
	@echo ""
