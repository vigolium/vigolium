# Build stage
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        make \
        curl \
        unzip \
        file \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Force HTTP/1.1 and enable curl retries via ~/.curlrc, which every curl in
# this stage (including the bun installer's own download) inherits. Under
# multi-arch buildx the emulated (QEMU) leg fetches release zips from GitHub
# over a slow/contended link where HTTP/2 stream resets ("stream was not closed
# cleanly") are common — these settings ride them out.
RUN printf '%s\n' '--http1.1' '--retry 5' '--retry-delay 3' '--retry-all-errors' > /root/.curlrc

# bun is required by `make build`: it compiles the embedded archon binary
# (platform/archon-audit → pkg/archon/archonbin/_bin/) and the jstangle binaries
# (platform/jstangle → internal/resources/deparos/jstangle/). Retry the whole
# install a few times since the bun script's own download can still fail.
RUN for attempt in 1 2 3 4 5; do \
        curl -fsSL https://bun.sh/install | bash && break; \
        echo "bun install attempt $attempt failed; retrying in 5s..." >&2; \
        sleep 5; \
    done
ENV PATH="/root/.bun/bin:${PATH}"
RUN bun --version

# Build a fully static binary so it has no host glibc dependencies. The bun
# driver/sqliteshim falls back to pure-go modernc.org/sqlite when CGO=0.
ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

# Use `make build` (not raw `go build`) so the embedded archon + jstangle
# binaries are staged before compile. Version/commit/build-time are derived
# inside the Makefile from pkg/cli/version.go + git rev-parse.
RUN set -e; \
    target_os="${TARGETOS:-$(go env GOOS)}"; \
    target_arch="${TARGETARCH:-$(go env GOARCH)}"; \
    case "$target_arch" in \
        amd64) audit_arch="x64" ;; \
        arm64) audit_arch="arm64" ;; \
        *) echo "unsupported Docker target arch for vigolium-audit: $target_arch" >&2; exit 1 ;; \
    esac; \
    audit_blob="platform/vigolium-audit/build/dist/vigolium-audit-${target_os}-${audit_arch}"; \
    if [ -f "$audit_blob" ]; then \
        bash build/scripts/stage-audit-blob.sh "$target_os" "$target_arch"; \
    else \
        echo "prebuilt $audit_blob not found; make build will rebuild vigolium-audit"; \
    fi; \
    make ensure-jstangle \
    && make build \
    && mkdir -p /out \
    && cp bin/vigolium /out/vigolium

# Runtime stage
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        curl \
        wget \
        git \
        bash \
        unzip \
        python3 \
        python3-pip \
        dumb-init \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python

# Chromium headless environment
ENV CHROME_NO_SANDBOX=true
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage"

# Same curl hardening as the builder stage: the runtime stage downloads codeql,
# nuclei-templates, chrome-for-testing, etc., all of which hit the same flaky
# HTTP/2 streams on the emulated multi-arch leg.
RUN printf '%s\n' '--http1.1' '--retry 5' '--retry-delay 3' '--retry-all-errors' > /root/.curlrc

# Install semgrep + codeql (multi-arch via uname -m inside the script).
COPY build/scripts/install-deps.sh /tmp/install-deps.sh
RUN bash /tmp/install-deps.sh && rm /tmp/install-deps.sh

# Copy the freshly-built binary.
COPY --from=builder /out/vigolium /usr/local/bin/vigolium

# Tools installed by `vigolium doctor --fix` land in well-known per-user paths.
# Pre-populate PATH so subsequent build stages and `docker run` shells find them.
ENV PATH="/root/.bun/bin:/root/.local/bin:/root/.pi/bin:/opt/codeql:${PATH}"

# The bundled piolium installer drops its config at $HOME/.piolium/agent
# instead of the ~/.pi default. Pointing PIOLIUM_HOME there makes doctor and
# the audit driver pick up the install without an explicit $HOME/.pi/ fallback.
ENV PIOLIUM_HOME=/root/.piolium

# The image runs as root; the bundled `claude` CLI refuses to run as root
# unless it detects a sandboxed environment. IS_SANDBOX=1 opts in.
ENV IS_SANDBOX=1

# Pull in runtime dependencies in one shot: bun, claude, agent-browser,
# piolium (bun+pi+extension), nuclei-templates, chrome-for-testing.
RUN vigolium doctor --fix

WORKDIR /root

ENTRYPOINT ["dumb-init", "--", "vigolium"]
