# Build stage
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        make \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# bun is required by `make build`: it compiles the embedded archon binary
# (platform/archon-audit → pkg/archon/archonbin/_bin/) and the jsscan binaries
# (platform/jsscan → internal/resources/deparos/jsscan/).
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

# Build a fully static binary so it has no host glibc dependencies. The bun
# driver/sqliteshim falls back to pure-go modernc.org/sqlite when CGO=0.
ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Use `make build` (not raw `go build`) so the embedded archon + jsscan
# binaries are staged before compile. Version/commit/build-time are derived
# inside the Makefile from pkg/cli/version.go + git rev-parse.
RUN make ensure-jsscan \
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
