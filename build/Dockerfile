# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION
ARG COMMIT_HASH
ARG BUILD_TIME

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/vigolium/vigolium/pkg/cli.Version=${VERSION} \
              -X github.com/vigolium/vigolium/pkg/cli.Commit=${COMMIT_HASH} \
              -X github.com/vigolium/vigolium/pkg/cli.BuildTime=${BUILD_TIME}" \
    -o /out/vigolium ./cmd/vigolium

# Runtime stage
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# System packages + chromium (single layer, retry for large packages)
RUN apt-get update && \
    for i in 1 2 3; do \
        apt-get install -y --no-install-recommends \
            chromium \
            git \
            curl \
            wget \
            ca-certificates \
            python3 \
            python3-pip \
            dumb-init \
            fonts-liberation \
        && break || { echo "Attempt $i failed, retrying..."; apt-get update; }; \
    done && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /usr/bin/python3 /usr/bin/python

# Chromium headless environment
ENV CHROME_NO_SANDBOX=true
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage"

# Source-aware tools
RUN curl -sfL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash

RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest && cp $(go env GOPATH)/bin/osv-scanner /usr/local/bin/

RUN pip install --break-system-packages --no-cache-dir ast-grep-cli semgrep

# Nuclei templates for KnownIssueScan phase
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates

# Copy binary
COPY --from=builder /out/vigolium /usr/local/bin/vigolium

WORKDIR /root

ENTRYPOINT ["dumb-init", "--"]
CMD ["vigolium"]
