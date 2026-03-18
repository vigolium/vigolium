# Running with Docker

This guide covers building and running Vigolium using Docker containers.

## Images

Two Dockerfiles are provided in `build/`:

| Dockerfile | Base | Size | Includes |
|------------|------|------|----------|
| `build/Dockerfile` | `debian:bookworm-slim` | ~1.5 GB | Chromium, git, curl, wget, Python 3, ast-grep, semgrep, trivy, kingfisher |
| `build/Dockerfile.minimal` | `alpine:3.21` | ~30 MB | Binary only (CA certs, tzdata) |

Use the **full image** for production scanning (browser-based spidering, source-aware analysis). Use the **minimal image** for headless/API-only workloads that don't need a browser or source-aware tools.

## Building

### Full image (recommended)

```bash
make docker
```

This builds the image as `vigolium:<version>` and `vigolium:latest` using `build/Dockerfile`.

To set a custom tag:

```bash
make docker-build DOCKER_TAG=my-tag
```

### Minimal image

```bash
docker build -f build/Dockerfile.minimal -t vigolium:minimal .
```

## Running

### Basic scan

```bash
docker run --rm vigolium scan url https://example.com
```

### Server mode

```bash
docker run --rm -p 8080:8080 vigolium server --listen :8080
```

### Persisting data

Mount a volume to preserve scan results, the database, and configuration across runs:

```bash
docker run --rm \
  -v vigolium-data:/root/.vigolium \
  vigolium scan url https://example.com
```

For the minimal image (runs as non-root `vigolium` user, UID 1000):

```bash
docker run --rm \
  -v vigolium-data:/home/vigolium/.vigolium \
  vigolium:minimal scan url https://example.com
```

### Custom configuration

Mount your configuration file into the container:

```bash
docker run --rm \
  -v $(pwd)/vigolium-configs.yaml:/root/vigolium-configs.yaml \
  -v vigolium-data:/root/.vigolium \
  vigolium scan url https://example.com
```

### Source-aware scanning

Mount your source code into the container and use `--source`:

```bash
docker run --rm \
  -v /path/to/source:/src \
  -v vigolium-data:/root/.vigolium \
  vigolium scan url https://example.com --source /src
```

### Agent mode

Agent mode requires API keys passed as environment variables:

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY \
  -v vigolium-data:/root/.vigolium \
  vigolium agent autopilot --input https://example.com
```

### HTML report output

Mount an output directory to retrieve generated reports:

```bash
docker run --rm \
  -v $(pwd)/reports:/reports \
  vigolium scan url https://example.com --format html -o /reports/scan.html
```

## Pushing to a Registry

```bash
make docker-push DOCKER_REGISTRY=ghcr.io/your-org
```

This tags and pushes both `vigolium:<version>` and `vigolium:latest` to the specified registry.

## Notes

- The full image uses `dumb-init` as PID 1 for proper signal handling.
- The full image runs as `root` to allow Chromium sandbox access. Set `CHROME_NO_SANDBOX=true` (default) in containerized environments.
- The minimal image runs as a non-root user (`vigolium`, UID 1000).
- Both images compile with `CGO_ENABLED=0` for a static binary with no C dependencies.
