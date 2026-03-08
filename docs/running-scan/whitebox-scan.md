# Whitebox Scanning

Whitebox scanning uses application source code to extract routes, detect frameworks, find security issues statically, and feed discovered endpoints into dynamic scanning. This combines static analysis (SAST) with dynamic testing for better coverage.

## Quick Start

```bash
# Full whitebox scan: SAST + discovery + SPA + dynamic
vigolium scan -t https://example.com --source ./my-app --strategy whitebox

# SAST only (no dynamic scanning)
vigolium scan -t https://example.com --source ./my-app --only sast

# Ad-hoc route extraction (no DB, just print routes)
vigolium scan --repo ./my-app
```

## How It Works

The whitebox pipeline:

1. **Source Resolution** — Local path validated or Git URL cloned
2. **Framework Detection** — Automatically detects the web framework from project files
3. **SAST Analysis** — ast-grep extracts routes and runs security rules
4. **Route Ingestion** — Extracted routes are saved to the database as HTTP records
5. **Dynamic Assessment** — Routes become targets for active/passive scanner modules

Routes extracted by SAST flow directly into the dynamic assessment phase, giving the scanner endpoints it could not discover through crawling or brute-forcing alone.

## The `--strategy whitebox` Flag

The whitebox strategy enables these phases:

| Phase | Enabled |
|-------|:-------:|
| External Harvesting | - |
| Discovery | yes |
| Spidering | - |
| SPA | yes |
| Dynamic Assessment | yes |
| Source-Aware (SAST) | yes |

```bash
vigolium scan -t https://api.example.com --source ./backend --strategy whitebox
```

## Source Resolution

Two flags provide source code to the scanner:

| Flag | Input | Behavior |
|------|-------|----------|
| `--source` | Local directory | Used directly (e.g., `--source ./my-app`) |
| `--source-url` | Git URL | Shallow-cloned to `~/.vigolium/source-aware/` |

These flags are **mutually exclusive** — using both produces an error.

```bash
# Local source
vigolium scan -t https://api.example.com --source /path/to/app

# Git HTTPS URL (auto-cloned)
vigolium scan -t https://api.example.com --source-url https://github.com/org/backend.git

# Git SSH URL
vigolium scan -t https://api.example.com --source-url git@github.com:org/backend.git
```

Once linked, the source repo is stored in the database by hostname. Subsequent scans against the same host reuse the linked repo without needing `--source` or `--source-url` again.

## Framework Auto-Detection

Vigolium detects the framework by examining project manifest files:

| Framework | Detection Method |
|-----------|-----------------|
| **Gin** | `go.mod` contains `github.com/gin-gonic/gin` |
| **Next.js** | `package.json` contains `next` |
| **FastAPI** | `requirements.txt`, `pyproject.toml`, or `Pipfile` contains `fastapi` |
| **Express** | `package.json` contains `express` |
| **Django** | `manage.py` or `requirements.txt` contains `django` |
| **Flask** | `requirements.txt`, `pyproject.toml`, or `Pipfile` contains `flask` |
| **Go net/http** | Go project without Gin (fallback) |

Additional frameworks have SAST rules but are not auto-detected (use `--rule` to target them): **Laravel**, **Spring**, **PHP**.

## SAST Rules

ast-grep rules extract routes and detect security patterns. Rules are organized by category:

### Route Extraction Rules

Framework-specific rules that extract HTTP routes, parameters, and route groups:

- **Gin**: route handlers (`GET`, `POST`, etc.), route groups, param binding (`Param`, `Query`, `PostForm`, `ShouldBind`)
- **Next.js**: App Router handlers (exported `GET`/`POST` functions), Pages API handlers, dynamic route params
- **FastAPI**: route decorators, path/query/body params
- **Express**: route handlers (JS + TS), route groups (`use`), param binding (`req.params`, `req.query`, `req.body`)
- **Django**: URL patterns (`path`, `re_path`), class-based view methods, request param binding
- **Flask**: route decorators, method decorators, `add_url_rule`, param binding
- **Go net/http**: `HandleFunc`, router methods, route registration, URL query/form params
- **Laravel**: `Route::get`, `Route::post`, etc.
- **Spring**: `@GetMapping`, `@PostMapping`, `@RequestMapping`, etc.

### Security Rules

Static security analysis rules (independent of framework):

| Category | Examples |
|----------|---------|
| **XSS** | `dangerouslySetInnerHTML`, `eval()`, `innerHTML` assignment, `document.write`, jQuery HTML sinks, `postMessage` wildcard |
| **Auth** | Token in localStorage/sessionStorage, JWT decode without verification, hardcoded fallback secrets, mass assignment (`Object.assign(model, req.body)`) |
| **CORS** | Origin substring checking, origin reflection, postMessage without origin validation |
| **Config** | Source maps enabled in production, unsafe CSP directives, hardcoded secrets, public env vars with secrets, dev mode in production |
| **Next.js** | `"use server"` without auth, `unstable_cache`, `dangerouslyAllowSVG`, fail-open middleware, `__NEXT_DATA__` data leakage |

## Rule Filtering with `--rule`

Filter SAST rules by fuzzy name matching:

```bash
# Only Gin-related rules
vigolium scan -t https://api.example.com --source ./app --only sast --rule gin

# Only security XSS rules
vigolium scan -t https://api.example.com --source ./app --only sast --rule security-xss

# Only Next.js security rules
vigolium scan -t https://app.example.com --source ./app --only sast --rule nextjs

# Only auth-related security rules
vigolium scan -t https://api.example.com --source ./app --only sast --rule security-auth
```

## Ad-Hoc Mode with `--repo` / `--repo-url`

The `--repo` and `--repo-url` flags run SAST without saving results to the database. Results are printed directly to the terminal.

| Flag | Input | Behavior |
|------|-------|----------|
| `--repo` | Local directory | Used directly (e.g., `--repo ./my-app`) |
| `--repo-url` | Git URL | Shallow-cloned, then scanned |

These flags are **mutually exclusive** — using both produces an error.

```bash
# Print extracted routes for a Gin app
vigolium scan --repo ./my-gin-api

# Scan a remote repo (auto-cloned)
vigolium scan --repo-url https://github.com/org/backend.git

# Print routes for an Express app, filtered to route rules
vigolium scan --repo ./my-express-app --rule route

# Check for XSS patterns only
vigolium scan --repo ./my-nextjs-app --rule security-xss
```

Output is a table showing: method, path, parameters, source file, and line number.

## Third-Party Tool Integration

Vigolium can run external SAST tools (semgrep, trivy) that output SARIF format:

```bash
# Default config runs both semgrep and trivy if installed
vigolium scan -t https://example.com --source ./app --strategy whitebox
```

Configuration in `vigolium-configs.yaml`:

```yaml
source_aware:
  third_party_integration:
    enabled: true
    timeout: "10m"
    tools:
      - name: semgrep
        enabled: true
        command: semgrep
        args: ["scan", "--sarif", "--quiet"]
      - name: trivy
        enabled: true
        command: trivy
        args: ["fs", "--format", "sarif", "--quiet"]
```

Tools must be installed separately. If a tool binary is not found, it is skipped silently.

## Source Repo Management

Manage source repos linked to targets:

```bash
# List linked source repos
vigolium source ls

# Add a source repo manually
vigolium source add --hostname api.example.com --path ./backend
```

## SAST-Only Mode

Run static analysis in isolation without dynamic scanning:

```bash
# SAST only
vigolium scan -t https://api.example.com --source ./app --only sast

# SAST with specific rules
vigolium scan -t https://api.example.com --source ./app --only sast --rule gin
```

## Configuration Reference

Full `source_aware` section in `vigolium-configs.yaml`:

```yaml
source_aware:
  storage_path: "~/.vigolium/source-aware/"    # Where Git repos are cloned
  clone_depth: 1                                # Shallow clone depth

  ast_grep:
    enabled: true                               # Enable/disable ast-grep
    rules_dir: "~/.vigolium/sast-rules/astgrep/"  # Custom rules directory
    timeout: "5m"                               # Timeout per scan

  third_party_integration:
    enabled: true                               # Enable/disable external tools
    timeout: "10m"                              # Timeout for all tools combined
    tools:
      - name: semgrep
        enabled: true
        command: semgrep
        args: ["scan", "--sarif", "--quiet"]
      - name: trivy
        enabled: true
        command: trivy
        args: ["fs", "--format", "sarif", "--quiet"]
```

## Common Scenarios

```bash
# Full whitebox scan of a Go/Gin API
vigolium scan -t https://api.example.com --source ./api --strategy whitebox

# SAST-only for a Next.js app with security rules
vigolium scan -t https://app.example.com --source ./frontend --only sast --rule security

# Quick route extraction (no DB)
vigolium scan --repo ./my-flask-app

# Whitebox scan with HTML report
vigolium scan -t https://example.com --source ./app --strategy whitebox \
  --format html -o whitebox-report.html

# Whitebox scan of a remote repo
vigolium scan -t https://api.example.com \
  --source-url https://github.com/org/backend.git \
  --strategy whitebox

# Ad-hoc SAST from a remote repo
vigolium scan --repo-url https://github.com/org/backend.git

# Run SAST with only semgrep (disable trivy and ast-grep rules)
vigolium scan -t https://api.example.com --source ./app --only sast --rule semgrep
```
