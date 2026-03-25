# Whitebox Scanning

## Overview

Whitebox scanning combines source code analysis (SAST) with dynamic scanning (DAST) to maximize vulnerability coverage. By analyzing the application source, Vigolium discovers routes that may not be reachable through crawling alone, and enriches dynamic scan results with source-level context.

## What --source Does

The `--source` flag points Vigolium at the application source code. When provided, it enables:

- **SAST route extraction**: Uses ast-grep to statically analyze source code and discover HTTP routes, API endpoints, and handler functions across supported frameworks.
- **Route probing**: Discovered routes are probed with live HTTP requests against the target to verify reachability and capture real responses.
- **Persistent source association**: The source path is linked to the project in the database, enabling ongoing source-aware analysis across scans.
- **Source-aware agent analysis**: Agent modes receive source code context for more targeted and informed security analysis.

## Basic Whitebox Scan

Point Vigolium at both the target URL and the local source directory:

```bash
vigolium scan -t https://example.com --source ./app --strategy whitebox
```

The `whitebox` strategy activates SAST route extraction before the dynamic scan phases. Discovered routes are parameterized, probed, and fed into the scanner alongside any other inputs.

## Remote Repository

If the source code is hosted in a remote Git repository:

```bash
vigolium scan -t https://example.com --source-url https://github.com/org/repo.git --strategy whitebox
```

Vigolium clones the repository locally and runs the same source analysis pipeline. Both HTTPS and SSH Git URLs are supported (auto-detected via URL format).

## SAST-Only

To run only the static analysis phase without any dynamic scanning:

```bash
vigolium scan -t https://example.com --source ./app --only sast
```

This is useful for quickly identifying routes and potential issues from code without sending any traffic to the target. The target URL is still needed for route probing and record creation.

## Ad-Hoc SAST

The `--sast-adhoc` flag runs a one-off SAST analysis without creating a persistent source association in the database:

```bash
vigolium scan -t https://example.com --sast-adhoc ./app
```

This accepts either a local path or a Git URL. Use this when you want a quick source scan without affecting the project's configured source repository.

## Agent-Enhanced Whitebox

For AI-driven source-aware scanning, use the swarm agent mode with the `--source` flag:

```bash
vigolium agent swarm -t https://example.com --source ./app --discover
```

In this mode, the master agent:

1. Analyzes the source code to understand application architecture and identify high-value targets.
2. Discovers routes from source and filters them by the target hostname.
3. Generates custom JavaScript scanner extensions tailored to the application.
4. Executes targeted scans and triages results with source-level context.

The `--target` flag is required when using `--source` with swarm mode so that discovered routes can be filtered to the correct hostname.

## Route Parameterization

When Vigolium extracts routes from source code, many contain parameter placeholders in various framework-specific formats:

| Format | Example | Framework |
|--------|---------|-----------|
| `:param` | `/users/:id` | Express, Gin, Echo |
| `{param}` | `/users/{id}` | Spring, FastAPI, .NET |
| `<type:param>` | `/users/<int:id>` | Flask |

Vigolium automatically substitutes these placeholders with realistic probe values based on the parameter name:

- **id**, **user_id**: Numeric values (e.g., `1`)
- **uuid**: Valid UUID format (e.g., `550e8400-e29b-41d4-a716-446655440000`)
- **email**: Email format (e.g., `test@example.com`)
- **slug**: URL-safe string (e.g., `test-item`)
- Other names: Generic string values

This parameterization ensures that probed URLs are realistic enough to reach actual handlers rather than returning 404 errors due to invalid path parameters.
