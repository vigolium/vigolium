# Scanning an API

## Overview

Vigolium supports scanning REST APIs by importing endpoint definitions from OpenAPI specs, Swagger files, Postman collections, or raw curl commands. This guide covers the most common workflows for API security testing.

## From an OpenAPI/Swagger Spec

If you have an OpenAPI 3.x specification:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com
```

For older Swagger 2.0 files:

```bash
vigolium scan --input swagger.json -I swagger -t https://api.example.com
```

The `-t` (target) flag sets the base URL. Vigolium resolves relative paths from the spec against this target. If your spec contains a `servers` block with the correct URL, the target flag still takes precedence.

You can also pass a remote URL as the input:

```bash
vigolium scan --input https://api.example.com/openapi.json -I openapi -t https://api.example.com
```

## From a Postman Collection

Export your Postman collection as JSON (v2.1 format) and pass it directly:

```bash
vigolium scan --input collection.json -I postman -t https://api.example.com
```

Environment variables in the collection are resolved where possible. For variables that reference a specific environment, set the target flag to the correct base URL.

## From curl Commands

Pipe one or more curl commands into Vigolium:

```bash
echo 'curl https://api.example.com/users' | vigolium scan -I curl -t https://api.example.com
```

You can also pass a file containing multiple curl commands (one per line):

```bash
vigolium scan --input curls.txt -I curl -t https://api.example.com
```

This is useful when you have recorded traffic from browser DevTools or intercepting proxies. Copy requests as curl and feed them directly to the scanner.

## With Authentication

Most APIs require authentication. You can configure session handling via a session config file or by passing headers directly:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com \
  -H "Authorization: Bearer <token>"
```

For more complex authentication flows (OAuth2, cookie-based sessions, token refresh), refer to the authenticated scanning documentation in `docs/authenticated-scan.md`.

## Recommended Strategy

APIs do not require browser-based spidering since all endpoints are already defined in the input spec. Use the `lite` strategy to skip unnecessary discovery phases:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com --strategy lite
```

Alternatively, skip the spidering phase explicitly while keeping other discovery mechanisms:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com --skip spidering
```

The `lite` strategy is faster and avoids sending unnecessary crawling traffic to endpoints that may have side effects.

## Filtering Modules for APIs

Focus the scan on API-relevant vulnerability checks using module tags:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com --module-tag api
```

You can combine multiple tags to narrow the scope further:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com \
  --module-tag api --module-tag injection
```

To see available module tags, run:

```bash
vigolium modules --list-tags
```

This helps reduce scan time and noise by running only the checks that are relevant to API attack surfaces (e.g., injection, authentication bypass, IDOR) rather than browser-oriented checks like reflected XSS in HTML contexts.
