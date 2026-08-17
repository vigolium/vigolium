# Scanning an API

## Overview

Vigolium supports scanning REST APIs by importing endpoint definitions from OpenAPI specs, Swagger files, WSDL/SOAP service descriptions, Postman collections, or raw curl commands. This guide covers the most common workflows for API security testing.

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

## From a WSDL / SOAP Service

If the API is a SOAP service, point Vigolium at its WSDL. Each bound operation is
expanded into a SOAP `POST` request carrying a synthesized XML envelope, which
the active modules then fuzz (injection, XXE, etc.) through the request body and
the `SOAPAction` header:

```bash
vigolium scan --input service.wsdl -I wsdl -t https://soap.example.com
```

`-I wsdl` is optional — a `.wsdl` file is auto-detected from its content. Both
SOAP 1.1 (a `SOAPAction` header with `text/xml`) and SOAP 1.2 (`action=` inside
`application/soap+xml`) are handled, for document/literal and rpc styles.

For a live WCF (`.svc`) or classic ASMX (`.asmx`) endpoint, pass the service URL
directly — Vigolium fetches the WSDL for you (`?singleWsdl` for WCF, `?WSDL` for
ASMX):

```bash
vigolium scan --input https://soap.example.com/Calculator.svc
```

The endpoint comes from the WSDL's `<soap:address>`. Passing `-t` overrides only
the host (scheme + host from `-t`, service path from the WSDL) so you can redirect
traffic at an in-scope target while keeping the service path intact. Use
`--spec-header` for auth headers and `--spec-var name=value` to replace a body
element's placeholder value by its local name:

```bash
vigolium scan --input service.wsdl -I wsdl -t https://soap.example.com \
  --spec-header "Authorization: Bearer <token>" \
  --spec-var userName=admin
```

> **Scope:** WSDL 1.1 with SOAP 1.1/1.2 is supported. WSDL 2.0 and unresolved
> multi-file `<import>` are not — for a service that splits its schema across
> files, use the `.svc` `?singleWsdl` form, which inlines everything.

Vigolium also auto-ingests SOAP services it discovers during a crawl: if a
response looks like a WSDL (for example a `?wsdl` document), its operations are
expanded into scan traffic automatically, the same way an OpenAPI document found
mid-scan is.

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

For single- and multi-step login flows, cookie sessions, and role comparison, see
[Native Scan Authentication](../native-scan/authentication.md).

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
vigolium module --tags
```

This helps reduce scan time and noise by running only the checks that are relevant to API attack surfaces (e.g., injection, authentication bypass, IDOR) rather than browser-oriented checks like reflected XSS in HTML contexts.
