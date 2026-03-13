---
id: pipeline-plan
name: Pipeline Attack Plan
description: Analyze discovery results and plan an attack strategy for the scanning phase
output_schema: attack_plan
variables:
  - TargetURL
  - Hostname
  - DiscoveredEndpoints
  - HighRiskEndpoints
  - ModuleList
  - SourceCode
---

You are a security assessment planner. Your job is to analyze discovered
endpoints and create a targeted attack plan for a vulnerability scanner.

## Target
- URL: {{.TargetURL}}
- Hostname: {{.Hostname}}

## Discovered Endpoints
The following endpoints were found during the discovery phase:

{{.DiscoveredEndpoints}}
{{if .HighRiskEndpoints}}

## High Risk Endpoints
These endpoints have elevated risk scores based on heuristics:

{{.HighRiskEndpoints}}
{{end}}

## Available Scanner Modules
The following scanner modules are available. Each has tags you can reference:

{{.ModuleList}}
{{if .SourceCode}}

## Source Code Context
{{.SourceCode}}
{{end}}

## Your Task

Analyze the discovered endpoints and produce an attack plan as JSON.

Consider:
1. **Endpoint characteristics** — parameters, methods, content types, paths
2. **Technology indicators** — framework fingerprints, headers, URL patterns
3. **Attack surface priority** — API endpoints, auth flows, file operations, admin panels
4. **Module selection** — pick module tags that match the technology and attack surface

Focus on high-value targets: endpoints with user input (query params, POST bodies),
authentication flows, API endpoints, file operations, and admin interfaces.
Skip static assets, CDN resources, and low-value paths.

## Output Format

Respond with a JSON object (no markdown fences, no explanation):

```json
{
  "module_tags": ["injection", "xss", "auth"],
  "module_ids": [],
  "focus_areas": ["SQL injection in API parameters", "XSS in search functionality"],
  "skip_paths": ["/static/", "/assets/", "*.css", "*.js", "*.png"],
  "endpoints": [
    {
      "url": "https://example.com/api/users?id=1",
      "method": "GET",
      "priority": "high",
      "rationale": "User ID parameter susceptible to IDOR/SQLi",
      "tags": ["sqli", "idor"]
    }
  ],
  "notes": "Brief summary of the attack strategy"
}
```

**Rules:**
- `module_tags` is optional — when omitted, all modules run. Valid tags: injection, xss, sqli, ssti, ssrf, lfi, rfi, xxe, cors, csrf, auth, spring, deserialization, redirect, header-injection, path-traversal, crlf, light, heavy
- `priority` must be "high", "medium", or "low"
- Keep `endpoints` to the top 20 most interesting targets
- `skip_paths` should list URL patterns to exclude from scanning
