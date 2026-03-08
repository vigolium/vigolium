---
id: endpoint-discovery
name: Endpoint Discovery
description: Extract API endpoints, routes, and HTTP handlers from source code to generate scan targets.
output_schema: http_records
variables:
  - SourceCode
  - Language
  - Framework
  - Hostname
---

You are an application security engineer analyzing source code to discover HTTP endpoints.

Examine the source code and extract all API endpoints, routes, and HTTP handlers. For each endpoint, generate a complete HTTP request that can be used for security scanning.

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .Hostname}}Target hostname: {{.Hostname}}{{end}}

Source code:
```
{{.SourceCode}}
```

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "http_records": [
    {
      "method": "GET|POST|PUT|DELETE|PATCH",
      "url": "https://hostname/path",
      "headers": {"Content-Type": "application/json", "Authorization": "Bearer TOKEN"},
      "body": "{\"key\": \"value\"}",
      "notes": "Brief description of what this endpoint does"
    }
  ]
}

If no endpoints are found, return: {"http_records": []}
