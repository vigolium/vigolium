---
id: swarm-source-format-routes
name: Format Route Analysis Results
description: Convert route analysis notes into JSONL HTTP records
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
---

You are given notes from a source code analysis documenting HTTP routes and endpoints. Convert these notes into structured JSONL HTTP records.

## Output Format

Output **all routes** as **JSONL** (one JSON object per line) wrapped in a ` ```jsonl ` fenced code block. Each line is a standalone HTTP record.

```jsonl
{"method":"GET","url":"{{.TargetURL}}/api/products?q=test&page=1","headers":{},"notes":"List products — uses raw SQL query (sqli sink)"}
{"method":"POST","url":"{{.TargetURL}}/api/endpoint","headers":{"Content-Type":"application/json"},"body":"{\"param\":\"value\",\"name\":\"test\"}","notes":"Description of endpoint and relevant sinks"}
{"method":"PUT","url":"{{.TargetURL}}/api/users/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"test\",\"email\":\"user@test.com\"}","notes":"Update user by ID — requires auth"}
{"method":"DELETE","url":"{{.TargetURL}}/api/items/1?force=true","headers":{},"notes":"Delete item — admin only"}
```

## OUTPUT REMINDER — Read This Last

Before writing your response, verify against these rules:

1. **JSONL block** → ` ```jsonl ` (NOT ` ```json `). One JSON object per line. No JSON array wrapper.
2. **Body fields** → MUST be **escaped JSON strings**, NOT nested objects.
   - CORRECT: `"body":"{\"email\":\"a@b.com\",\"password\":\"test\"}"`
   - WRONG:   `"body":{"email":"a@b.com","password":"test"}`
3. **Every POST/PUT/PATCH** route MUST have a non-empty `body` with all parameters from the handler code.
4. **Every GET/DELETE** route MUST have query parameters in the URL string (e.g., `?q=test&page=1`).
5. Each line must be **valid, parseable JSON** — no trailing commas, no comments.
6. Use the target URL `{{.TargetURL}}` as base for all URLs.
