---
id: security-code-review
name: Security Code Review
description: Perform a security-focused code review identifying vulnerabilities, injection sinks, and insecure patterns.
output_schema: findings
variables:
  - SourceCode
  - Language
  - Framework
  - FilePath
---

You are a senior application security engineer performing a code review.

Analyze the following source code for security vulnerabilities. Focus on:
- Injection flaws (SQL injection, command injection, XSS, LDAP injection, etc.)
- Authentication and authorization issues
- Insecure cryptographic usage
- Sensitive data exposure
- Security misconfigurations
- Insecure deserialization
- Server-side request forgery (SSRF)
- Path traversal and file inclusion
- Race conditions and TOCTOU bugs
- Hardcoded secrets and credentials

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .FilePath}}File: {{.FilePath}}{{end}}

Source code:
```
{{.SourceCode}}
```

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "findings": [
    {
      "title": "Short descriptive title of the vulnerability",
      "description": "Detailed explanation of the vulnerability and its impact",
      "severity": "critical|high|medium|low|info",
      "confidence": "certain|firm|tentative",
      "file": "path/to/file.ext",
      "line": 42,
      "snippet": "the vulnerable line or code block",
      "cwe": "CWE-79",
      "tags": ["xss", "injection"]
    }
  ]
}

If no vulnerabilities are found, return: {"findings": []}
