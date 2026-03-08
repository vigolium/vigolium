# Vigolium API Reference — Modules

## GET /api/modules — List Modules

Returns all registered scanner modules (active and passive).

**Query parameters:**

| Parameter | Type   | Description                        |
|-----------|--------|------------------------------------|
| `search`  | string | Filter by module name, ID, description, or tag |
| `tag`     | string | Filter by exact tag (case-insensitive, e.g. `spring`, `injection`, `heavy`) |

```bash
# List all modules
curl -s http://localhost:9002/api/modules | jq .

# Search for XSS modules
curl -s 'http://localhost:9002/api/modules?search=xss' | jq .

# Filter by tag
curl -s 'http://localhost:9002/api/modules?tag=spring' | jq .

# Combine search and tag
curl -s 'http://localhost:9002/api/modules?search=misconfig&tag=java' | jq .
```

**Response (200):**

```json
{
  "modules": [
    {
      "id": "xss-light",
      "name": "XSS Light Scanner",
      "description": "...",
      "short_description": "Detects reflected XSS via character transformation analysis",
      "confirmation_criteria": "Confirmed when injected probe characters are reflected without sanitization",
      "severity": "high",
      "confidence": "firm",
      "scan_scope": ["PER_REQUEST"],
      "tags": ["injection", "xss", "light"],
      "type": "active"
    },
    {
      "id": "spring-actuator-misconfig",
      "name": "Spring Actuator Misconfiguration",
      "description": "...",
      "short_description": "Detects exposed Spring Boot actuator endpoints",
      "confirmation_criteria": "...",
      "severity": "high",
      "confidence": "certain",
      "scan_scope": ["PER_HOST"],
      "tags": ["spring", "java", "misconfiguration", "info-disclosure", "light"],
      "type": "active"
    }
  ],
  "total": 2
}
```

### Tag Categories

Modules are tagged across four dimensions:

| Category | Example tags |
|----------|-------------|
| **Technology** | `spring`, `rails`, `laravel`, `django`, `express`, `nextjs`, `aspnet`, `php`, `wordpress`, `drupal`, `java`, `python`, `ruby`, `nodejs`, `javascript`, `nginx`, `tomcat`, `firebase`, `graphql` |
| **Vulnerability class** | `injection`, `xss`, `sqli`, `ssti`, `lfi`, `rce`, `ssrf`, `xxe`, `csrf`, `idor`, `open-redirect`, `deserialization`, `prototype-pollution`, `cache-poisoning`, `smuggling`, `race-condition` |
| **Category** | `misconfiguration`, `info-disclosure`, `fingerprint`, `authentication`, `session`, `cryptography`, `file-exposure`, `cloud`, `cms`, `api`, `header-security`, `behavior-analysis` |
| **Resource cost** | `light` (few requests / passive), `moderate` (typical active scan), `heavy` (timing-based, blind, many requests) |
