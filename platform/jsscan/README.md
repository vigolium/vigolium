# jsscan

Extract API endpoints and HTTP request patterns from JavaScript bundles.

## Install

```bash
bun install --linker isolated
bun run build:bin
```

## Usage

```bash
# From file
jsscan app.bundle.js

# From stdin
curl -s https://example.com/app.js | jsscan

# Overwrite file with deobfuscated code
jsscan -f app.bundle.js
```

## Output

JSON lines to stdout. There are 3 record types:

### `requestPattern` — detected HTTP call patterns (fetch, XHR, jQuery, etc.)

```json
{"type":"requestPattern","patternType":"fetch","code":"fetch(\"/api/users\", {method: \"POST\"})","functionName":"createUser","paramCount":2,"literals":["/api/users"],"callSites":[...],"tracedVariables":[...]}
```

### `extractedRequest` — resolved API endpoint with method/headers/body

```json
{"type":"extractedRequest","url":"/api/users","method":"POST","params":"","body":"${data}","headers":["Content-Type: application/json"],"cookies":[]}
```

### `code` — deobfuscated source (always last line)

```json
{"type":"code","filename":"app.bundle.js","content":"..."}
```

## Options

| Flag | Description |
|------|-------------|
| `-f, --force` | Overwrite input file with deobfuscated code |

## Examples

```bash
# List all extracted URLs
jsscan bundle.js | jq -r 'select(.type == "extractedRequest") | .url'

# Get request patterns with their code
jsscan bundle.js | jq 'select(.type == "requestPattern")'

# Save deobfuscated code separately
jsscan bundle.js | jq -r 'select(.type == "code") | .content' > clean.js
```
