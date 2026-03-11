# Source Analysis JSON Parsing: Use ```json``` Code Blocks

## Problem

The current source analysis prompt tells the agent: **"Start your response with `{`"** — raw JSON with no fences. The `extractJSON()` function then has to find the JSON block among:
- Raw JSON at the start
- JavaScript code blocks containing `{...}` (extensions)
- Any preamble text the LLM adds despite instructions

The failure path (observed with `vigolium agent swarm -t http://localhost:3000 --source ~/Desktop/demo/juice-shop --source-analysis-only --debug`):

1. The LLM adds some preamble before the JSON (common with large source analysis outputs)
2. `extractJSON` Strategy 4 scans for balanced `{}` blocks and may hit a JS code block first, or
3. The JSON itself has syntax errors (nested JSON-in-strings for request bodies is fragile)
4. Once `extractJSON` fails, `parseSourceAnalysisHybrid` returns error, legacy fallback also fails

## Proposed Fix

Wrap the JSON output in ` ```json ``` ` fences instead of requiring raw JSON.

### Why This Works

1. **Disambiguation** — `extractFencedBlocks()` (Strategy 3) already extracts all fenced blocks. We can specifically look for ` ```json ` blocks and distinguish them from ` ```javascript ` blocks, rather than relying on "first valid JSON block found anywhere"
2. **Resilience to preamble** — LLMs can add explanatory text before/after the code block and it won't matter
3. **No conflict with extensions** — JS extensions use ` ```javascript `, JSON uses ` ```json `, clear separation

## Implementation Plan

### Parser changes (`pkg/agent/pipeline_types.go`)

- Add a new `extractJSONFromFencedBlock(raw string)` helper that specifically looks for ` ```json ` blocks (not ` ```javascript ` or ` ```js `)
- In `parseSourceAnalysisHybrid`, try this targeted extraction first before falling back to `extractJSON()`

### Prompt changes (both templates)

Files:
- `public/presets/prompts/pipeline/pipeline-source-analysis.md`
- `public/presets/prompts/swarm/agent-swarm-source-analysis.md`

Changes:
- Change the output format section to wrap JSON in ` ```json ``` `
- Remove the "Start your response with `{`" rule
- Instead: "Wrap the JSON object in a ` ```json ``` ` code block"
- Keep the markdown format for extensions unchanged (` ```javascript ``` `)

### Fallback (for robustness)

If the ` ```json ``` ` block parse fails, fall back to the current `extractJSON()` strategy (handles raw JSON, any-fenced, balanced-brace scanning). This gives a 3-tier parsing pipeline:

1. ` ```json ``` ` fence extraction (new, preferred)
2. Generic `extractJSON()` — any JSON extraction (existing fallback)
3. Error

No need for a separate "markdown format fallback prompt" — the parser layering handles it. The key insight is that ` ```json ``` ` gives the parser a **reliable anchor** to find the structured data, while the current "raw JSON in the wild" approach is inherently fragile.

## Key Files

- `pkg/agent/parser.go` — `extractJSON()`, `extractFencedBlocks()`, `findJSONBlock()` helpers
- `pkg/agent/pipeline_types.go` — `ParseSourceAnalysisResult()`, `parseSourceAnalysisHybrid()`, `extractCodeBlockExtensions()`
- `pkg/agent/parser_test.go` — parser tests
- `pkg/agent/pipeline_types_test.go` — source analysis parsing tests
