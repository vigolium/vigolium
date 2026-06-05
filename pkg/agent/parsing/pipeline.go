package parsing

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"go.uber.org/zap"
)

// swarmPlanWrapper wraps SwarmPlan for JSON parsing flexibility.
type swarmPlanWrapper struct {
	Plan agenttypes.SwarmPlan `json:"swarm_plan"`
}

// ParseSwarmPlan extracts a SwarmPlan from raw agent output.
// It supports two formats:
//  1. Legacy: a single JSON object containing all fields including extensions[].code
//  2. Hybrid: a single-line JSON plan (module_tags, module_ids, focus_areas, notes)
//     followed by fenced ```javascript code blocks for extensions. Each extension
//     is preceded by a heading like "#### filename.js" and optionally "Reason: ...".
//
// module_tags is optional — when absent the downstream scan runs all modules.
func ParseSwarmPlan(raw string) (*agenttypes.SwarmPlan, error) {
	// Try markdown section format first (most robust for LLM output)
	if plan, err := parseSwarmPlanMarkdown(raw); err == nil && SwarmPlanHasContent(plan) {
		return plan, nil
	}

	// Try hybrid format: JSONL plan line + fenced code blocks for extensions
	if plan, err := parseSwarmPlanHybrid(raw); err == nil && SwarmPlanHasContent(plan) {
		return plan, nil
	}

	// Try all valid JSON blocks looking for one with recognizable plan fields
	for _, block := range FindAllJSONBlocks(raw) {
		if !IsJSON(block) {
			continue
		}
		var wrapper swarmPlanWrapper
		if json.Unmarshal([]byte(block), &wrapper) == nil && SwarmPlanHasContent(&wrapper.Plan) {
			return &wrapper.Plan, nil
		}
		var plan agenttypes.SwarmPlan
		if json.Unmarshal([]byte(block), &plan) == nil && SwarmPlanHasContent(&plan) {
			return &plan, nil
		}
	}

	// Last resort: regex-extract fields from garbled JSON.
	if plan := extractSwarmPlanRegex(raw); plan != nil {
		zap.L().Info("Recovered swarm plan via regex fallback",
			zap.Int("module_tags", len(plan.ModuleTags)))
		return plan, nil
	}

	return nil, fmt.Errorf("failed to parse swarm plan: no recognizable plan structure found")
}

// ParseSwarmExtensions extracts extensions, quick_checks, and snippets from
// raw agent output. This is used by the Phase 2 extension agent whose only job
// is to produce code — so we don't require module_tags or other plan fields.
// Returns nil if the output contains no extensions (e.g., "No custom extensions needed.").
func ParseSwarmExtensions(raw string) (*agenttypes.SwarmPlan, error) {
	plan := &agenttypes.SwarmPlan{}

	// Extract fenced JavaScript code blocks as full extensions
	if codeExts := ExtractCodeBlockExtensions(raw); len(codeExts) > 0 {
		plan.Extensions = codeExts
	}

	// Extract quick_checks from fenced JSON blocks
	for _, fenced := range ExtractFencedBlocks(raw) {
		fenced = strings.TrimSpace(fenced)
		if fenced == "" {
			continue
		}
		// Try as quick_checks array
		if fenced[0] == '[' {
			var qcs []agenttypes.QuickCheck
			if json.Unmarshal([]byte(fenced), &qcs) == nil && len(qcs) > 0 && qcs[0].ID != "" {
				plan.QuickChecks = append(plan.QuickChecks, qcs...)
				continue
			}
			// Try as snippets array
			var snips []agenttypes.Snippet
			if json.Unmarshal([]byte(fenced), &snips) == nil && len(snips) > 0 && snips[0].ID != "" {
				plan.Snippets = append(plan.Snippets, snips...)
				continue
			}
		}
	}

	// Also try keyed JSON extraction for quick_checks
	if len(plan.QuickChecks) == 0 {
		if qcBlock := FindJSONArrayInSection(raw, "quick_checks"); qcBlock != "" {
			var qcs []agenttypes.QuickCheck
			if json.Unmarshal([]byte(qcBlock), &qcs) == nil {
				plan.QuickChecks = qcs
			}
		}
	}

	// Check if output explicitly says no extensions needed
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "no custom extensions needed") || strings.Contains(lower, "no extensions needed") {
		return nil, nil
	}

	if len(plan.Extensions) == 0 && len(plan.QuickChecks) == 0 && len(plan.Snippets) == 0 {
		return nil, fmt.Errorf("no extensions found in extension agent output")
	}

	return plan, nil
}

// SwarmPlanHasContent returns true if the plan contains at least one meaningful field.
// module_tags is no longer required — a plan with only focus_areas, extensions, etc. is valid.
func SwarmPlanHasContent(plan *agenttypes.SwarmPlan) bool {
	if plan == nil {
		return false
	}
	return len(plan.ModuleTags) > 0 ||
		len(plan.ModuleIDs) > 0 ||
		len(plan.Extensions) > 0 ||
		len(plan.QuickChecks) > 0 ||
		len(plan.Snippets) > 0 ||
		len(plan.FocusAreas) > 0 ||
		plan.Notes != ""
}

// moduleTagsRegex matches a "module_tags" JSON array in possibly garbled text.
var moduleTagsRegex = regexp.MustCompile(`"module_tags"\s*:\s*\[((?:"[^"]*"(?:\s*,\s*)?)*)\]`)

// moduleIDsRegex matches a "module_ids" JSON array in possibly garbled text.
var moduleIDsRegex = regexp.MustCompile(`"module_ids"\s*:\s*\[((?:"[^"]*"(?:\s*,\s*)?)*)\]`)

// focusAreasRegex matches a "focus_areas" JSON array.
var focusAreasRegex = regexp.MustCompile(`"focus_areas"\s*:\s*\[((?:"[^"]*"(?:\s*,\s*)?)*)\]`)

// notesRegex matches a "notes" JSON string.
var notesRegex = regexp.MustCompile(`"notes"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// extractSwarmPlanRegex attempts to recover a minimal SwarmPlan from garbled JSON
// by regex-extracting individual fields. Returns nil if no recognizable fields are found.
func extractSwarmPlanRegex(raw string) *agenttypes.SwarmPlan {
	plan := &agenttypes.SwarmPlan{}

	// Try extracting module_tags (optional)
	if m := moduleTagsRegex.FindStringSubmatch(raw); len(m) >= 2 {
		var tags []string
		if json.Unmarshal([]byte("["+m[1]+"]"), &tags) == nil {
			plan.ModuleTags = tags
		}
	}

	// Try extracting module_ids (optional)
	if m := moduleIDsRegex.FindStringSubmatch(raw); len(m) >= 2 {
		var ids []string
		if json.Unmarshal([]byte("["+m[1]+"]"), &ids) == nil {
			plan.ModuleIDs = ids
		}
	}

	// Best-effort extraction of other fields
	if fm := focusAreasRegex.FindStringSubmatch(raw); len(fm) >= 2 {
		var fa []string
		if json.Unmarshal([]byte("["+fm[1]+"]"), &fa) == nil {
			plan.FocusAreas = fa
		}
	}
	if nm := notesRegex.FindStringSubmatch(raw); len(nm) >= 2 {
		plan.Notes = nm[1]
	}

	// Extract code block extensions (hybrid format)
	if codeExts := ExtractCodeBlockExtensions(raw); len(codeExts) > 0 {
		plan.Extensions = codeExts
	}

	if !SwarmPlanHasContent(plan) {
		return nil
	}
	return plan
}

// parseSwarmPlanHybrid parses the hybrid output format where the plan JSON is a
// single line and extensions are in fenced ```javascript code blocks.
func parseSwarmPlanHybrid(raw string) (*agenttypes.SwarmPlan, error) {
	lines := strings.Split(raw, "\n")

	// Step 1: Find and parse the plan JSON line — look for lines containing known plan fields.
	planKeys := []string{"\"module_tags\"", "\"module_ids\"", "\"focus_areas\"", "\"extensions\"", "\"quick_checks\"", "\"snippets\""}
	var plan agenttypes.SwarmPlan
	planFound := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hasPlanKey := false
		for _, key := range planKeys {
			if strings.Contains(line, key) {
				hasPlanKey = true
				break
			}
		}
		if !hasPlanKey {
			continue
		}
		if json.Unmarshal([]byte(line), &plan) == nil && SwarmPlanHasContent(&plan) {
			planFound = true
			break
		}
		// Also try extracting JSON from this line (in case of surrounding text)
		if extracted := FindJSONBlock(line); extracted != "" {
			if json.Unmarshal([]byte(extracted), &plan) == nil && SwarmPlanHasContent(&plan) {
				planFound = true
				break
			}
		}
	}

	// Fallback: try all JSON blocks in the full text (handles corrupted first block + valid later block)
	if !planFound {
		for _, block := range FindAllJSONBlocks(raw) {
			if json.Unmarshal([]byte(block), &plan) == nil && SwarmPlanHasContent(&plan) {
				planFound = true
				break
			}
		}
	}

	if !planFound {
		return nil, fmt.Errorf("no plan JSON line found")
	}

	// Step 2: Extract fenced JavaScript code blocks as extensions (supplement, don't overwrite)
	if codeExts := ExtractCodeBlockExtensions(raw); len(codeExts) > 0 {
		plan.Extensions = append(plan.Extensions, codeExts...)
	}

	return &plan, nil
}

// parseSwarmPlanMarkdown parses the markdown section format where the LLM outputs
// structured sections with ## headings instead of a single JSON blob.
// This format is inherently more robust against LLM token-level corruption.
func parseSwarmPlanMarkdown(raw string) (*agenttypes.SwarmPlan, error) {
	sections := splitMarkdownSections(raw)

	// At least one recognized section must be present for this to be a markdown-format plan.
	recognizedSections := []string{"MODULE_TAGS", "MODULE_IDS", "FOCUS_AREAS", "NOTES", "NEEDS_EXTENSIONS"}
	hasSection := false
	for _, name := range recognizedSections {
		if _, ok := sections[name]; ok {
			hasSection = true
			break
		}
	}
	if !hasSection {
		return nil, fmt.Errorf("no recognized markdown sections found")
	}

	plan := &agenttypes.SwarmPlan{}

	if tagsRaw, ok := sections["MODULE_TAGS"]; ok {
		plan.ModuleTags = parseCommaSeparated(tagsRaw)
	}

	if idsRaw, ok := sections["MODULE_IDS"]; ok {
		plan.ModuleIDs = parseCommaSeparated(idsRaw)
	}

	if faRaw, ok := sections["FOCUS_AREAS"]; ok {
		plan.FocusAreas = parseBulletList(faRaw)
	}

	if skillsRaw, ok := sections["RECOMMENDED_SKILLS"]; ok {
		// Skill names have no spaces, so keep only the leading token of each
		// bullet — tolerant of the model appending "- name — why it applies".
		for _, item := range parseBulletList(skillsRaw) {
			if f := strings.Fields(item); len(f) > 0 {
				if name := strings.Trim(f[0], "`*:"); name != "" {
					plan.RecommendedSkills = append(plan.RecommendedSkills, name)
				}
			}
		}
	}

	if notes, ok := sections["NOTES"]; ok {
		plan.Notes = strings.TrimSpace(notes)
	}

	if ne, ok := sections["NEEDS_EXTENSIONS"]; ok {
		cleaned := strings.TrimSpace(stripCodeFenceMarkers(ne))
		lines := strings.SplitN(cleaned, "\n", 2)

		// Try labeled format first: "conclusion: yes" / "reason: ..."
		if conclusionVal, ok := extractLabeledValue(lines[0], "conclusion"); ok {
			decision := strings.ToLower(conclusionVal)
			plan.NeedsExtensions = decision == "yes" || decision == "true"
			if len(lines) > 1 {
				if reasonVal, ok := extractLabeledValue(lines[1], "reason"); ok {
					plan.NeedsExtensionsReason = reasonVal
				} else {
					plan.NeedsExtensionsReason = strings.TrimSpace(lines[1])
				}
			}
		} else {
			// Legacy plain format: first line is yes/no, second line is reason
			decision := strings.TrimSpace(strings.ToLower(lines[0]))
			plan.NeedsExtensions = decision == "yes" || decision == "true"
			if len(lines) > 1 {
				plan.NeedsExtensionsReason = strings.TrimSpace(lines[1])
			}
		}
	}

	// Extract extensions from fenced code blocks (existing logic handles #### headings)
	if codeExts := ExtractCodeBlockExtensions(raw); len(codeExts) > 0 {
		plan.Extensions = codeExts
	}

	// Extract quick_checks from JSON — try keyed field first, then standalone arrays in fences
	if qcBlock := FindJSONArrayInSection(raw, "quick_checks"); qcBlock != "" {
		var qcs []agenttypes.QuickCheck
		if json.Unmarshal([]byte(qcBlock), &qcs) == nil {
			plan.QuickChecks = qcs
		}
	}
	if len(plan.QuickChecks) == 0 {
		// Try fenced JSON blocks as standalone quick check arrays
		for _, fenced := range ExtractFencedBlocks(raw) {
			fenced = strings.TrimSpace(fenced)
			if fenced == "" || fenced[0] != '[' {
				continue
			}
			var qcs []agenttypes.QuickCheck
			if json.Unmarshal([]byte(fenced), &qcs) == nil && len(qcs) > 0 && qcs[0].ID != "" {
				plan.QuickChecks = qcs
				break
			}
		}
	}

	return plan, nil
}

// splitMarkdownSections splits text by ## headings and returns a map of section name to content.
func splitMarkdownSections(raw string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(raw, "\n")

	var currentSection string
	var content strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") && !strings.HasPrefix(trimmed, "### ") {
			// Save previous section
			if currentSection != "" {
				sections[currentSection] = content.String()
			}
			currentSection = strings.TrimSpace(trimmed[3:])
			content.Reset()
			continue
		}
		if currentSection != "" {
			if content.Len() > 0 {
				content.WriteByte('\n')
			}
			content.WriteString(line)
		}
	}
	// Save last section
	if currentSection != "" {
		sections[currentSection] = content.String()
	}
	return sections
}

// parseCommaSeparated splits a string by commas and/or newlines and returns trimmed,
// non-empty tokens. It also strips code fence markers (```) which LLMs sometimes
// wrap around values in markdown sections.
func parseCommaSeparated(s string) []string {
	// Strip code fence markers (``` or ```lang) — agents sometimes wrap values in fences
	s = stripCodeFenceMarkers(s)

	var result []string
	// Split by commas first; if that yields only one token containing newlines,
	// fall back to newline splitting (agents sometimes use newline-separated lists).
	commaParts := strings.Split(s, ",")
	if len(commaParts) == 1 && strings.Contains(s, "\n") {
		// Newline-separated list
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				result = append(result, line)
			}
		}
	} else {
		for _, token := range commaParts {
			token = strings.TrimSpace(token)
			if token != "" {
				result = append(result, token)
			}
		}
	}
	return result
}

// stripCodeFenceMarkers removes ``` lines (with optional language tag) from a string.
func stripCodeFenceMarkers(s string) string {
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			continue
		}
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(line)
	}
	return out.String()
}

// extractLabeledValue checks if a line has the form "label: value" and returns the value.
func extractLabeledValue(line, label string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	prefix := label + ":"
	if len(trimmed) >= len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix) {
		return strings.TrimSpace(trimmed[len(prefix):]), true
	}
	return "", false
}

// parseBulletList extracts items from a bulleted markdown list.
func parseBulletList(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") {
			item := strings.TrimSpace(line[2:])
			if item != "" {
				result = append(result, item)
			}
		} else if strings.HasPrefix(line, "* ") {
			item := strings.TrimSpace(line[2:])
			if item != "" {
				result = append(result, item)
			}
		} else if line != "" {
			// Plain text line (not bulleted)
			result = append(result, line)
		}
	}
	return result
}

// FindJSONArrayInSection searches for a JSON array associated with a key name in the raw text.
func FindJSONArrayInSection(raw, key string) string {
	pattern := `"` + key + `"`
	idx := strings.Index(raw, pattern)
	if idx < 0 {
		return ""
	}
	// Find the '[' after the key
	rest := raw[idx+len(pattern):]
	for i, ch := range rest {
		if ch == '[' {
			block := FindJSONBlockFrom(rest, i)
			if block != "" {
				return block
			}
		}
		if ch != ':' && ch != ' ' && ch != '\t' {
			break
		}
	}
	return ""
}

// ExtractCodeBlockExtensions extracts GeneratedExtension entries from fenced
// ```javascript code blocks in the raw output. It looks for heading patterns
// like "#### filename.js" or "### filename.js" before each block, and
// "Reason: ..." lines for the reason field.
func ExtractCodeBlockExtensions(raw string) []agenttypes.GeneratedExtension {
	var extensions []agenttypes.GeneratedExtension
	unnamedCounter := 0
	lines := strings.Split(raw, "\n")

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		// Look for opening fence: ```javascript or ```js
		if !IsJSFenceOpen(trimmed) {
			continue
		}

		fenceLineIdx := i

		// Collect code until closing ```
		var code strings.Builder
		i++
		for i < len(lines) {
			if strings.TrimSpace(lines[i]) == "```" {
				break
			}
			if code.Len() > 0 {
				code.WriteByte('\n')
			}
			code.WriteString(lines[i])
			i++
		}

		codeStr := code.String()
		if codeStr == "" {
			continue
		}

		// Extract filename from a preceding heading (#### filename.js / ### filename.js)
		// and reason from a "Reason: ..." line. Scan backwards from the fence line.
		filename, reason := ExtractExtensionMeta(lines, fenceLineIdx)

		// If no heading filename, try to extract from module id in the code
		if filename == "" {
			filename = ExtractFilenameFromCode(codeStr)
		}
		if filename == "extension.js" {
			filename = fmt.Sprintf("extension-%d.js", unnamedCounter)
			unnamedCounter++
		}

		extensions = append(extensions, agenttypes.GeneratedExtension{
			Filename: filename,
			Code:     codeStr,
			Reason:   reason,
		})
	}

	return extensions
}

// IsJSFenceOpen returns true if the line opens a JavaScript or TypeScript code fence.
func IsJSFenceOpen(line string) bool {
	if strings.HasPrefix(line, "```javascript") {
		return true
	}
	// Match ```js but not ```json
	if strings.HasPrefix(line, "```js") && !strings.HasPrefix(line, "```json") {
		return true
	}
	// Match ```typescript and ```ts but not ```tsx or ```tsconfig
	if strings.HasPrefix(line, "```typescript") {
		return true
	}
	if strings.HasPrefix(line, "```ts") && !strings.HasPrefix(line, "```tsx") && !strings.HasPrefix(line, "```tsconfig") {
		return true
	}
	return false
}

// ParseExtensionsFromJSON attempts to extract extensions from a structured
// {"extensions": [...]} JSON block in the agent output. Returns nil if no
// structured extensions are found.
func ParseExtensionsFromJSON(raw string) []agenttypes.GeneratedExtension {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil
	}

	// Try wrapped format: {"extensions": [...]}
	var output agenttypes.AgentExtensionsOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err == nil && len(output.Extensions) > 0 {
		return output.Extensions
	}

	// Try as bare array: [{"filename": ..., "code": ..., "reason": ...}, ...]
	var exts []agenttypes.GeneratedExtension
	if err := json.Unmarshal([]byte(jsonStr), &exts); err == nil && len(exts) > 0 {
		return exts
	}

	return nil
}

// ExtractExtensionMeta scans lines backwards from fenceIdx to find a heading
// containing a .js filename and an optional "Reason:" line.
func ExtractExtensionMeta(lines []string, fenceIdx int) (filename, reason string) {
	// Scan up to 5 lines backwards looking for metadata
	start := fenceIdx - 5
	if start < 0 {
		start = 0
	}
	for j := fenceIdx; j >= start; j-- {
		line := strings.TrimSpace(lines[j])

		// Heading with filename: "#### custom-check.js" or "### custom-check.js"
		if filename == "" && strings.HasPrefix(line, "#") {
			// Strip leading # characters and whitespace
			name := strings.TrimLeft(line, "# ")
			if strings.HasSuffix(name, ".js") {
				filename = name
			}
		}

		// Reason line
		if reason == "" && strings.HasPrefix(line, "Reason:") {
			reason = strings.TrimSpace(strings.TrimPrefix(line, "Reason:"))
		}
	}
	return filename, reason
}

// ExtractFilenameFromCode tries to extract a filename from the module id in JS code.
// It looks for patterns like id: "custom-something" and converts to custom-something.js.
func ExtractFilenameFromCode(code string) string {
	// Look for id: "..." or id: '...'
	for _, pattern := range []string{`id: "`, `id: '`, `id:"`, `id:'`} {
		idx := strings.Index(code, pattern)
		if idx < 0 {
			continue
		}
		start := idx + len(pattern)
		quote := code[start-1] // matching quote character
		end := strings.IndexByte(code[start:], quote)
		if end > 0 {
			return code[start:start+end] + ".js"
		}
	}
	return "extension.js"
}

// attackPlanWrapper wraps AttackPlan for JSON parsing flexibility.
type attackPlanWrapper struct {
	Plan agenttypes.AttackPlan `json:"plan"`
}

// triageResultWrapper wraps TriageResult for JSON parsing flexibility.
type triageResultWrapper struct {
	Triage agenttypes.TriageResult `json:"triage"`
}

// sourceAnalysisWrapper wraps SourceAnalysisResult for JSON parsing flexibility.
type sourceAnalysisWrapper struct {
	SourceAnalysis agenttypes.SourceAnalysisResult `json:"source_analysis"`
}

// AttackPlanHasContent returns true if the plan has at least one meaningful field.
func AttackPlanHasContent(plan *agenttypes.AttackPlan) bool {
	if plan == nil {
		return false
	}
	return len(plan.ModuleTags) > 0 ||
		len(plan.ModuleIDs) > 0 ||
		len(plan.FocusAreas) > 0 ||
		len(plan.SkipPaths) > 0 ||
		len(plan.Endpoints) > 0 ||
		plan.Notes != ""
}

// ParseAttackPlan extracts an AttackPlan from raw agent output.
func ParseAttackPlan(raw string) (*agenttypes.AttackPlan, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try wrapped format: {"plan": {...}}
	var wrapper attackPlanWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && AttackPlanHasContent(&wrapper.Plan) {
		return &wrapper.Plan, nil
	}

	// Try direct format: {...}
	var plan agenttypes.AttackPlan
	if err := json.Unmarshal([]byte(jsonStr), &plan); err == nil && AttackPlanHasContent(&plan) {
		return &plan, nil
	}

	return nil, fmt.Errorf("failed to parse attack plan from JSON: no recognizable plan structure found")
}

// ParseTriageResult extracts a TriageResult from raw agent output.
func ParseTriageResult(raw string) (*agenttypes.TriageResult, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try wrapped format: {"triage": {...}}
	var wrapper triageResultWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && wrapper.Triage.Verdict != "" {
		return &wrapper.Triage, nil
	}

	// Try direct format: {...}
	var result agenttypes.TriageResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err == nil && result.Verdict != "" {
		return &result, nil
	}

	return nil, fmt.Errorf("failed to parse triage result from JSON: invalid structure (expected verdict)")
}

// ParseTriageConfirmResult extracts a TriageConfirmResult from raw agent output.
// Accepted verdicts are "confirmed" and "false_positive". Verdict values are
// trimmed and lowercased before validation; aliases like "fp" or
// "false-positive" are normalized to "false_positive".
func ParseTriageConfirmResult(raw string) (*agenttypes.TriageConfirmResult, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	var result agenttypes.TriageConfirmResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse triage confirm result: %w", err)
	}

	v := strings.ToLower(strings.TrimSpace(result.Verdict))
	switch v {
	case "confirmed", "confirm", "true_positive", "true-positive", "tp":
		result.Verdict = agenttypes.TriageVerdictConfirmed
	case "false_positive", "false-positive", "fp", "false":
		result.Verdict = agenttypes.TriageVerdictFalsePositive
	default:
		return nil, fmt.Errorf("triage confirm result has invalid verdict %q (want %q or %q)",
			result.Verdict, agenttypes.TriageVerdictConfirmed, agenttypes.TriageVerdictFalsePositive)
	}
	return &result, nil
}

// ParseSourceAnalysisResult extracts a SourceAnalysisResult from raw agent output.
// It uses a layered strategy to maximize recovery from malformed LLM output:
//  1. JSONL: Parse records from a ```jsonl fenced block (one JSON object per line — blast-radius reduction)
//  2. Hybrid: JSON object with http_records/session_config + fenced ```javascript code blocks
//  3. Multi-block merge: Merge http_records across multiple ```json blocks
//  4. Legacy: Single JSON object containing all fields
//  5. Garbled recovery: Scan raw text for individual {"method":...} objects
//  6. Session-config-only: Return session_config when present without routes (auth sub-agent)
//  7. Extensions-only fallback: Return any ```javascript code blocks even when no records parse
func ParseSourceAnalysisResult(raw string) (*agenttypes.SourceAnalysisResult, error) {
	// Lazily extract code block extensions — only computed once, on first access.
	var codeExts []agenttypes.GeneratedExtension
	codeExtsLoaded := false
	getCodeExts := func() []agenttypes.GeneratedExtension {
		if !codeExtsLoaded {
			codeExts = ExtractCodeBlockExtensions(raw)
			codeExtsLoaded = true
		}
		return codeExts
	}

	mergeCodeExts := func(result *agenttypes.SourceAnalysisResult) {
		if exts := getCodeExts(); len(exts) > 0 {
			result.Extensions = MergeExtensionsByFilename(result.Extensions, exts)
		}
	}

	// Strategy 1: Try JSONL from ```jsonl fenced block (blast-radius reduction for large route lists)
	if jsonlContent, err := ExtractJSONLFromFencedBlock(raw); err == nil {
		records, badCount := ParseHTTPRecordJSONL(jsonlContent)
		if len(records) > 0 {
			if badCount > 0 {
				zap.L().Info("source-analysis: JSONL parsing skipped malformed lines",
					zap.Int("good", len(records)),
					zap.Int("bad", badCount))
			}
			result := &agenttypes.SourceAnalysisResult{HTTPRecords: records}
			// Also extract session_config from any ```json block in the same output
			result.SessionConfig = ExtractSessionConfigFromGarbled(raw)
			mergeCodeExts(result)
			return result, nil
		}
	}

	// Strategy 2: Try hybrid format — JSON with records/session_config + fenced code blocks for extensions
	if result, err := parseSourceAnalysisHybrid(raw); err == nil && len(result.HTTPRecords) > 0 {
		mergeCodeExts(result)
		return result, nil
	}

	// Strategy 3: Try multi-block merge — when agent outputs multiple JSON blocks (e.g., separate tasks),
	// merge http_records from all parseable blocks into a single result.
	if result := mergeMultiBlockSourceAnalysis(raw); result != nil && len(result.HTTPRecords) > 0 {
		mergeCodeExts(result)
		return result, nil
	}

	// Strategy 4: Fall back to legacy all-in-one JSON format
	jsonStr, jsonErr := ExtractJSON(raw)
	if jsonErr == nil {
		// Try wrapped format: {"source_analysis": {...}}
		var wrapper sourceAnalysisWrapper
		if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.SourceAnalysis.HTTPRecords) > 0 {
			result := &wrapper.SourceAnalysis
			mergeCodeExts(result)
			return result, nil
		}

		// Try direct format: {...}
		var result agenttypes.SourceAnalysisResult
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			mergeCodeExts(&result)
			if len(result.HTTPRecords) > 0 {
				return &result, nil
			}
		} else {
			// Array-of-records fallback: the LLM sometimes outputs a bare JSON array
			var records []agenttypes.AgentHTTPRecord
			if arrErr := json.Unmarshal([]byte(jsonStr), &records); arrErr == nil && len(records) > 0 {
				res := &agenttypes.SourceAnalysisResult{HTTPRecords: records}
				mergeCodeExts(res)
				return res, nil
			}
		}
	}

	// Strategy 5: Garbled recovery — scan raw text for individual {"method":...} objects
	if strings.Contains(raw, `"method"`) {
		records, failCount := ExtractRecordsFromGarbled(raw)
		if len(records) > 0 {
			zap.L().Warn("Recovered HTTP records from garbled output",
				zap.Int("recovered", len(records)),
				zap.Int("failed", failCount))
			result := &agenttypes.SourceAnalysisResult{HTTPRecords: records}
			result.SessionConfig = ExtractSessionConfigFromGarbled(raw)
			mergeCodeExts(result)
			return result, nil
		}
	}

	// Strategy 6: Session-config-only fallback — the auth sub-agent legitimately returns
	// empty http_records with a valid session_config. Extract it so it's not lost.
	if sessionCfg := ExtractSessionConfigFromGarbled(raw); sessionCfg != nil && len(sessionCfg.Sessions) > 0 {
		result := &agenttypes.SourceAnalysisResult{SessionConfig: sessionCfg}
		mergeCodeExts(result)
		return result, nil
	}

	// Strategy 7: Extensions-only fallback — return JS code blocks even when no records parse
	if exts := getCodeExts(); len(exts) > 0 {
		return &agenttypes.SourceAnalysisResult{Extensions: exts}, nil
	}

	if jsonErr != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", jsonErr)
	}
	return nil, fmt.Errorf("failed to parse source analysis result: no http_records found")
}

// NormalizeSessionConfigKeys fixes common LLM key-name garbling in session config JSON.
// Maps: "session" -> "session_config", "sessions_config" -> "sessions", "sessionConfig" -> "session_config".
func NormalizeSessionConfigKeys(block string) string {
	// Order matters — replace the garbled nested key first, then the outer key.
	// "sessions_config" -> "sessions" (garbled inner key)
	block = strings.ReplaceAll(block, `"sessions_config"`, `"sessions"`)
	// "sessionConfig" -> "session_config" (camelCase variant)
	block = strings.ReplaceAll(block, `"sessionConfig"`, `"session_config"`)
	// "session" -> "session_config" (truncated key) — but only when followed by :{
	// to avoid replacing "session" inside "session_config" or "sessions"
	block = strings.ReplaceAll(block, `"session":{`, `"session_config":{`)
	return block
}

// ExtractSessionConfigFromJSON scans all ```json fenced blocks for session_config data.
// Returns the first valid session_config found, or nil if none.
func ExtractSessionConfigFromJSON(raw string) *agenttypes.AgentSessionConfig {
	blocks := ExtractAllJSONFromFencedBlocks(raw)
	for _, block := range blocks {
		// Try as-is first, then with key normalization.
		for _, b := range []string{block, NormalizeSessionConfigKeys(block)} {
			var sa agenttypes.SourceAnalysisResult
			if err := json.Unmarshal([]byte(b), &sa); err == nil && sa.SessionConfig != nil && len(sa.SessionConfig.Sessions) > 0 {
				return sa.SessionConfig
			}
			// Try wrapper format too
			var wrapper sourceAnalysisWrapper
			if err := json.Unmarshal([]byte(b), &wrapper); err == nil && wrapper.SourceAnalysis.SessionConfig != nil {
				return wrapper.SourceAnalysis.SessionConfig
			}
		}
	}
	return nil
}

// ExtractSessionConfigFromGarbled recovers session config from garbled agent output.
// It uses a layered approach: clean extraction first, then needle-based scanning
// for "session_config", "sessions", and individual "login" objects.
func ExtractSessionConfigFromGarbled(raw string) *agenttypes.AgentSessionConfig {
	// Layer 1: delegate to clean path — zero overhead for well-formed output.
	// ExtractSessionConfigFromJSON already applies key normalization internally.
	if cfg := ExtractSessionConfigFromJSON(raw); cfg != nil {
		return cfg
	}

	// Normalize key names in the full raw text for subsequent needle searches.
	normalized := NormalizeSessionConfigKeys(raw)

	// Layer 2: scan for "session_config" needle, extract enclosing JSON block.
	for _, text := range []string{raw, normalized} {
		if idx := strings.Index(text, `"session_config"`); idx >= 0 {
			// Walk backward to find the opening { for the enclosing object
			start := idx - 1
			for start >= 0 && text[start] != '{' {
				start--
			}
			if start >= 0 {
				block := FindJSONBlockFrom(text, start)
				if block != "" {
					// Try as SourceAnalysisResult
					var sa agenttypes.SourceAnalysisResult
					if err := json.Unmarshal([]byte(block), &sa); err == nil && sa.SessionConfig != nil && len(sa.SessionConfig.Sessions) > 0 {
						return sa.SessionConfig
					}
					// Try as bare AgentSessionConfig
					var cfg agenttypes.AgentSessionConfig
					if err := json.Unmarshal([]byte(block), &cfg); err == nil && len(cfg.Sessions) > 0 {
						return &cfg
					}
				}
			}
		}
	}

	// Layer 3: scan for "sessions" needle with enclosing object.
	for _, text := range []string{raw, normalized} {
		if idx := strings.Index(text, `"sessions"`); idx >= 0 {
			start := idx - 1
			for start >= 0 && text[start] != '{' {
				start--
			}
			if start >= 0 {
				block := FindJSONBlockFrom(text, start)
				if block != "" {
					var cfg agenttypes.AgentSessionConfig
					if err := json.Unmarshal([]byte(block), &cfg); err == nil && len(cfg.Sessions) > 0 {
						return &cfg
					}
				}
			}
		}
	}

	// Layer 4: scan for individual "login" objects containing "url" — JSON unmarshal
	needle := `"login"`
	var entries []agenttypes.AgentSessionEntry
	i := 0
	for i < len(raw) {
		idx := strings.Index(raw[i:], needle)
		if idx < 0 {
			break
		}
		pos := i + idx

		// Walk backward to find the opening { for the session entry
		start := pos - 1
		for start >= 0 && raw[start] != '{' {
			start--
		}
		if start < 0 {
			i = pos + len(needle)
			continue
		}

		block := FindJSONBlockFrom(raw, start)
		if block == "" {
			i = pos + len(needle)
			continue
		}

		var entry agenttypes.AgentSessionEntry
		if err := json.Unmarshal([]byte(block), &entry); err == nil && entry.Name != "" {
			entries = append(entries, entry)
		}

		i = start + len(block)
	}

	if len(entries) > 0 {
		return &agenttypes.AgentSessionConfig{Sessions: entries}
	}

	// Layer 5: regex-based field extraction for deeply garbled JSON.
	if cfg := ExtractSessionConfigFromRegex(raw); cfg != nil {
		return cfg
	}

	return nil
}

// sessionNameRe matches "name": "value" patterns in garbled JSON.
var sessionNameRe = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)

// sessionRoleRe matches "role": "primary" or "role": "compare" patterns.
var sessionRoleRe = regexp.MustCompile(`"role"\s*:\s*"(primary|compare)"`)

// loginURLRe matches "url": "http..." patterns inside login objects.
var loginURLRe = regexp.MustCompile(`"url"\s*:\s*"(https?://[^"]+)"`)

// loginMethodRe matches "method": "POST" etc.
var loginMethodRe = regexp.MustCompile(`"method"\s*:\s*"([A-Z]+)"`)

// loginBodyRe matches "body": "..." patterns (handles escaped quotes).
var loginBodyRe = regexp.MustCompile(`"body"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// loginContentTypeRe matches content_type values (may have garbled key).
var loginContentTypeRe = regexp.MustCompile(`content_type[^"]*"\s*:\s*"(application/[^"]+)"`)

// ExtractSessionConfigFromRegex recovers session config from deeply garbled JSON
// by scanning for individual field values with regexes.
func ExtractSessionConfigFromRegex(raw string) *agenttypes.AgentSessionConfig {
	// Find all session name matches — these are our anchors for splitting regions
	nameMatches := sessionNameRe.FindAllStringIndex(raw, -1)
	if len(nameMatches) == 0 {
		return nil
	}

	// Check that this is actually session config context (not unrelated "name" fields)
	if !strings.Contains(raw, `"login"`) && !strings.Contains(raw, `"sessions"`) && !strings.Contains(raw, `"session_config"`) {
		return nil
	}

	var entries []agenttypes.AgentSessionEntry

	for idx, nameLoc := range nameMatches {
		// Extract the region for this session entry
		regionStart := nameLoc[0]
		regionEnd := len(raw)
		if idx+1 < len(nameMatches) {
			regionEnd = nameMatches[idx+1][0]
		}
		region := raw[regionStart:regionEnd]

		// Extract name
		nameSubmatch := sessionNameRe.FindStringSubmatch(region)
		if nameSubmatch == nil {
			continue
		}
		name := nameSubmatch[1]

		// Skip names that don't look like session identifiers
		if len(name) > 50 || strings.ContainsAny(name, "{}[]") {
			continue
		}

		entry := agenttypes.AgentSessionEntry{Name: name}

		// Extract role
		if m := sessionRoleRe.FindStringSubmatch(region); m != nil {
			entry.Role = m[1]
		}

		// Extract login flow
		if urlMatch := loginURLRe.FindStringSubmatch(region); urlMatch != nil {
			login := &agenttypes.AgentLoginFlow{
				URL: urlMatch[1],
			}
			if m := loginMethodRe.FindStringSubmatch(region); m != nil {
				login.Method = m[1]
			} else {
				login.Method = "POST" // login flows are almost always POST
			}
			if m := loginContentTypeRe.FindStringSubmatch(region); m != nil {
				login.ContentType = m[1]
			}
			if m := loginBodyRe.FindStringSubmatch(region); m != nil {
				login.Body = m[1]
			}
			entry.Login = login
		}

		entries = append(entries, entry)
	}

	if len(entries) > 0 {
		return &agenttypes.AgentSessionConfig{Sessions: entries}
	}
	return nil
}

// SessionConfigNeedsRepair determines whether LLM repair should be attempted for session config.
func SessionConfigNeedsRepair(cfg *agenttypes.AgentSessionConfig, rawOutput string) bool {
	// Case A: no config at all, but raw output has session-related keywords
	if cfg == nil || len(cfg.Sessions) == 0 {
		hasSessionKeywords := strings.Contains(rawOutput, `"session_config"`) ||
			strings.Contains(rawOutput, `"sessions"`) ||
			(strings.Contains(rawOutput, `"login"`) && strings.Contains(rawOutput, `"url"`))
		return hasSessionKeywords
	}

	// Case B: config recovered but all login flows lost extract rules
	if !strings.Contains(rawOutput, `"extract"`) {
		return false
	}
	for _, s := range cfg.Sessions {
		if s.Login != nil && len(s.Login.Extract) > 0 {
			return false
		}
	}
	return true
}

// MergeExtensionsByFilename merges two extension slices, deduplicating by filename.
// Extensions from the second slice (codeExts) take precedence on filename collisions
// since fenced code blocks are the canonical source for extension code.
func MergeExtensionsByFilename(existing, codeExts []agenttypes.GeneratedExtension) []agenttypes.GeneratedExtension {
	if len(existing) == 0 {
		return codeExts
	}
	if len(codeExts) == 0 {
		return existing
	}
	// Start with codeExts (they take precedence), then append unique entries from existing.
	seen := make(map[string]struct{}, len(codeExts))
	for _, ext := range codeExts {
		seen[ext.Filename] = struct{}{}
	}
	merged := make([]agenttypes.GeneratedExtension, len(codeExts), len(codeExts)+len(existing))
	copy(merged, codeExts)
	for _, ext := range existing {
		if _, ok := seen[ext.Filename]; !ok {
			merged = append(merged, ext)
			seen[ext.Filename] = struct{}{}
		}
	}
	return merged
}

// mergeMultiBlockSourceAnalysis tries to parse multiple JSON fenced blocks and merge
// their http_records into a single SourceAnalysisResult.
func mergeMultiBlockSourceAnalysis(raw string) *agenttypes.SourceAnalysisResult {
	blocks := ExtractAllJSONFromFencedBlocks(raw)
	if len(blocks) == 0 {
		return nil
	}

	merged := &agenttypes.SourceAnalysisResult{}
	anyParsed := false

	for _, block := range blocks {
		// Try as SourceAnalysisResult
		var result agenttypes.SourceAnalysisResult
		if err := json.Unmarshal([]byte(block), &result); err == nil {
			if len(result.HTTPRecords) > 0 {
				merged.HTTPRecords = append(merged.HTTPRecords, result.HTTPRecords...)
				anyParsed = true
			}
			if result.SessionConfig != nil && merged.SessionConfig == nil {
				merged.SessionConfig = result.SessionConfig
			}
			if len(result.Extensions) > 0 {
				merged.Extensions = append(merged.Extensions, result.Extensions...)
			}
		} else {
			// Array-of-records fallback
			var records []agenttypes.AgentHTTPRecord
			if arrErr := json.Unmarshal([]byte(block), &records); arrErr == nil && len(records) > 0 {
				merged.HTTPRecords = append(merged.HTTPRecords, records...)
				anyParsed = true
			}
		}
	}

	if !anyParsed {
		return nil
	}
	return merged
}

// ExtractAllJSONFromFencedBlocks extracts valid JSON content from ALL ```json fenced
// code blocks (not just the first). Returns all parseable JSON strings.
func ExtractAllJSONFromFencedBlocks(raw string) []string {
	var results []string
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		if !strings.HasPrefix(trimmed, "```json") {
			continue
		}
		rest := strings.TrimPrefix(trimmed, "```json")
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}

		var content strings.Builder
		i++
		for i < len(lines) {
			if strings.TrimSpace(lines[i]) == "```" {
				break
			}
			if content.Len() > 0 {
				content.WriteByte('\n')
			}
			content.WriteString(lines[i])
			i++
		}

		candidate := strings.TrimSpace(content.String())
		if candidate == "" {
			continue
		}

		if IsJSON(candidate) {
			results = append(results, candidate)
		} else if block := FindJSONBlock(candidate); block != "" && IsJSON(block) {
			results = append(results, block)
		}
	}
	return results
}

// parseSourceAnalysisHybrid parses the hybrid output format where the JSON contains
// http_records and session_config, and extensions are in fenced ```javascript code blocks.
func parseSourceAnalysisHybrid(raw string) (*agenttypes.SourceAnalysisResult, error) {
	// Try extracting JSON from a ```json fenced block first (preferred — unambiguous anchor).
	// Fall back to generic ExtractJSON() for backward compatibility with raw-JSON output.
	jsonStr, err := ExtractJSONFromFencedBlock(raw)
	if err != nil {
		jsonStr, err = ExtractJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("no JSON block found: %w", err)
		}
	}

	// Try wrapped format first
	var wrapper sourceAnalysisWrapper
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && len(wrapper.SourceAnalysis.HTTPRecords) > 0 {
		return &wrapper.SourceAnalysis, nil
	}

	// Try direct format
	var result agenttypes.SourceAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		// Array-of-records fallback
		var records []agenttypes.AgentHTTPRecord
		if arrErr := json.Unmarshal([]byte(jsonStr), &records); arrErr == nil && len(records) > 0 {
			return &agenttypes.SourceAnalysisResult{HTTPRecords: records}, nil
		}
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	if len(result.HTTPRecords) == 0 {
		return nil, fmt.Errorf("no http_records found in JSON")
	}

	return &result, nil
}
