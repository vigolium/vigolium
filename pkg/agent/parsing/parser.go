package parsing

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
)

// ExtractJSONFromFencedBlock extracts JSON content specifically from ```json fenced code blocks,
// ignoring ```javascript/```js blocks. This provides a reliable anchor for structured data
// when the agent output contains both JSON and JavaScript code blocks.
// Returns the first valid JSON found in a ```json block, or an error if none found.
func ExtractJSONFromFencedBlock(raw string) (string, error) {
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		// Look for ```json fence (but not ```javascript or ```js-something)
		if !strings.HasPrefix(trimmed, "```json") {
			continue
		}
		// Ensure it's actually ```json and not ```jsonl or ```jsonc etc.
		rest := strings.TrimPrefix(trimmed, "```json")
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}

		// Collect content until closing ```
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
			return candidate, nil
		}

		// Try finding a JSON block within the fenced content (handles extra whitespace/comments)
		if block := FindJSONBlock(candidate); block != "" && IsJSON(block) {
			return block, nil
		}
	}
	return "", fmt.Errorf("no valid JSON found in ```json fenced blocks")
}

// ExtractJSON attempts to extract a JSON object or array from raw text using multiple strategies:
// 1. Try parsing the raw string directly
// 2. Strip markdown code fences (at start) and retry
// 3. Extract content from markdown code fences found anywhere in text
// 4. Scan for balanced '{}'/'[]' blocks and try each
func ExtractJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	// Strategy 1: raw string is valid JSON
	if IsJSON(raw) {
		return raw, nil
	}

	// Strategy 2: strip markdown fences at start
	stripped := StripMarkdownFences(raw)
	if stripped != raw && IsJSON(stripped) {
		return stripped, nil
	}

	// Strategy 2b: repair invalid escape sequences (common in LLM output with regex patterns)
	// and retry strategies 1-2
	repaired := RepairInvalidEscapes(raw)
	if repaired != raw && IsJSON(repaired) {
		return repaired, nil
	}
	if stripped2 := StripMarkdownFences(repaired); stripped2 != repaired && IsJSON(stripped2) {
		return stripped2, nil
	}

	// Strategy 3: extract content from ``` fences anywhere in text
	for _, fenced := range ExtractFencedBlocks(raw) {
		fenced = strings.TrimSpace(fenced)
		if fenced != "" && IsJSON(fenced) {
			return fenced, nil
		}
		// Try repairing invalid escapes within the fenced block
		if fenced != "" {
			if repairedFenced := RepairInvalidEscapes(fenced); repairedFenced != fenced && IsJSON(repairedFenced) {
				return repairedFenced, nil
			}
		}
		// Also try finding a JSON block within the fenced content
		if block := FindJSONBlock(fenced); block != "" && IsJSON(block) {
			return block, nil
		}
	}

	// Strategy 4: lazily scan for balanced JSON blocks and try each
	var bestCandidate string
	var bestCandidateErr error
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '{' || ch == '[' {
			block := FindJSONBlockFrom(raw, i)
			if block != "" {
				if IsJSON(block) {
					return block, nil
				}
				// Try repairing invalid escapes in the block
				if repairedBlock := RepairInvalidEscapes(block); repairedBlock != block && IsJSON(repairedBlock) {
					return repairedBlock, nil
				}
				// Track the first (largest) candidate for error reporting
				if bestCandidate == "" {
					bestCandidate = block
					var v interface{}
					bestCandidateErr = json.Unmarshal([]byte(block), &v)
				}
				i += len(block) - 1 // skip past this block, loop increments
			}
		}
	}

	if bestCandidate != "" {
		snippet := bestCandidate
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return "", fmt.Errorf("found JSON-like block but it contains syntax errors: %w (snippet: %s)", bestCandidateErr, snippet)
	}
	return "", fmt.Errorf("no valid JSON found in agent output")
}

// ExtractFencedBlocks extracts content from all markdown code fences (```...```) in the text.
func ExtractFencedBlocks(s string) []string {
	var blocks []string
	for {
		openIdx := strings.Index(s, "```")
		if openIdx < 0 {
			break
		}
		// Skip past the opening fence line
		afterOpen := s[openIdx+3:]
		nlIdx := strings.Index(afterOpen, "\n")
		if nlIdx < 0 {
			break
		}
		content := afterOpen[nlIdx+1:]
		// Find closing fence
		closeIdx := strings.Index(content, "```")
		if closeIdx < 0 {
			break
		}
		blocks = append(blocks, content[:closeIdx])
		s = content[closeIdx+3:]
	}
	return blocks
}

// IsJSON returns true if the string is valid JSON.
func IsJSON(s string) bool {
	var v interface{}
	return json.Unmarshal([]byte(s), &v) == nil
}

// StripMarkdownFences removes ```json ... ``` or ``` ... ``` fences.
func StripMarkdownFences(s string) string {
	s = strings.TrimSpace(s)

	// Check for opening fence
	if !strings.HasPrefix(s, "```") {
		return s
	}

	// Find end of first line (the opening fence line)
	idx := strings.Index(s, "\n")
	if idx < 0 {
		return s
	}
	s = s[idx+1:]

	// Find closing fence
	if lastIdx := strings.LastIndex(s, "```"); lastIdx >= 0 {
		s = s[:lastIdx]
	}

	return strings.TrimSpace(s)
}

// FindJSONBlock scans for the first '{' or '[' and returns the balanced JSON block.
func FindJSONBlock(s string) string {
	return FindJSONBlockFrom(s, 0)
}

// FindJSONBlockFrom scans for the first balanced '{}'/'[]' block starting at position start.
func FindJSONBlockFrom(s string, start int) string {
	for i := start; i < len(s); i++ {
		ch := rune(s[i])
		if ch == '{' || ch == '[' {
			closing := matchingBrace(ch)
			depth := 0
			inString := false
			escaped := false
			for j := i; j < len(s); j++ {
				if escaped {
					escaped = false
					continue
				}
				c := s[j]
				if c == '\\' && inString {
					escaped = true
					continue
				}
				if c == '"' {
					inString = !inString
					continue
				}
				if inString {
					continue
				}
				if rune(c) == ch {
					depth++
				} else if rune(c) == closing {
					depth--
					if depth == 0 {
						return s[i : j+1]
					}
				}
			}
			// Unbalanced block starting at i — skip past this opener
			return ""
		}
	}
	return ""
}

// FindAllJSONBlocks returns all balanced JSON blocks (objects or arrays) found in s, in order.
func FindAllJSONBlocks(s string) []string {
	var blocks []string
	i := 0
	for i < len(s) {
		ch := s[i]
		if ch == '{' || ch == '[' {
			block := FindJSONBlockFrom(s, i)
			if block != "" {
				blocks = append(blocks, block)
				i += len(block)
				continue
			}
		}
		i++
	}
	return blocks
}

func matchingBrace(open rune) rune {
	if open == '{' {
		return '}'
	}
	return ']'
}

// ExtractJSONLFromFencedBlock extracts content from the first ```jsonl fenced code block.
// Returns the raw content of the block (not parsed), or an error if none found.
func ExtractJSONLFromFencedBlock(raw string) (string, error) {
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		if !strings.HasPrefix(trimmed, "```jsonl") {
			continue
		}
		// Ensure it's actually ```jsonl and not ```jsonlines or similar
		rest := strings.TrimPrefix(trimmed, "```jsonl")
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}

		// Collect content until closing ```
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
		return candidate, nil
	}
	return "", fmt.Errorf("no ```jsonl fenced block found")
}

// ParseHTTPRecordJSONL parses JSONL-formatted HTTP records (one JSON object per line).
// Returns successfully parsed records and the count of lines that failed to parse.
// Lines that fail strict JSON parsing are repaired via balanced-brace extraction
// and truncated-JSON closure before being retried.
func ParseHTTPRecordJSONL(raw string) ([]agenttypes.AgentHTTPRecord, int) {
	var records []agenttypes.AgentHTTPRecord
	badCount := 0

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}

		var rec agenttypes.AgentHTTPRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Repair pass: try extracting a balanced JSON block (strips trailing garbage)
			repaired := FindJSONBlockFrom(line, 0)
			if repaired == "" {
				// Fall back to closing unclosed braces/brackets
				repaired = RepairTruncatedJSON(line)
			}
			if repaired != "" && repaired != line {
				if err2 := json.Unmarshal([]byte(repaired), &rec); err2 != nil {
					badCount++
					continue
				}
			} else {
				badCount++
				continue
			}
		}
		if !isValidHTTPRecord(rec) {
			// Try normalizing the record before dropping it
			fixed, ok := normalizeRecord(rec)
			if !ok {
				badCount++
				continue
			}
			rec = fixed
		}
		records = append(records, rec)
	}
	return records, badCount
}

// ExtractRecordsFromGarbled scans raw text for JSON objects that look like HTTP records
// (containing "method":) and attempts to extract them individually. This recovers records
// from corrupted JSON arrays where one garbled field would otherwise lose all records.
func ExtractRecordsFromGarbled(raw string) ([]agenttypes.AgentHTTPRecord, int) {
	var records []agenttypes.AgentHTTPRecord
	failCount := 0

	// Scan for {"method": boundaries
	needle := `"method"`
	i := 0
	for i < len(raw) {
		idx := strings.Index(raw[i:], needle)
		if idx < 0 {
			break
		}
		pos := i + idx

		// Walk backwards to find the opening { for this object
		start := pos - 1
		for start >= 0 && raw[start] != '{' {
			start--
		}
		if start < 0 {
			i = pos + len(needle)
			continue
		}

		// Use FindJSONBlockFrom to extract the balanced {...} block
		block := FindJSONBlockFrom(raw, start)
		if block == "" {
			i = pos + len(needle)
			continue
		}

		var rec agenttypes.AgentHTTPRecord
		if err := json.Unmarshal([]byte(block), &rec); err == nil && isValidHTTPRecord(rec) {
			records = append(records, rec)
		} else {
			failCount++
		}

		i = start + len(block)
	}
	return records, failCount
}

// validHTTPMethods is the set of recognized HTTP methods for record validation.
var validHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
}

// isValidHTTPRecord checks that a parsed AgentHTTPRecord has a valid HTTP method
// and a well-formed URL with a scheme.
func isValidHTTPRecord(rec agenttypes.AgentHTTPRecord) bool {
	if !validHTTPMethods[strings.ToUpper(rec.Method)] {
		return false
	}
	if rec.URL == "" {
		return false
	}
	u, err := url.Parse(rec.URL)
	if err != nil {
		return false
	}
	return u.Scheme != ""
}

// NormalizeAgentRecords performs a normalization pass on agent HTTP records,
// fixing common LLM output issues:
// - Truncated/malformed JSON bodies (attempts to close open braces/brackets)
// - Garbled URL paths (removes non-ASCII, fixes double slashes)
// - Malformed headers (removes entries with garbled names)
// - Notes/description leaking into body field
// Records that cannot be salvaged are dropped and counted.
func NormalizeAgentRecords(records []agenttypes.AgentHTTPRecord) (normalized []agenttypes.AgentHTTPRecord, dropped int) {
	for _, rec := range records {
		fixed, ok := normalizeRecord(rec)
		if !ok {
			dropped++
			continue
		}
		normalized = append(normalized, fixed)
	}
	return normalized, dropped
}

func normalizeRecord(rec agenttypes.AgentHTTPRecord) (agenttypes.AgentHTTPRecord, bool) {
	// Normalize method — infer from context if not a valid HTTP method
	rec.Method = strings.ToUpper(strings.TrimSpace(rec.Method))
	if !validHTTPMethods[rec.Method] {
		if rec.Body != "" {
			rec.Method = "POST"
		} else {
			rec.Method = "GET"
		}
	}

	// Normalize URL — strip non-printable chars, fix common garbling
	rec.URL = cleanAgentURL(rec.URL)
	if rec.URL == "" {
		return rec, false
	}
	u, err := url.Parse(rec.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rec, false
	}

	// Normalize headers — remove garbled entries
	if len(rec.Headers) > 0 {
		clean := make(map[string]string, len(rec.Headers))
		for k, v := range rec.Headers {
			if isValidHeaderName(k) {
				clean[k] = v
			}
		}
		rec.Headers = clean
	}

	// Normalize body — fix truncated JSON
	if rec.Body != "" {
		rec.Body = normalizeBody(rec.Body)
	}

	return rec, true
}

// cleanAgentURL cleans up garbled URL strings from LLM output.
func cleanAgentURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)

	// Remove non-printable characters
	var cleaned strings.Builder
	for _, r := range rawURL {
		if r >= 32 && r < 127 {
			cleaned.WriteRune(r)
		}
	}
	rawURL = cleaned.String()

	// Extract embedded URL: if the path contains an http:// or https:// URL,
	// use that instead (e.g., "/order-history/http://localhost:3000/rest" → "http://localhost:3000/rest")
	for _, scheme := range []string{"https://", "http://"} {
		if idx := strings.Index(rawURL, scheme); idx > 0 {
			rawURL = rawURL[idx:]
			break
		}
	}

	// Fix double slashes in path (but not in scheme)
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		scheme := rawURL[:idx+3]
		rest := rawURL[idx+3:]
		// Find end of host
		hostEnd := strings.Index(rest, "/")
		if hostEnd >= 0 {
			host := rest[:hostEnd]
			path := rest[hostEnd:]
			// Collapse consecutive slashes in path
			for strings.Contains(path, "//") {
				path = strings.ReplaceAll(path, "//", "/")
			}
			rawURL = scheme + host + path
		}
	}

	return rawURL
}

// isValidHeaderName checks that a header name contains only valid HTTP token characters.
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		// HTTP token characters: printable ASCII except delimiters
		if c < 33 || c > 126 {
			return false
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}

// normalizeBody attempts to fix truncated JSON bodies by closing open braces/brackets.
func normalizeBody(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return body
	}

	// Only attempt JSON repair for JSON-looking bodies
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return body
	}

	// Already valid JSON — no repair needed
	if IsJSON(trimmed) {
		return body
	}

	// Count open/close braces and brackets
	repaired := RepairTruncatedJSON(trimmed)
	if IsJSON(repaired) {
		return repaired
	}

	return body
}

// RepairInvalidEscapes fixes invalid JSON escape sequences produced by LLMs.
// JSON only allows \", \\, \/, \b, \f, \n, \r, \t, and \uXXXX as escapes.
// LLMs often emit regex patterns like \w, \d, \. inside JSON strings without
// double-escaping. This function scans JSON strings and doubles lone backslashes
// that precede non-valid-escape characters.
func RepairInvalidEscapes(s string) string {
	var out strings.Builder
	out.Grow(len(s) + 64) // slight over-allocation for added backslashes
	inString := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inString {
			out.WriteByte(c)
			if c == '"' {
				inString = true
			}
			continue
		}

		// Inside a JSON string
		if c == '"' {
			out.WriteByte(c)
			inString = false
			continue
		}
		if c != '\\' {
			out.WriteByte(c)
			continue
		}

		// c == '\\' — look at the next character
		if i+1 >= len(s) {
			out.WriteByte(c)
			continue
		}
		next := s[i+1]
		switch next {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
			// Valid JSON escape — emit both characters and skip past the escaped char
			out.WriteByte(c)
			out.WriteByte(next)
			i++ // consume the escape character
		default:
			// Invalid escape like \w, \d, \. — double the backslash
			out.WriteByte('\\')
			out.WriteByte(c)
		}
	}
	return out.String()
}

// RepairTruncatedJSON attempts to close unclosed braces/brackets and quotes in truncated JSON.
func RepairTruncatedJSON(s string) string {
	var stack []byte
	inString := false
	escaped := false

	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		c := s[i]
		if c == '\\' && inString {
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{':
			stack = append(stack, '}')
		case '[':
			stack = append(stack, ']')
		case '}', ']':
			if len(stack) > 0 && stack[len(stack)-1] == c {
				stack = stack[:len(stack)-1]
			}
		}
	}

	if len(stack) == 0 && !inString {
		return s
	}

	var sb strings.Builder
	sb.WriteString(s)

	// Close open string first
	if inString {
		sb.WriteByte('"')
	}

	// Close open braces/brackets in reverse order
	for i := len(stack) - 1; i >= 0; i-- {
		sb.WriteByte(stack[i])
	}
	return sb.String()
}

// ParseFindings extracts findings from raw agent output.
func ParseFindings(raw string) ([]agenttypes.AgentFinding, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try parsing as AgentFindingsOutput first
	var output agenttypes.AgentFindingsOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err == nil && len(output.Findings) > 0 {
		return output.Findings, nil
	}

	// Try parsing as a bare array
	var findings []agenttypes.AgentFinding
	if err := json.Unmarshal([]byte(jsonStr), &findings); err == nil {
		return findings, nil
	}

	return nil, fmt.Errorf("failed to parse findings from JSON: invalid structure")
}

// ParseHTTPRecords extracts HTTP records from raw agent output.
func ParseHTTPRecords(raw string) ([]agenttypes.AgentHTTPRecord, error) {
	jsonStr, err := ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try parsing as AgentHTTPRecordsOutput first
	var output agenttypes.AgentHTTPRecordsOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err == nil && len(output.HTTPRecords) > 0 {
		return output.HTTPRecords, nil
	}

	// Try parsing as a bare array
	var records []agenttypes.AgentHTTPRecord
	if err := json.Unmarshal([]byte(jsonStr), &records); err == nil {
		return records, nil
	}

	return nil, fmt.Errorf("failed to parse HTTP records from JSON: invalid structure")
}

// ToDBFinding converts an AgentFinding to a database.Finding.
func ToDBFinding(af agenttypes.AgentFinding, moduleID string, scanUUID string, projectUUID string) *database.Finding {
	matchedAt := []string{}
	if af.File != "" {
		loc := af.File
		if af.Line > 0 {
			loc = fmt.Sprintf("%s:%d", af.File, af.Line)
		}
		matchedAt = append(matchedAt, loc)
	}

	confidence := af.Confidence
	if confidence == "" {
		confidence = "tentative"
	}

	severity := af.Severity
	if severity == "" {
		severity = "info"
	}

	tags := af.Tags
	if af.CWE != "" {
		tags = append(tags, af.CWE)
	}

	// Generate finding hash for deduplication
	hashInput := fmt.Sprintf("%s|%s|%s|%s", moduleID, af.Title, af.File, af.Snippet)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashInput)))

	return &database.Finding{
		ModuleID:         moduleID,
		ModuleName:       af.Title,
		Description:      af.Description,
		Severity:         severity,
		Confidence:       confidence,
		Tags:             tags,
		MatchedAt:        matchedAt,
		ExtractedResults: extractSnippets(af),
		FindingHash:      hash,
		ScanUUID:         scanUUID,
		ProjectUUID:      projectUUID,
		ModuleType:       database.ModuleTypeAgent,
		FindingSource:    database.FindingSourceAgent,
		ModuleShort:      af.Title,
		Status:           database.StatusDraft,
		FoundAt:          time.Now(),
	}
}

// extractSnippets collects snippet data from an AgentFinding.
func extractSnippets(af agenttypes.AgentFinding) []string {
	if af.Snippet == "" {
		return nil
	}
	return []string{af.Snippet}
}
