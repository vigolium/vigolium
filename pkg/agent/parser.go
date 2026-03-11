package agent

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// extractJSON attempts to extract a JSON object or array from raw text using multiple strategies:
// 1. Try parsing the raw string directly
// 2. Strip markdown code fences (at start) and retry
// 3. Extract content from markdown code fences found anywhere in text
// 4. Scan for balanced '{}'/'[]' blocks and try each
func extractJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	// Strategy 1: raw string is valid JSON
	if isJSON(raw) {
		return raw, nil
	}

	// Strategy 2: strip markdown fences at start
	stripped := stripMarkdownFences(raw)
	if stripped != raw && isJSON(stripped) {
		return stripped, nil
	}

	// Strategy 3: extract content from ``` fences anywhere in text
	for _, fenced := range extractFencedBlocks(raw) {
		fenced = strings.TrimSpace(fenced)
		if fenced != "" && isJSON(fenced) {
			return fenced, nil
		}
		// Also try finding a JSON block within the fenced content
		if block := findJSONBlock(fenced); block != "" && isJSON(block) {
			return block, nil
		}
	}

	// Strategy 4: lazily scan for balanced JSON blocks and try each
	var bestCandidate string
	var bestCandidateErr error
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '{' || ch == '[' {
			block := findJSONBlockFrom(raw, i)
			if block != "" {
				if isJSON(block) {
					return block, nil
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

// extractFencedBlocks extracts content from all markdown code fences (```...```) in the text.
func extractFencedBlocks(s string) []string {
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

// isJSON returns true if the string is valid JSON.
func isJSON(s string) bool {
	var v interface{}
	return json.Unmarshal([]byte(s), &v) == nil
}

// stripMarkdownFences removes ```json ... ``` or ``` ... ``` fences.
func stripMarkdownFences(s string) string {
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

// findJSONBlock scans for the first '{' or '[' and returns the balanced JSON block.
func findJSONBlock(s string) string {
	return findJSONBlockFrom(s, 0)
}

// findJSONBlockFrom scans for the first balanced '{}'/'[]' block starting at position start.
func findJSONBlockFrom(s string, start int) string {
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

// findAllJSONBlocks returns all balanced JSON blocks (objects or arrays) found in s, in order.
func findAllJSONBlocks(s string) []string {
	var blocks []string
	i := 0
	for i < len(s) {
		ch := s[i]
		if ch == '{' || ch == '[' {
			block := findJSONBlockFrom(s, i)
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

// ParseFindings extracts findings from raw agent output.
func ParseFindings(raw string) ([]AgentFinding, error) {
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try parsing as AgentFindingsOutput first
	var output AgentFindingsOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err == nil && len(output.Findings) > 0 {
		return output.Findings, nil
	}

	// Try parsing as a bare array
	var findings []AgentFinding
	if err := json.Unmarshal([]byte(jsonStr), &findings); err == nil {
		return findings, nil
	}

	return nil, fmt.Errorf("failed to parse findings from JSON: invalid structure")
}

// ParseHTTPRecords extracts HTTP records from raw agent output.
func ParseHTTPRecords(raw string) ([]AgentHTTPRecord, error) {
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from agent output: %w", err)
	}

	// Try parsing as AgentHTTPRecordsOutput first
	var output AgentHTTPRecordsOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err == nil && len(output.HTTPRecords) > 0 {
		return output.HTTPRecords, nil
	}

	// Try parsing as a bare array
	var records []AgentHTTPRecord
	if err := json.Unmarshal([]byte(jsonStr), &records); err == nil {
		return records, nil
	}

	return nil, fmt.Errorf("failed to parse HTTP records from JSON: invalid structure")
}

// ToDBFinding converts an AgentFinding to a database.Finding.
func ToDBFinding(af AgentFinding, moduleID string, scanUUID string, projectUUID string) *database.Finding {
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
		FoundAt:          time.Now(),
	}
}

// extractSnippets collects snippet data from an AgentFinding.
func extractSnippets(af AgentFinding) []string {
	if af.Snippet == "" {
		return nil
	}
	return []string{af.Snippet}
}
