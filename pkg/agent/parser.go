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
// 2. Strip markdown code fences and retry
// 3. Scan for the first '{' or '[' and extract from there
func extractJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	// Strategy 1: raw string is valid JSON
	if isJSON(raw) {
		return raw, nil
	}

	// Strategy 2: strip markdown fences
	stripped := stripMarkdownFences(raw)
	if stripped != raw && isJSON(stripped) {
		return stripped, nil
	}

	// Strategy 3: find first { or [ and extract balanced JSON
	if extracted := findJSONBlock(raw); extracted != "" && isJSON(extracted) {
		return extracted, nil
	}

	return "", fmt.Errorf("no valid JSON found in agent output")
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
	for i, ch := range s {
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
		}
	}
	return ""
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
