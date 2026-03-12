package sourcetools

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// ToFinding converts a RawFinding into a database.Finding for storage.
func ToFinding(raw RawFinding, sr *database.SourceRepo) database.Finding {
	matchedAt := formatMatchedAt(raw, sr.RootPath)

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s", raw.ToolName, raw.RuleID, raw.FilePath, matchedAt)))

	description := raw.RuleName
	if description == "" {
		description = raw.Message
	}

	finding := database.Finding{
		ProjectUUID:     sr.ProjectUUID,
		HTTPRecordUUIDs: []string{}, // no HTTP record for source findings
		ModuleID:        raw.RuleID,
		ModuleName:      raw.RuleID,
		Description:     description,
		Severity:        raw.Severity,
		Confidence:      "firm",
		Tags:            []string{"sast", raw.ToolName},
		MatchedAt:       []string{matchedAt},
		FindingHash:     fmt.Sprintf("%x", hash),
		ModuleType:      database.ModuleTypeSAST,
		FindingSource:   database.FindingSourceSourceTools,
		ModuleShort:     raw.Message,
		FoundAt:         time.Now(),
		CreatedAt:       time.Now(),
	}

	if evidence := extractSourceContext(sr.RootPath, raw.FilePath, raw.StartLine); evidence != "" {
		finding.AdditionalEvidence = []string{evidence}
	}

	return finding
}

// GroupFindings groups raw findings by (toolName, ruleID, description)
// and returns merged database.Finding entries. Findings sharing the same key
// are consolidated into one Finding with multiple MatchedAt and AdditionalEvidence
// entries. The highest severity across the group wins.
func GroupFindings(raws []RawFinding, sr *database.SourceRepo) []database.Finding {
	type group struct {
		finding database.Finding
	}

	groups := make(map[string]*group)
	var order []string

	for _, raw := range raws {
		description := raw.RuleName
		if description == "" {
			description = raw.Message
		}
		key := fmt.Sprintf("%s:%s:%s", raw.ToolName, raw.RuleID, description)

		matchedAt := formatMatchedAt(raw, sr.RootPath)

		if g, ok := groups[key]; ok {
			g.finding.MatchedAt = append(g.finding.MatchedAt, matchedAt)
			if evidence := extractSourceContext(sr.RootPath, raw.FilePath, raw.StartLine); evidence != "" {
				g.finding.AdditionalEvidence = append(g.finding.AdditionalEvidence, evidence)
			}
			g.finding.Severity = higherSeverity(g.finding.Severity, raw.Severity)
		} else {
			hash := sha256.Sum256([]byte(key))
			f := database.Finding{
				ProjectUUID:     sr.ProjectUUID,
				HTTPRecordUUIDs: []string{},
				ModuleID:        raw.RuleID,
				ModuleName:      raw.RuleID,
				Description:     description,
				Severity:        raw.Severity,
				Confidence:      "firm",
				Tags:            []string{"sast", raw.ToolName},
				MatchedAt:       []string{matchedAt},
				FindingHash:     fmt.Sprintf("%x", hash),
				ModuleType:      database.ModuleTypeSAST,
				FindingSource:   database.FindingSourceSourceTools,
				ModuleShort:     raw.Message,
				FoundAt:         time.Now(),
				CreatedAt:       time.Now(),
			}
			if evidence := extractSourceContext(sr.RootPath, raw.FilePath, raw.StartLine); evidence != "" {
				f.AdditionalEvidence = []string{evidence}
			}
			groups[key] = &group{finding: f}
			order = append(order, key)
		}
	}

	result := make([]database.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, groups[key].finding)
	}
	return result
}

// higherSeverity returns the more severe of two severity strings.
func higherSeverity(a, b string) string {
	if b == "" {
		return a
	}
	order := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

// formatMatchedAt builds a location string from file and line info.
// When rootPath is provided, the file path is made absolute.
func formatMatchedAt(raw RawFinding, rootPath string) string {
	filePath := raw.FilePath
	if rootPath != "" {
		filePath = filepath.Join(rootPath, raw.FilePath)
	}
	if raw.StartLine > 0 {
		if raw.EndLine > 0 && raw.EndLine != raw.StartLine {
			return fmt.Sprintf("%s:%d-%d", filePath, raw.StartLine, raw.EndLine)
		}
		return fmt.Sprintf("%s:%d", filePath, raw.StartLine)
	}
	return filePath
}

// extractSourceContext reads ~10 lines above and below startLine from the file
// at rootPath/filePath and returns a formatted code block string.
func extractSourceContext(rootPath, filePath string, startLine int) string {
	if startLine <= 0 || rootPath == "" || filePath == "" {
		return ""
	}

	absPath := filepath.Join(rootPath, filePath)
	f, err := os.Open(absPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	fromLine := startLine - 10
	if fromLine < 1 {
		fromLine = 1
	}
	toLine := startLine + 10

	var b strings.Builder
	fmt.Fprintf(&b, "// %s:%d\n", filePath, startLine)

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum < fromLine {
			continue
		}
		if lineNum > toLine {
			break
		}
		marker := "  "
		if lineNum == startLine {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%4d | %s\n", marker, lineNum, scanner.Text())
	}

	if b.Len() == 0 {
		return ""
	}
	return b.String()
}
