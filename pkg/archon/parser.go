package archon

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vigolium/vigolium/pkg/database"
)

// AuditImport holds the parsed result of an archon output folder.
type AuditImport struct {
	RawFindings []*ArchonFinding
	State       *AuditState
}

// AuditState represents the top-level audit-state.json structure.
type AuditState struct {
	Audits []AuditEntry `json:"audits"`
}

// AuditEntry is a single audit run inside audit-state.json.
type AuditEntry struct {
	AuditID     string                `json:"audit_id"`
	Commit      string                `json:"commit"`
	Branch      string                `json:"branch"`
	StartedAt   time.Time             `json:"started_at"`
	CompletedAt time.Time             `json:"completed_at"`
	Status      string                `json:"status"`
	Phases      map[string]PhaseEntry `json:"phases"`
}

// PhaseEntry describes one phase in the audit.
// Summary is flexible: LLM-generated audit-state.json may produce a plain string
// or a structured object. We accept both and normalise to map[string]interface{}.
type PhaseEntry struct {
	Status      string                 `json:"status"`
	CompletedAt time.Time              `json:"completed_at"`
	Summary     map[string]interface{} `json:"-"` // populated by custom unmarshal
	SummaryRaw  json.RawMessage        `json:"summary,omitempty"`
}

// UnmarshalJSON implements lenient parsing for PhaseEntry.
// It accepts summary as a string, an object, or absent.
func (p *PhaseEntry) UnmarshalJSON(data []byte) error {
	// Use an alias to avoid infinite recursion.
	type Alias struct {
		Status      string          `json:"status"`
		CompletedAt time.Time       `json:"completed_at"`
		Summary     json.RawMessage `json:"summary,omitempty"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.Status = a.Status
	p.CompletedAt = a.CompletedAt
	p.SummaryRaw = a.Summary

	if len(a.Summary) == 0 {
		return nil
	}

	// Try object first.
	var m map[string]interface{}
	if err := json.Unmarshal(a.Summary, &m); err == nil {
		p.Summary = m
		return nil
	}

	// Fall back to string.
	var s string
	if err := json.Unmarshal(a.Summary, &s); err == nil {
		p.Summary = map[string]interface{}{"text": s}
		return nil
	}

	// Accept anything else silently — don't fail the whole parse.
	return nil
}

// SummaryText returns the summary as a plain string if it was provided as one,
// or empty string otherwise.
func (p PhaseEntry) SummaryText() string {
	if t, ok := p.Summary["text"]; ok {
		if s, ok := t.(string); ok {
			return s
		}
	}
	return ""
}

// ArchonFinding is the intermediate representation of a parsed finding file.
type ArchonFinding struct {
	// Common fields
	FindingID string // e.g. "P7-001", "P8-001"
	Phase     string // "7", "8", "10"
	Sequence  string // "001", "002"
	Slug      string // e.g. "open-redirect-authproxy"
	Title     string
	Severity  string
	Confidence string
	CWE       string
	Verdict   string // VALID, INVALID, etc.
	PoCStatus string // theoretical, pending, confirmed

	// Phase 8+ specific
	SeverityOriginal    string
	SeverityFinal       string
	AdversarialVerdict  string
	AdversarialRationale string

	// Locations extracted from the body
	Locations []string

	// Full markdown body (everything after frontmatter/header)
	Body string

	// Source filename
	Filename string
}

// ParseAuditFolder parses an archon output folder and returns the import data.
func ParseAuditFolder(folderPath string) (*AuditImport, error) {
	statePath := filepath.Join(folderPath, "audit-state.json")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("audit-state.json not found in %s", folderPath)
	}

	state, err := parseAuditState(statePath)
	if err != nil {
		return nil, fmt.Errorf("parse audit-state.json: %w", err)
	}
	if len(state.Audits) == 0 {
		return nil, fmt.Errorf("no audit entries in audit-state.json")
	}

	findingsDir := filepath.Join(folderPath, "findings-draft")
	findings, err := parseFindingsDir(findingsDir)
	if err != nil {
		return nil, fmt.Errorf("parse findings-draft: %w", err)
	}

	return &AuditImport{
		State:       state,
		RawFindings: findings,
	}, nil
}

// BuildAgentRun creates a database.AgentRun from the parsed audit state.
func BuildAgentRun(state *AuditState, folderPath, projectUUID string) *database.AgentRun {
	audit := state.Audits[0]

	// Collect phase keys sorted
	var phases []string
	for k := range audit.Phases {
		phases = append(phases, k)
	}
	sort.Strings(phases)

	// Calculate finding count from final phase summary
	findingCount := 0
	if p11, ok := audit.Phases["11"]; ok {
		if total, ok := p11.Summary["total_findings"]; ok {
			if v, ok := total.(float64); ok {
				findingCount = int(v)
			}
		}
	}

	// Duration
	durationMs := audit.CompletedAt.Sub(audit.StartedAt).Milliseconds()

	// Store full audit-state as result_json
	stateBytes, _ := json.Marshal(state)

	// Read attack-pattern-registry if it exists
	attackPlan := ""
	if data, err := os.ReadFile(filepath.Join(folderPath, "attack-pattern-registry.json")); err == nil {
		attackPlan = string(data)
	}

	status := audit.Status
	if status == "complete" {
		status = "completed"
	}

	return &database.AgentRun{
		UUID:        uuid.New().String(),
		ProjectUUID: projectUUID,
		Mode:        "archon",
		AgentName:   "archon-audit",
		InputRaw:    fmt.Sprintf("commit:%s branch:%s", audit.Commit, audit.Branch),
		InputType:   "archon",
		Status:      status,
		PhasesRun:   phases,
		FindingCount: findingCount,
		SourcePath:  folderPath,
		StartedAt:   audit.StartedAt,
		CompletedAt: audit.CompletedAt,
		DurationMs:  durationMs,
		ResultJSON:  string(stateBytes),
		AttackPlan:  attackPlan,
	}
}

// BuildFindings converts parsed ArchonFindings to database.Finding structs.
func BuildFindings(findings []*ArchonFinding, auditID, agentRunUUID, projectUUID string) []*database.Finding {
	var result []*database.Finding
	for _, af := range findings {
		result = append(result, toDBFinding(af, auditID, agentRunUUID, projectUUID))
	}
	return result
}

func parseAuditState(path string) (*AuditState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state AuditState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func parseFindingsDir(dir string) ([]*ArchonFinding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil // no findings-draft directory is valid (empty audit)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	// First pass: parse base findings (skip .cold-verify.md files)
	findingsByID := make(map[string]*ArchonFinding)
	var findings []*ArchonFinding

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if strings.Contains(e.Name(), ".cold-verify.") {
			continue // handle in second pass
		}

		path := filepath.Join(dir, e.Name())
		af, err := parseFindingFile(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		if af != nil {
			findingsByID[af.FindingID] = af
			findings = append(findings, af)
		}
	}

	// Second pass: apply cold-verify overlays
	for _, e := range entries {
		if !strings.Contains(e.Name(), ".cold-verify.md") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		overlay, err := parseFindingFile(path)
		if err != nil {
			continue // skip unparseable cold-verify files
		}
		if overlay == nil {
			continue
		}

		// Find the base finding to overlay
		if base, ok := findingsByID[overlay.FindingID]; ok {
			applyColdVerify(base, overlay)
		}
	}

	return findings, nil
}

// findingFileRegex matches archon finding filenames like p7-001-slug.md or p8-002-slug.cold-verify.md
var findingFileRegex = regexp.MustCompile(`^p(\d+)-(\d+)-(.+?)(?:\.cold-verify)?\.md$`)

func parseFindingFile(path string) (*ArchonFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	filename := filepath.Base(path)
	m := findingFileRegex.FindStringSubmatch(filename)
	if m == nil {
		return nil, nil // not a finding file
	}

	phase := m[1]
	seq := m[2]
	slug := m[3]
	findingID := fmt.Sprintf("P%s-%s", phase, seq)

	content := string(data)

	af := &ArchonFinding{
		FindingID: findingID,
		Phase:     phase,
		Sequence:  seq,
		Slug:      slug,
		Filename:  filename,
	}

	if phase == "7" {
		parsePhase7Finding(af, content)
	} else {
		parseFrontmatterFinding(af, content)
	}

	return af, nil
}

// parsePhase7Finding parses the Phase 7 table-header format.
func parsePhase7Finding(af *ArchonFinding, content string) {
	// Extract fields from markdown table rows: | **Field** | Value |
	tableFieldRe := regexp.MustCompile(`\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|`)
	for _, match := range tableFieldRe.FindAllStringSubmatch(content, -1) {
		key := strings.TrimSpace(match[1])
		val := strings.TrimSpace(match[2])
		switch key {
		case "Title":
			af.Title = val
		case "Severity":
			af.Severity = val
		case "Confidence":
			af.Confidence = val
		case "CWE":
			af.CWE = extractCWE(val)
		}
	}

	// Extract PoC-Status from inline text
	if idx := strings.Index(content, "PoC-Status:"); idx != -1 {
		line := content[idx:]
		if nl := strings.IndexByte(line, '\n'); nl != -1 {
			line = line[:nl]
		}
		af.PoCStatus = strings.TrimSpace(strings.TrimPrefix(line, "PoC-Status:"))
	}

	// Extract locations from ## Code Location or ## Code Locations sections
	af.Locations = extractLocations(content)

	// Full body as description
	af.Body = content
}

// parseFrontmatterFinding parses the Phase 8/9/10 YAML-like frontmatter format.
func parseFrontmatterFinding(af *ArchonFinding, content string) {
	lines := strings.Split(content, "\n")
	bodyStart := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// Check if next non-empty line starts a markdown section
			for j := i + 1; j < len(lines); j++ {
				next := strings.TrimSpace(lines[j])
				if next == "" {
					continue
				}
				if strings.HasPrefix(next, "## ") || strings.HasPrefix(next, "# ") {
					bodyStart = j
				}
				break
			}
			if bodyStart > 0 {
				break
			}
			continue
		}

		// Parse Key: Value lines
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := strings.TrimSpace(trimmed[colonIdx+1:])

		switch key {
		case "Phase":
			af.Phase = val
		case "Sequence":
			af.Sequence = val
		case "Slug":
			af.Slug = val
		case "Verdict":
			af.Verdict = val
		case "Severity-Original":
			af.SeverityOriginal = val
		case "Severity-Final":
			af.SeverityFinal = val
		case "PoC-Status":
			af.PoCStatus = val
		case "Adversarial-Verdict":
			af.AdversarialVerdict = val
		case "Adversarial-Rationale":
			af.AdversarialRationale = val
		}
	}

	// Extract title from ## Summary section's first sentence, or use slug
	if af.Title == "" {
		af.Title = extractTitleFromBody(content, af.Slug)
	}

	// Extract severity: prefer Severity-Final, fall back to Severity-Original
	if af.SeverityFinal != "" {
		af.Severity = af.SeverityFinal
	} else if af.SeverityOriginal != "" {
		af.Severity = af.SeverityOriginal
	}

	// Extract confidence from verdict/adversarial verdict
	if af.Confidence == "" {
		v := af.AdversarialVerdict
		if v == "" {
			v = af.Verdict
		}
		af.Confidence = mapConfidence(v)
	}

	// Extract locations
	af.Locations = extractLocations(content)

	// Full body
	if bodyStart > 0 {
		af.Body = strings.Join(lines[bodyStart:], "\n")
	} else {
		af.Body = content
	}
}

func applyColdVerify(base, overlay *ArchonFinding) {
	if overlay.AdversarialVerdict != "" {
		base.AdversarialVerdict = overlay.AdversarialVerdict
	}
	if overlay.SeverityFinal != "" {
		base.SeverityFinal = overlay.SeverityFinal
		base.Severity = overlay.SeverityFinal
	}
	if overlay.PoCStatus != "" {
		base.PoCStatus = overlay.PoCStatus
	}
	if overlay.AdversarialRationale != "" {
		base.AdversarialRationale = overlay.AdversarialRationale
	}
	// Merge body: append cold-verify notes
	if overlay.Body != "" {
		base.Body = base.Body + "\n\n---\n## Cold Verification\n\n" + overlay.Body
	}
}

func toDBFinding(af *ArchonFinding, auditID, agentRunUUID, projectUUID string) *database.Finding {
	moduleID := fmt.Sprintf("archon:%s", strings.ToLower(af.FindingID))

	severity := strings.ToUpper(af.Severity)
	if severity == "" {
		severity = "INFO"
	}
	// Normalize to match vigolium's expected values
	switch severity {
	case "HIGH":
		severity = "high"
	case "MEDIUM":
		severity = "medium"
	case "LOW":
		severity = "low"
	case "INFO", "INFORMATIONAL":
		severity = "info"
	case "CRITICAL":
		severity = "critical"
	default:
		severity = strings.ToLower(severity)
	}

	confidence := mapConfidence(af.Confidence)

	// Build tags
	tags := []string{"archon", fmt.Sprintf("phase-%s", af.Phase)}
	if af.Verdict != "" {
		tags = append(tags, strings.ToLower(af.Verdict))
	}
	if af.PoCStatus != "" {
		tags = append(tags, fmt.Sprintf("poc-%s", strings.ToLower(af.PoCStatus)))
	}
	if af.CWE != "" {
		tags = append(tags, af.CWE)
	}

	// Source file: first location
	sourceFile := ""
	if len(af.Locations) > 0 {
		sourceFile = af.Locations[0]
	}

	// Generate hash for dedup
	hashInput := fmt.Sprintf("%s|%s|%s", auditID, moduleID, af.FindingID)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashInput)))

	cweID := af.CWE

	return &database.Finding{
		ProjectUUID:     projectUUID,
		HTTPRecordUUIDs: []string{},
		AgentRunUUID:    agentRunUUID,
		ModuleID:        moduleID,
		ModuleName:      af.Title,
		ModuleType:      database.ModuleTypeWhitebox,
		FindingSource:   database.FindingSourceArchon,
		ModuleShort:     af.Slug,
		Description:     af.Body,
		Severity:        severity,
		Confidence:      confidence,
		Tags:            tags,
		CWEID:           cweID,
		SourceFile:      sourceFile,
		MatchedAt:       af.Locations,
		FindingHash:     hash,
		FoundAt:         time.Now(),
	}
}

// --- helpers ---

var cweRegex = regexp.MustCompile(`(CWE-\d+)`)

func extractCWE(val string) string {
	m := cweRegex.FindString(val)
	return m
}

var (
	fileLocRegex    = regexp.MustCompile(`\*\*File\*\*:\s*` + "`" + `([^` + "`" + `]+)` + "`")
	codeLocRegex    = regexp.MustCompile("`" + `([^` + "`" + `]+\.\w+:\d+(?:-\d+)?)` + "`" + `\s*--`)
)

func extractLocations(content string) []string {
	var locs []string
	seen := make(map[string]bool)

	for _, m := range fileLocRegex.FindAllStringSubmatch(content, -1) {
		loc := m[1]
		if !seen[loc] {
			seen[loc] = true
			locs = append(locs, loc)
		}
	}

	for _, m := range codeLocRegex.FindAllStringSubmatch(content, -1) {
		loc := m[1]
		if !seen[loc] {
			seen[loc] = true
			locs = append(locs, loc)
		}
	}

	return locs
}

func extractTitleFromBody(content, slug string) string {
	// Try to find title in ## Summary section first line
	summaryIdx := strings.Index(content, "## Summary")
	if summaryIdx != -1 {
		rest := content[summaryIdx+len("## Summary"):]
		lines := strings.Split(rest, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				// Use first non-empty line as title, truncated
				if len(l) > 200 {
					l = l[:200]
				}
				return l
			}
		}
	}
	// Fall back to humanized slug
	return strings.ReplaceAll(slug, "-", " ")
}

func mapConfidence(val string) string {
	switch strings.ToUpper(strings.TrimSpace(val)) {
	case "CONFIRMED", "HIGH", "VALID":
		return "firm"
	default:
		return "tentative"
	}
}
