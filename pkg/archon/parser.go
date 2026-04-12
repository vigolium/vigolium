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

// flexTime wraps time.Time with lenient JSON unmarshaling that accepts both
// RFC3339 ("2006-01-02T15:04:05Z07:00") and date-only ("2006-01-02") formats.
// LLM-generated audit-state.json files frequently emit date-only strings.
type flexTime struct {
	time.Time
}

func (ft *flexTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		ft.Time = time.Time{}
		return nil
	}
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		ft.Time = t
		return nil
	}
	// Fall back to date-only.
	if t, err := time.Parse("2006-01-02", s); err == nil {
		ft.Time = t
		return nil
	}
	return fmt.Errorf("flexTime: cannot parse %q", s)
}

// AuditImport holds the parsed result of an archon output folder.
type AuditImport struct {
	RawFindings []*ArchonFinding
	State       *AuditState
	RepoName    string // resolved repo name (URL preferred, then slug, then folder basename)
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
	Repo        string                `json:"repo,omitempty"`        // optional repo slug (e.g. "goharbor/harbor")
	Repository  string                `json:"repository,omitempty"`  // alternate key used by lite/scan modes
	RepoURL     string                `json:"repo_url,omitempty"`    // optional full repo URL
	Mode        string                `json:"mode,omitempty"`        // audit mode: lite, scan, deep
	StartedAt   flexTime              `json:"started_at"`
	CompletedAt flexTime              `json:"completed_at"`
	Status      string                `json:"status"`
	Phases      map[string]PhaseEntry `json:"phases"`
}

// EffectiveRepo returns the repo name from whichever JSON field was populated.
func (e AuditEntry) EffectiveRepo() string {
	if e.Repo != "" {
		return e.Repo
	}
	return e.Repository
}

// PhaseEntry describes one phase in the audit.
// Summary is flexible: LLM-generated audit-state.json may produce a plain string
// or a structured object. We accept both and normalise to map[string]interface{}.
type PhaseEntry struct {
	Status      string                 `json:"status"`
	CompletedAt flexTime               `json:"completed_at"`
	Summary     map[string]interface{} `json:"-"` // populated by custom unmarshal
	SummaryRaw  json.RawMessage        `json:"summary,omitempty"`
}

// UnmarshalJSON implements lenient parsing for PhaseEntry.
// It accepts summary as a string, an object, or absent.
func (p *PhaseEntry) UnmarshalJSON(data []byte) error {
	// Use an alias to avoid infinite recursion.
	type Alias struct {
		Status      string          `json:"status"`
		CompletedAt flexTime        `json:"completed_at"`
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
// It tolerates a missing audit-state.json (e.g. when the archon process was
// cancelled before completing). Findings are read from findings/ (promoted,
// severity-prefixed IDs) when present and otherwise fall back to
// findings-draft/ (intermediate p/l/q-prefixed IDs).
func ParseAuditFolder(folderPath string) (*AuditImport, error) {
	statePath := filepath.Join(folderPath, "audit-state.json")

	var state *AuditState
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		// No state file yet — create a synthetic empty state so callers
		// that access State fields don't panic.
		state = &AuditState{}
	} else {
		var parseErr error
		state, parseErr = parseAuditState(statePath)
		if parseErr != nil {
			return nil, fmt.Errorf("parse audit-state.json: %w", parseErr)
		}
	}

	// Prefer findings/ (promoted, post-audit) over findings-draft/ (intermediate).
	findings, err := parsePromotedFindings(filepath.Join(folderPath, "findings"))
	if err != nil {
		return nil, fmt.Errorf("parse findings: %w", err)
	}
	if len(findings) == 0 {
		findings, err = parseFindingsDir(filepath.Join(folderPath, "findings-draft"))
		if err != nil {
			return nil, fmt.Errorf("parse findings-draft: %w", err)
		}
	}

	// Nothing to import if both state and findings are empty.
	if len(state.Audits) == 0 && len(findings) == 0 {
		return nil, fmt.Errorf("no audit-state.json and no findings in %s", folderPath)
	}

	repoName := resolveRepoName(state, folderPath)

	return &AuditImport{
		State:       state,
		RawFindings: findings,
		RepoName:    repoName,
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
	durationMs := audit.CompletedAt.Sub(audit.StartedAt.Time).Milliseconds()

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
		StartedAt:   audit.StartedAt.Time,
		CompletedAt: audit.CompletedAt.Time,
		DurationMs:  durationMs,
		ResultJSON:  string(stateBytes),
		AttackPlan:  attackPlan,
	}
}

// BuildFindings converts parsed ArchonFindings to database.Finding structs.
func BuildFindings(findings []*ArchonFinding, auditID, agentRunUUID, projectUUID, repoName string) []*database.Finding {
	var result []*database.Finding
	for _, af := range findings {
		result = append(result, toDBFinding(af, auditID, agentRunUUID, projectUUID, repoName))
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

// liteFindingFileRegex matches legacy lite-mode filenames like l1-001.md or l2-003.md (no slug).
var liteFindingFileRegex = regexp.MustCompile(`^l(\d+)-(\d+)\.md$`)

// quickFindingFileRegex matches current lite-mode filenames like q1-001.md or q2-009.md.
// Lite mode phases are Q0 (recon), Q1 (secrets scan), Q2 (fast SAST); only Q1/Q2 emit findings.
var quickFindingFileRegex = regexp.MustCompile(`^q(\d+)-(\d+)\.md$`)

// promotedFindingRegex matches severity-prefixed promoted finding names.
// Matches both directory entries (C1-sqli-user-lookup) and flat files (C1.md, H2-weak-jwt.md).
// Group 1: severity letter (C/H/M/L), Group 2: sequence, Group 3: optional slug.
var promotedFindingRegex = regexp.MustCompile(`^([CHML])(\d+)(?:-(.+?))?$`)

func parseFindingFile(path string) (*ArchonFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	filename := filepath.Base(path)
	content := string(data)

	// Try standard deep/scan-mode pattern first: p<phase>-<seq>-<slug>.md
	if m := findingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		slug := m[3]
		findingID := fmt.Sprintf("P%s-%s", phase, seq)

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

	// Try legacy lite-mode pattern: l<phase>-<seq>.md
	if m := liteFindingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		findingID := fmt.Sprintf("L%s-%s", phase, seq)

		af := &ArchonFinding{
			FindingID: findingID,
			Phase:     phase,
			Sequence:  seq,
			Filename:  filename,
		}
		parseLiteFinding(af, content)
		return af, nil
	}

	// Try current lite-mode pattern: q<phase>-<seq>.md
	if m := quickFindingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		findingID := fmt.Sprintf("Q%s-%s", phase, seq)

		af := &ArchonFinding{
			FindingID: findingID,
			Phase:     phase,
			Sequence:  seq,
			Filename:  filename,
		}
		parseLiteFinding(af, content)
		return af, nil
	}

	return nil, nil // not a finding file
}

// parsePromotedFindings reads the archon/findings/ directory where confirmed
// findings have been promoted out of findings-draft/ with severity-prefixed IDs
// (C1, H2, M3, ...). Two layouts are supported:
//
//   - Directory per finding: findings/C1-sqli-user-lookup/{draft.md, report.md, poc.*, evidence/}
//   - Flat files: findings/C1.md + findings/C1-poc.md (test-fixture shape)
//
// Returns nil without error when the directory does not exist.
func parsePromotedFindings(dir string) ([]*ArchonFinding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var findings []*ArchonFinding
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if af := parsePromotedFindingDir(filepath.Join(dir, name), name); af != nil {
				findings = append(findings, af)
			}
			continue
		}
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		// Skip PoC companion files — they share an ID with the primary finding.
		base := strings.TrimSuffix(name, ".md")
		if strings.HasSuffix(base, "-poc") {
			continue
		}
		if af := parsePromotedFindingFile(filepath.Join(dir, name), base); af != nil {
			findings = append(findings, af)
		}
	}

	// Sort for deterministic ordering: severity C > H > M > L, then numeric sequence.
	sort.SliceStable(findings, func(i, j int) bool {
		return promotedSortKey(findings[i]) < promotedSortKey(findings[j])
	})
	return findings, nil
}

// promotedSortKey builds a string sort key that orders C* < H* < M* < L* and
// then pads the sequence number so C2 < C10.
func promotedSortKey(af *ArchonFinding) string {
	rank := "9"
	if len(af.FindingID) > 0 {
		switch af.FindingID[0] {
		case 'C':
			rank = "0"
		case 'H':
			rank = "1"
		case 'M':
			rank = "2"
		case 'L':
			rank = "3"
		}
	}
	return rank + fmt.Sprintf("%06s", af.Sequence) + af.FindingID
}

// parsePromotedFindingDir parses a findings/<ID>-<slug>/ directory by reading
// draft.md (metadata) and optionally appending report.md to the body.
func parsePromotedFindingDir(dirPath, entryName string) *ArchonFinding {
	m := promotedFindingRegex.FindStringSubmatch(entryName)
	if m == nil {
		return nil
	}

	draftPath := filepath.Join(dirPath, "draft.md")
	data, err := os.ReadFile(draftPath)
	if err != nil {
		// No draft — try report.md as the sole source.
		data, err = os.ReadFile(filepath.Join(dirPath, "report.md"))
		if err != nil {
			return nil
		}
	}

	af := newPromotedArchonFinding(m, entryName)
	af.Filename = entryName + "/draft.md"
	parseLiteFinding(af, string(data))

	// Append report.md if it exists and isn't already the body source.
	if report, err := os.ReadFile(filepath.Join(dirPath, "report.md")); err == nil && len(report) > 0 {
		if !strings.Contains(af.Body, string(report)) {
			af.Body = af.Body + "\n\n---\n\n" + string(report)
		}
	}

	// Directory name wins over any Q-prefixed ID the content-level parser
	// might have derived from a "## Q1-001:" header inside draft.md.
	restorePromotedIdentity(af, m)
	return af
}

// parsePromotedFindingFile parses a flat findings/<ID>[-<slug>].md file.
func parsePromotedFindingFile(path, base string) *ArchonFinding {
	m := promotedFindingRegex.FindStringSubmatch(base)
	if m == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	af := newPromotedArchonFinding(m, base)
	af.Filename = base + ".md"
	parseLiteFinding(af, string(data))
	restorePromotedIdentity(af, m)
	return af
}

// newPromotedArchonFinding creates an ArchonFinding seeded with the promoted
// ID/slug/severity from a regex match against the dir or file name.
func newPromotedArchonFinding(m []string, entryName string) *ArchonFinding {
	sevLetter := m[1]
	seq := m[2]
	slug := ""
	if len(m) > 3 {
		slug = m[3]
	}
	return &ArchonFinding{
		FindingID: sevLetter + seq,
		Phase:     "lite",
		Sequence:  seq,
		Slug:      slug,
		Severity:  severityFromLetter(sevLetter),
	}
}

// restorePromotedIdentity re-asserts the directory/file-derived FindingID,
// slug, and severity after parseLiteFinding has run, since the lite-finding
// content parser may overwrite them from inline "## Q1-001:" style headers.
func restorePromotedIdentity(af *ArchonFinding, m []string) {
	sevLetter := m[1]
	seq := m[2]
	slug := ""
	if len(m) > 3 {
		slug = m[3]
	}

	af.FindingID = sevLetter + seq
	af.Sequence = seq
	af.Phase = "lite"
	if slug != "" {
		af.Slug = slug
	}
	// Ensure severity comes from the promoted ID when content is silent.
	if af.Severity == "" {
		af.Severity = severityFromLetter(sevLetter)
	}
}

// severityFromLetter maps the C/H/M/L prefix of a promoted finding ID to a
// severity word that toDBFinding will normalize.
func severityFromLetter(letter string) string {
	switch letter {
	case "C":
		return "Critical"
	case "H":
		return "High"
	case "M":
		return "Medium"
	case "L":
		return "Low"
	}
	return ""
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

// liteBoldFieldRegex matches markdown bold list items: - **Key**: Value
var liteBoldFieldRegex = regexp.MustCompile(`-\s*\*\*(.+?)\*\*:\s*(.+)`)

// liteHeadingRegex matches lite finding headings: "## l2-001: Title" or
// the current "## Q1-001: Title" (case-insensitive on the L/Q prefix).
var liteHeadingRegex = regexp.MustCompile(`(?mi)^##\s+[lq]\d+-\d+:\s*(.+)`)

// parseLiteFinding parses the lite-mode markdown format with bold list items.
func parseLiteFinding(af *ArchonFinding, content string) {
	// Extract title from ## heading
	if m := liteHeadingRegex.FindStringSubmatch(content); m != nil {
		af.Title = strings.TrimSpace(m[1])
	}

	// Extract fields from - **Key**: Value lines
	for _, m := range liteBoldFieldRegex.FindAllStringSubmatch(content, -1) {
		key := strings.TrimSpace(m[1])
		val := strings.TrimSpace(m[2])
		switch key {
		case "Severity":
			af.Severity = val
		case "File":
			af.Locations = append(af.Locations, val)
		case "Line":
			// Append line number to the last location if present
			if len(af.Locations) > 0 {
				af.Locations[len(af.Locations)-1] += ":" + val
			}
		case "Category":
			af.Slug = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(val, " ", "-"), "—", "-"))
		case "CWE":
			af.CWE = extractCWE(val)
		case "Verdict":
			af.Verdict = val
		}
	}

	// If no slug was derived from Category, create one from the title
	if af.Slug == "" && af.Title != "" {
		af.Slug = strings.ToLower(strings.ReplaceAll(af.Title, " ", "-"))
	}

	// Set confidence from verdict — store the raw verdict value so that
	// toDBFinding's mapConfidence call produces the correct result.
	if af.Confidence == "" && af.Verdict != "" {
		af.Confidence = af.Verdict
	}

	af.Body = content
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

func toDBFinding(af *ArchonFinding, auditID, agentRunUUID, projectUUID, repoName string) *database.Finding {
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
		RepoName:        repoName,
		MatchedAt:       af.Locations,
		FindingHash:     hash,
		FoundAt:         time.Now(),
	}
}

// resolveRepoName determines the repository name from available sources.
// Priority: audit-state.json repo_url → repo → commit-recon-report.md → folder basename.
func resolveRepoName(state *AuditState, folderPath string) string {
	if len(state.Audits) > 0 {
		audit := state.Audits[0]
		if audit.RepoURL != "" {
			return audit.RepoURL
		}
		if repo := audit.EffectiveRepo(); repo != "" {
			return repo
		}
	}

	if name := extractRepoFromCommitRecon(folderPath); name != "" {
		return name
	}

	return filepath.Base(folderPath)
}

// repoLineRegex matches "**Repository**: value" in commit-recon-report.md.
// Captures the value after the colon, which may be a slug like "Kong/kong"
// or a slug followed by a URL like "goharbor/harbor (https://github.com/goharbor/harbor)".
var repoLineRegex = regexp.MustCompile(`(?m)^\*\*Repository\*\*:\s*(.+)$`)

// repoURLInParens extracts a URL from parentheses, e.g. "(https://github.com/goharbor/harbor)".
var repoURLInParens = regexp.MustCompile(`\((https?://[^\s)]+)\)`)

func extractRepoFromCommitRecon(folderPath string) string {
	data, err := os.ReadFile(filepath.Join(folderPath, "commit-recon-report.md"))
	if err != nil {
		return ""
	}

	m := repoLineRegex.FindSubmatch(data)
	if m == nil {
		return ""
	}
	val := strings.TrimSpace(string(m[1]))

	// Prefer a URL in parentheses if present (e.g. "goharbor/harbor (https://...)")
	if urlMatch := repoURLInParens.FindStringSubmatch(val); urlMatch != nil {
		return urlMatch[1]
	}

	// Otherwise return the raw value (typically an org/repo slug)
	return val
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
