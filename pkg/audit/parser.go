package audit

import (
	"bytes"
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
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"

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

// Import holds the parsed result of an audit output folder.
type Import struct {
	RawFindings  []*Finding
	State        *State
	RevisitState *RevisitState // nil when no revisit-audit-state.json exists
	RepoName     string        // resolved repo name (URL preferred, then slug, then folder basename)
}

// State represents the top-level audit-state.json structure.
type State struct {
	Audits        []Entry        `json:"audits"`
	MergeMetadata *MergeMetadata `json:"merge_metadata,omitempty"`
}

// MergeMetadata captures the provenance of a merged audit.
type MergeMetadata struct {
	Sources   []string          `json:"sources,omitempty"`
	RenameMap map[string]string `json:"rename_map,omitempty"`
}

// RevisitState represents the top-level revisit-audit-state.json structure.
type RevisitState struct {
	Revisits []RevisitEntry `json:"revisits"`
}

// RevisitEntry is a single revisit run.
type RevisitEntry struct {
	RevisitID     string                `json:"revisit_id"`
	ParentAuditID string                `json:"parent_audit_id"`
	Round         int                   `json:"round"`
	Commit        string                `json:"commit"`
	Branch        string                `json:"branch"`
	Repository    string                `json:"repository,omitempty"`
	Mode          string                `json:"mode,omitempty"`
	Model         string                `json:"model,omitempty"`
	AgentSDK      string                `json:"agent_sdk,omitempty"`
	StartedAt     flexTime              `json:"started_at"`
	CompletedAt   flexTime              `json:"completed_at"`
	Status        string                `json:"status"`
	Phases        map[string]PhaseEntry `json:"phases"`
	Seed          *RevisitSeed          `json:"seed,omitempty"`
	NewFindingIDs []string              `json:"new_finding_ids,omitempty"`
}

// RevisitSeed captures the known findings and attack modes from the prior audit.
type RevisitSeed struct {
	KBPath                    string         `json:"kb_path,omitempty"`
	KnownFindings             []KnownFinding `json:"known_findings,omitempty"`
	KnownAttackModes          []string       `json:"known_attack_modes,omitempty"`
	KnownFindingIDsBySeverity map[string]int `json:"known_finding_ids_by_severity,omitempty"`
}

// KnownFinding represents a finding from a prior audit round.
type KnownFinding struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Class    string `json:"class"`
	Location string `json:"location"`
}

// Entry is a single audit run inside audit-state.json.
type Entry struct {
	AuditID          string                `json:"audit_id"`
	Commit           string                `json:"commit"`
	Branch           string                `json:"branch"`
	Repo             string                `json:"repo,omitempty"`       // optional repo slug (e.g. "goharbor/harbor")
	Repository       string                `json:"repository,omitempty"` // alternate key used by lite/balanced modes
	RepoURL          string                `json:"repo_url,omitempty"`   // optional full repo URL
	Mode             string                `json:"mode,omitempty"`       // audit mode: lite, balanced, deep, merge, revisit
	Model            string                `json:"model,omitempty"`      // model used (e.g. opus-4.6, gpt-5.3-codex)
	AgentSDK         string                `json:"agent_sdk,omitempty"`  // platform (e.g. claude-code, codex, bytesec)
	HistoryAvailable *bool                 `json:"history_available,omitempty"`
	StartedAt        flexTime              `json:"started_at"`
	CompletedAt      flexTime              `json:"completed_at"`
	Status           string                `json:"status"`
	Phases           map[string]PhaseEntry `json:"phases"`
}

// EffectiveRepo returns the repo name from whichever JSON field was populated.
func (e Entry) EffectiveRepo() string {
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

// Finding is the intermediate representation of a parsed finding file.
type Finding struct {
	// Common fields
	FindingID  string // e.g. "P7-001", "P8-001"
	Phase      string // "7", "8", "10"
	Sequence   string // "001", "002"
	Slug       string // e.g. "open-redirect-authproxy"
	Title      string
	Severity   string
	Confidence string
	CWE        string
	Verdict    string // VALID, INVALID, etc.
	PoCStatus  string // theoretical, pending, confirmed

	// Phase 8+ specific
	SeverityOriginal     string
	SeverityFinal        string
	AdversarialVerdict   string
	AdversarialRationale string

	// Locations extracted from the body
	Locations []string

	// Full markdown body (everything after frontmatter/header)
	Body string

	// Source filename
	Filename string

	// Enrichment from promoted finding directories
	Remediation     string // extracted from ## Fix / ## Remediation sections
	PoCFile         string // filename of poc.* file (e.g. "poc.py", "poc.sh")
	PoCContent      string // raw content of poc.* file
	IsVariant       bool
	OriginFindingID string // e.g. "H6" when this finding is a variant

	// Provenance marks which directory the finding was read from:
	//   ""            promoted/confirmed (findings/) — keeps its real severity
	//   "theoretical" findings-theoretical/ (VALID but not confirmed)
	//   "draft"       findings-draft/ imported alongside a populated findings/
	// Non-empty values are coerced to INFO severity and tagged at DB-build
	// time so they read as informational context, not confirmed bugs.
	Provenance string
}

// ParseFolder parses an audit output folder and returns the import data.
// It tolerates a missing audit-state.json (e.g. when the audit process was
// cancelled before completing).
//
// Findings are read from findings/ (promoted, severity-prefixed IDs) when
// present. In addition, findings-theoretical/ (VALID-but-not-confirmed) and,
// when findings/ is populated, findings-draft/ (intermediate p/l/q-prefixed
// drafts) are imported as supplementary findings flagged via
// Finding.Provenance so they land as INFO-severity informational
// context. When findings/ is empty (cancelled/partial run) findings-draft/
// stands in as the primary set and keeps its real draft severities.
func ParseFolder(folderPath string) (*Import, error) {
	statePath := filepath.Join(folderPath, "audit-state.json")

	var state *State
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		// No state file yet — create a synthetic empty state so callers
		// that access State fields don't panic.
		state = &State{}
	} else {
		var parseErr error
		state, parseErr = parseState(statePath)
		if parseErr != nil {
			return nil, fmt.Errorf("parse audit-state.json: %w", parseErr)
		}
	}

	// Parse revisit-audit-state.json if present (ignore missing file errors).
	revisitState, _ := parseRevisitState(filepath.Join(folderPath, "revisit-audit-state.json"))

	// Prefer findings/ (promoted, post-audit) as the confirmed set.
	findings, err := parsePromotedFindings(filepath.Join(folderPath, "findings"))
	if err != nil {
		return nil, fmt.Errorf("parse findings: %w", err)
	}

	if len(findings) == 0 {
		// Cancelled/partial run: findings-draft/ is the only output, so it
		// stands in as the primary set with its real (draft) severities.
		findings, err = parseFindingsDir(filepath.Join(folderPath, "findings-draft"))
		if err != nil {
			return nil, fmt.Errorf("parse findings-draft: %w", err)
		}
	} else {
		// findings/ is the confirmed set. Drafts are intermediate copies of
		// the same work; import them too but flag them so they land as
		// informational context rather than confirmed bugs.
		drafts, derr := parseFindingsDir(filepath.Join(folderPath, "findings-draft"))
		if derr != nil {
			return nil, fmt.Errorf("parse findings-draft: %w", derr)
		}
		for _, d := range drafts {
			d.Provenance = "draft"
		}
		findings = append(findings, drafts...)
	}

	// findings-theoretical/ holds VALID-but-not-confirmed findings (distinct
	// IDs from findings/). Always import them as informational context.
	theoretical, terr := parsePromotedFindings(filepath.Join(folderPath, "findings-theoretical"))
	if terr != nil {
		return nil, fmt.Errorf("parse findings-theoretical: %w", terr)
	}
	for _, tf := range theoretical {
		tf.Provenance = "theoretical"
	}
	findings = append(findings, theoretical...)

	// Nothing to import if both state and findings are empty.
	if len(state.Audits) == 0 && len(findings) == 0 {
		return nil, fmt.Errorf("no audit-state.json and no findings in %s", folderPath)
	}

	repoName := resolveRepoName(state, folderPath)

	return &Import{
		State:        state,
		RevisitState: revisitState,
		RawFindings:  findings,
		RepoName:     repoName,
	}, nil
}

// FindingSource carries the import-source metadata used when converting
// Findings into database rows. The audit and piolium harnesses share
// the same on-disk schema but tag their DB rows differently so they can be
// queried apart. DefaultSource() returns the values used for audit
// runs; piolium populates its own values via PioliumSource().
type FindingSource struct {
	Mode      string // database.AgenticScan.Mode (e.g. "audit", "piolium")
	AgentName string // database.AgenticScan.AgentName (e.g. "vigolium-audit", "piolium")
	InputType string // database.AgenticScan.InputType
	IDPrefix  string // module_id prefix (e.g. "audit" → "audit:c1-...", "piolium" → "piolium:c1-...")
	Tag       string // tag added to every finding (e.g. "audit", "piolium")
}

// DefaultSource returns the metadata for vigolium-audit runs. Used by
// callers that don't explicitly choose a harness flavor.
func DefaultSource() FindingSource {
	return FindingSource{
		Mode:      "audit",
		AgentName: "vigolium-audit",
		InputType: "audit",
		IDPrefix:  "audit",
		Tag:       "audit",
	}
}

// BuildAgenticScan creates a database.AgenticScan from the parsed audit state.
// Defaults to vigolium-audit metadata; use BuildAgenticScanWithSource to override.
func BuildAgenticScan(state *State, folderPath, projectUUID string) *database.AgenticScan {
	return BuildAgenticScanWithSource(state, folderPath, projectUUID, DefaultSource())
}

// BuildAgenticScanWithSource is the source-aware variant. The piolium harness
// uses this so its DB rows tag as "piolium" rather than "audit" while sharing
// the on-disk schema and parser.
func BuildAgenticScanWithSource(state *State, folderPath, projectUUID string, src FindingSource) *database.AgenticScan {
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

	return &database.AgenticScan{
		UUID:         uuid.New().String(),
		ProjectUUID:  projectUUID,
		Mode:         src.Mode,
		AgentName:    src.AgentName,
		Model:        audit.Model,
		InputRaw:     fmt.Sprintf("commit:%s branch:%s", audit.Commit, audit.Branch),
		InputType:    src.InputType,
		TargetURL:    audit.EffectiveRepo(),
		Status:       status,
		PhasesRun:    phases,
		FindingCount: findingCount,
		SourcePath:   folderPath,
		SourceType:   database.InferSourceType(folderPath),
		StartedAt:    audit.StartedAt.Time,
		CompletedAt:  audit.CompletedAt.Time,
		DurationMs:   durationMs,
		ResultJSON:   string(stateBytes),
		AttackPlan:   attackPlan,
	}
}

// BuildFindings converts parsed Findings to database.Finding structs
// using vigolium-audit metadata. Callers needing a different source flavor
// (e.g. piolium) should use BuildFindingsWithSource.
func BuildFindings(findings []*Finding, auditID, agenticScanUUID, projectUUID, repoName string) []*database.Finding {
	return BuildFindingsWithSource(findings, auditID, agenticScanUUID, projectUUID, repoName, DefaultSource())
}

// BuildFindingsWithSource is the source-aware variant. The piolium harness
// uses this so module_ids prefix as "piolium:..." and tags include "piolium"
// rather than "audit".
func BuildFindingsWithSource(findings []*Finding, auditID, agenticScanUUID, projectUUID, repoName string, src FindingSource) []*database.Finding {
	var result []*database.Finding
	for _, af := range findings {
		result = append(result, toDBFindingWithSource(af, auditID, agenticScanUUID, projectUUID, repoName, src))
	}
	return result
}

func parseJSONFile[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func parseState(path string) (*State, error) {
	return parseJSONFile[State](path)
}

func parseRevisitState(path string) (*RevisitState, error) {
	return parseJSONFile[RevisitState](path)
}

func parseFindingsDir(dir string) ([]*Finding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil // no findings-draft directory is valid (empty audit)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	// First pass: parse base findings (skip .cold-verify.md files)
	findingsByID := make(map[string]*Finding)
	var findings []*Finding

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

// findingFileRegex matches audit finding filenames like p7-001-slug.md or p8-002-slug.cold-verify.md
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

// phasePrefixedDirRegex matches piolium's promoted-finding directory naming,
// which keeps the source phase-prefixed ID rather than promoting to severity-
// letter format. Examples: "p10-001-direct-git-url-ref-reaches-…",
// "p12-cleartext-http-git-sources" (no sequence — slug only).
// Group 1: phase digits, Group 2: optional sequence digits, Group 3: optional slug.
var phasePrefixedDirRegex = regexp.MustCompile(`^p(\d+)(?:-(\d+))?(?:-(.+?))?$`)

func parseFindingFile(path string) (*Finding, error) {
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

		af := &Finding{
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

		af := &Finding{
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

		af := &Finding{
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

// parsePromotedFindings reads the audit/findings/ directory where confirmed
// findings have been promoted out of findings-draft/ with severity-prefixed IDs
// (C1, H2, M3, ...). Two layouts are supported:
//
//   - Directory per finding: findings/C1-sqli-user-lookup/{draft.md, report.md, poc.*, evidence/}
//   - Flat files: findings/C1.md + findings/C1-poc.md (test-fixture shape)
//
// Returns nil without error when the directory does not exist.
func parsePromotedFindings(dir string) ([]*Finding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var findings []*Finding
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			// Severity-prefixed (audit: C1-sqli-user-lookup/) — try first.
			if af := parsePromotedFindingDir(filepath.Join(dir, name), name); af != nil {
				findings = append(findings, af)
				continue
			}
			// Phase-prefixed (piolium: p10-001-direct-git-url-…/). Piolium
			// keeps the source phase ID on its promoted findings rather than
			// renumbering to severity-letter format.
			if af := parsePhasePrefixedFindingDir(filepath.Join(dir, name), name); af != nil {
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
func promotedSortKey(af *Finding) string {
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

// readFindingDirContents populates af in place from a findings/<ID>/
// directory: parses draft.md frontmatter first, then prefers report.md
// for the body, and finally enriches with poc.* and metadata.json.
// Returns false when neither draft.md nor report.md exists. Callers must
// pre-populate af with the directory-derived identity (FindingID, Phase,
// Sequence, Slug, Severity); frontmatter from draft.md may refine it.
func readFindingDirContents(dirPath, entryName string, af *Finding) bool {
	reportData, reportErr := os.ReadFile(filepath.Join(dirPath, "report.md"))
	draftData, draftErr := os.ReadFile(filepath.Join(dirPath, "draft.md"))
	if reportErr != nil && draftErr != nil {
		return false
	}

	if draftErr == nil {
		af.Filename = entryName + "/draft.md"
		parseFrontmatterFinding(af, string(draftData))
	}
	if reportErr == nil && len(reportData) > 0 {
		af.Filename = entryName + "/report.md"
		reportContent := string(reportData)
		parseReportMd(af, reportContent)
		af.Body = reportContent
	} else if draftErr == nil {
		parseLiteFinding(af, string(draftData))
	}

	if pocFile := detectPoCFile(dirPath); pocFile != "" {
		af.PoCFile = pocFile
		if pocContent, err := os.ReadFile(filepath.Join(dirPath, pocFile)); err == nil && len(pocContent) > 0 {
			const maxPoCSize = 512 * 1024
			if len(pocContent) > maxPoCSize {
				pocContent = append(pocContent[:maxPoCSize], "\n... (truncated)"...)
			}
			af.PoCContent = string(pocContent)
		}
	}
	parseMetadataJSON(af, dirPath)
	return true
}

// parsePhasePrefixedFindingDir parses a piolium-style findings/p<phase>-<seq>-<slug>/
// directory. Same content layout as the severity-prefixed audit variant;
// only the identity (FindingID, Phase, Sequence, Slug) is derived from
// the phase-prefixed directory name. Draft frontmatter may override.
func parsePhasePrefixedFindingDir(dirPath, entryName string) *Finding {
	m := phasePrefixedDirRegex.FindStringSubmatch(entryName)
	if m == nil {
		return nil
	}
	phase := m[1]
	seq := ""
	slug := ""
	if len(m) > 2 {
		seq = m[2]
	}
	if len(m) > 3 {
		slug = m[3]
	}
	findingID := "P" + phase
	if seq != "" {
		findingID = fmt.Sprintf("P%s-%s", phase, seq)
	}
	af := &Finding{FindingID: findingID, Phase: phase, Sequence: seq, Slug: slug}
	if !readFindingDirContents(dirPath, entryName, af) {
		return nil
	}
	if af.Slug == "" && slug != "" {
		af.Slug = slug
	}
	return af
}

// parsePromotedFindingDir parses a findings/<ID>-<slug>/ directory.
// Priority: report.md (polished, structured) → draft.md (frontmatter metadata).
// Also reads poc.* files and metadata.json for enrichment.
func parsePromotedFindingDir(dirPath, entryName string) *Finding {
	m := promotedFindingRegex.FindStringSubmatch(entryName)
	if m == nil {
		return nil
	}
	af := newPromotedFinding(m, entryName)
	if !readFindingDirContents(dirPath, entryName, af) {
		return nil
	}
	restorePromotedIdentity(af, m)
	return af
}

// parsePromotedFindingFile parses a flat findings/<ID>[-<slug>].md file.
func parsePromotedFindingFile(path, base string) *Finding {
	m := promotedFindingRegex.FindStringSubmatch(base)
	if m == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	af := newPromotedFinding(m, base)
	af.Filename = base + ".md"
	parseLiteFinding(af, string(data))
	restorePromotedIdentity(af, m)
	return af
}

// newPromotedFinding creates an Finding seeded with the promoted
// ID/slug/severity from a regex match against the dir or file name.
func newPromotedFinding(m []string, entryName string) *Finding {
	sevLetter := m[1]
	seq := m[2]
	slug := ""
	if len(m) > 3 {
		slug = m[3]
	}
	return &Finding{
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
func restorePromotedIdentity(af *Finding, m []string) {
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
	// The promoted directory prefix (C/H/M/L) is the canonical severity for
	// the finding — that's the tier the auditor assigned at promotion time
	// and the one operators see when listing the findings/ tree. Any later
	// downgrade recorded inside report.md or in the draft's body (## Cold
	// Verification) is preserved as descriptive content, but does not
	// overwrite the headline severity. SeverityOriginal/SeverityFinal stay
	// available on the struct for callers that want the verdict trail.
	af.Severity = severityFromLetter(sevLetter)
}

// mdParser is a reusable goldmark markdown parser.
var mdParser = goldmark.DefaultParser()

// reportTitleSepRegex strips the finding-ID prefix from H1 headings:
// "H3 — Title" or "M9 - Title" → "Title".
var reportTitleSepRegex = regexp.MustCompile(`^\S+\s*(?:—|--|-)\s*`)

// reportBoldKVRegex matches **Key**: Value patterns within paragraph text.
var reportBoldKVRegex = regexp.MustCompile(`\*\*(.+?)\*\*:\s*(.+)`)

// reportPlainKVRegex matches plain Key: Value lines.
var reportPlainKVRegex = regexp.MustCompile(`^([A-Za-z][A-Za-z _-]+?):\s*(.+)$`)

// parseReportMd uses goldmark AST to extract structured fields from report.md.
// Handles all observed LLM format variants (bold-header, plain-kv, H1-title).
func parseReportMd(af *Finding, content string) {
	source := []byte(content)
	reader := text.NewReader(source)
	doc := mdParser.Parse(reader)

	sections := parseMdSections(doc, source)

	// Extract title from H1 heading.
	if h1 := sections.h1Text; h1 != "" {
		title := reportTitleSepRegex.ReplaceAllString(h1, "")
		if title != "" {
			af.Title = strings.TrimSpace(title)
		}
	}

	// Extract metadata from the preamble (content before first ## heading).
	for _, line := range sections.preambleLines {
		// Bold key-value: **Severity**: HIGH
		if m := reportBoldKVRegex.FindStringSubmatch(line); m != nil {
			applyReportField(af, strings.TrimSpace(m[1]), strings.TrimSpace(m[2]))
			continue
		}
		// Plain key-value: Severity: HIGH
		if m := reportPlainKVRegex.FindStringSubmatch(line); m != nil {
			applyReportField(af, strings.TrimSpace(m[1]), strings.TrimSpace(m[2]))
		}
	}

	// If no title from H1, try a Title field or first Summary paragraph.
	if af.Title == "" {
		af.Title = extractTitleFromBody(content, af.Slug)
	}

	// Extract locations from the full body (regex-based, works across all formats).
	if locs := extractLocations(content); len(locs) > 0 {
		af.Locations = locs
	}

	// Extract remediation from ## Fix / ## Remediation / ## Recommendation.
	for _, name := range []string{"Fix", "Remediation", "Recommendation"} {
		if body := sections.sectionBody(name); body != "" {
			af.Remediation = body
			break
		}
	}
}

// mdSections holds the parsed structure of a markdown document.
type mdSections struct {
	h1Text        string
	preambleLines []string          // text lines before the first ## heading
	sections      map[string]string // lowercase heading → raw text body
}

// sectionBody returns the body of a named section (case-insensitive).
func (s *mdSections) sectionBody(name string) string {
	return s.sections[strings.ToLower(name)]
}

// parseMdSections walks the goldmark AST to extract the document structure.
func parseMdSections(doc ast.Node, source []byte) *mdSections {
	result := &mdSections{
		sections: make(map[string]string),
	}

	var currentHeading string
	var currentLevel int
	var sectionStart int
	firstH2Offset := -1

	for node := doc.FirstChild(); node != nil; node = node.NextSibling() {
		if heading, ok := node.(*ast.Heading); ok {
			// Flush previous section.
			if currentHeading != "" && sectionStart > 0 {
				body := extractNodeRangeText(source, sectionStart, nodeStartOffset(node))
				result.sections[strings.ToLower(currentHeading)] = strings.TrimSpace(body)
			}

			headingText := nodeInlineText(heading, source)

			if heading.Level == 1 && result.h1Text == "" {
				result.h1Text = headingText
				currentHeading = ""
				currentLevel = 0
				sectionStart = 0
				continue
			}

			if heading.Level == 2 {
				if firstH2Offset == -1 {
					firstH2Offset = nodeStartOffset(node)
					// Collect preamble lines (between H1 and first H2).
					preambleEnd := firstH2Offset
					result.preambleLines = splitPreambleLines(source, result.h1Text, preambleEnd)
				}
				currentHeading = headingText
				currentLevel = heading.Level
				sectionStart = nodeEndOffset(node, source)
			} else if heading.Level > 2 && currentLevel >= 2 {
				// Sub-headings within a section — keep accumulating.
				continue
			}
		}
	}

	// Flush final section.
	if currentHeading != "" && sectionStart > 0 {
		body := string(source[sectionStart:])
		result.sections[strings.ToLower(currentHeading)] = strings.TrimSpace(body)
	}

	// If no H2 was found, treat everything as preamble.
	if firstH2Offset == -1 {
		result.preambleLines = splitPreambleLines(source, result.h1Text, len(source))
	}

	return result
}

// nodeInlineText extracts the plain text content of a heading node.
func nodeInlineText(n ast.Node, source []byte) string {
	var buf strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			buf.Write(t.Segment.Value(source))
		} else {
			// Recurse into inline elements (bold, code, etc.)
			buf.WriteString(nodeInlineText(c, source))
		}
	}
	return buf.String()
}

// nodeStartOffset returns the byte offset where a node starts in the source.
func nodeStartOffset(n ast.Node) int {
	if n.HasChildren() {
		first := n.FirstChild()
		if first != nil && first.Type() == ast.TypeInline {
			if t, ok := first.(*ast.Text); ok {
				return t.Segment.Start
			}
		}
	}
	if lines := n.Lines(); lines != nil && lines.Len() > 0 {
		return lines.At(0).Start
	}
	return 0
}

// nodeEndOffset returns the byte offset after the last line of a node.
func nodeEndOffset(n ast.Node, source []byte) int {
	if lines := n.Lines(); lines != nil && lines.Len() > 0 {
		return lines.At(lines.Len() - 1).Stop
	}
	// For headings without body lines, find the next newline after the heading text.
	start := nodeStartOffset(n)
	idx := bytes.IndexByte(source[start:], '\n')
	if idx >= 0 {
		return start + idx + 1
	}
	return start
}

// extractNodeRangeText extracts text between two byte offsets.
func extractNodeRangeText(source []byte, start, end int) string {
	if start >= end || start >= len(source) {
		return ""
	}
	if end > len(source) {
		end = len(source)
	}
	return string(source[start:end])
}

// splitPreambleLines extracts non-empty text lines from the preamble area.
func splitPreambleLines(source []byte, h1Text string, endOffset int) []string {
	if endOffset > len(source) {
		endOffset = len(source)
	}
	raw := string(source[:endOffset])

	// Skip past the H1 heading line if present.
	if h1Text != "" {
		if idx := strings.Index(raw, h1Text); idx >= 0 {
			nlIdx := strings.IndexByte(raw[idx:], '\n')
			if nlIdx >= 0 {
				raw = raw[idx+nlIdx+1:]
			}
		}
	}

	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "---" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// applyReportField maps a key-value pair from report.md header to Finding fields.
func applyReportField(af *Finding, key, val string) {
	switch strings.ToLower(key) {
	case "severity":
		if af.Severity == "" || af.SeverityFinal == "" {
			af.Severity = val
		}
	case "poc-status":
		af.PoCStatus = val
	case "status":
		if strings.Contains(strings.ToLower(val), "confirmed") {
			af.Verdict = "VALID"
		}
		if strings.Contains(strings.ToLower(val), "poc executed") {
			af.PoCStatus = "executed"
		}
	case "title":
		if af.Title == "" {
			af.Title = val
		}
	case "cwe", "cwe context":
		if cwe := extractCWE(val); cwe != "" {
			af.CWE = cwe
		}
	case "cve context":
		if cwe := extractCWE(val); cwe != "" && af.CWE == "" {
			af.CWE = cwe
		}
	case "component":
		val = strings.Trim(val, "`")
		if len(af.Locations) == 0 {
			af.Locations = append(af.Locations, val)
		}
	case "confidence":
		af.Confidence = val
	}
}

// detectPoCFile returns the filename of a poc.* file in the directory, or empty string.
func detectPoCFile(dirPath string) string {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "poc.") {
			return name
		}
	}
	return ""
}

// findingMetadata is the JSON structure of metadata.json in a promoted finding dir.
type findingMetadata struct {
	IsVariant       bool   `json:"is_variant"`
	OriginFindingID string `json:"origin_finding_id"`
	OriginPattern   string `json:"origin_pattern"`
	Round           int    `json:"round,omitempty"`
	RevisitID       string `json:"revisit_id,omitempty"`
	Model           string `json:"model,omitempty"`
	AgentSDK        string `json:"agent_sdk,omitempty"`
}

// parseMetadataJSON reads metadata.json and populates variant fields on the finding.
func parseMetadataJSON(af *Finding, dirPath string) {
	data, err := os.ReadFile(filepath.Join(dirPath, "metadata.json"))
	if err != nil {
		return
	}
	var meta findingMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return
	}
	af.IsVariant = meta.IsVariant
	if meta.OriginFindingID != "" {
		af.OriginFindingID = meta.OriginFindingID
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
func parsePhase7Finding(af *Finding, content string) {
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
func parseFrontmatterFinding(af *Finding, content string) {
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

		// Match keys case-insensitively. Audit uses Title-Case
		// ("Phase", "Severity-Original"); piolium uses lowercase YAML-style
		// ("phase", "severity"). The parser accepts both.
		switch strings.ToLower(key) {
		case "phase":
			af.Phase = val
		case "sequence":
			af.Sequence = val
		case "slug":
			af.Slug = val
		case "verdict":
			af.Verdict = val
		case "severity-original":
			af.SeverityOriginal = val
		case "severity-final":
			af.SeverityFinal = val
		case "severity":
			// Piolium frontmatter has a single "severity" field. Map it to
			// SeverityFinal so the existing "prefer final over original"
			// resolution still works.
			af.SeverityFinal = val
		case "poc-status":
			af.PoCStatus = val
		case "adversarial-verdict":
			af.AdversarialVerdict = val
		case "adversarial-rationale":
			af.AdversarialRationale = val
		}
	}

	// Overlay any "## Cold Verification" body block onto fields the
	// frontmatter left empty. Frontmatter remains authoritative; this only
	// fills gaps so drafts that were downgraded during cold review but
	// never promoted to a polished report.md still import with the
	// post-review verdict.
	applyColdVerificationOverlay(af, lines)

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

// applyColdVerificationOverlay scans content for a "## Cold Verification"
// section (written by audit's adversarial-review pass) and pulls
// Adversarial-Verdict, Adversarial-Rationale, and PoC-Status into
// Finding fields the frontmatter left empty. Frontmatter remains
// authoritative — this only fills gaps. Severity is intentionally not
// overlaid here: the directory prefix (C/H/M/L) is the canonical severity
// for promoted findings and is reasserted by restorePromotedIdentity.
func applyColdVerificationOverlay(af *Finding, lines []string) {
	headingIdx := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "## ") {
			continue
		}
		title := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "##")))
		if strings.HasPrefix(title, "cold verification") {
			headingIdx = i
			break
		}
	}
	if headingIdx == -1 {
		return
	}

	for j := headingIdx + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		// Stop at the next heading at any level — Cold Verification key:value
		// pairs always sit directly under the section heading; sub-sections
		// like "### Verification Details" hold prose, not structured fields.
		if strings.HasPrefix(trimmed, "#") {
			break
		}
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		val := strings.TrimSpace(trimmed[colonIdx+1:])
		if val == "" {
			continue
		}
		switch key {
		case "adversarial-verdict":
			if af.AdversarialVerdict == "" {
				af.AdversarialVerdict = val
			}
		case "adversarial-rationale":
			if af.AdversarialRationale == "" {
				af.AdversarialRationale = val
			}
		case "poc-status":
			if af.PoCStatus == "" {
				af.PoCStatus = val
			}
		}
	}
}

// liteBoldFieldRegex matches markdown bold list items: - **Key**: Value
var liteBoldFieldRegex = regexp.MustCompile(`-\s*\*\*(.+?)\*\*:\s*(.+)`)

// liteHeadingRegex matches lite finding headings: "## l2-001: Title" or
// the current "## Q1-001: Title" (case-insensitive on the L/Q prefix).
var liteHeadingRegex = regexp.MustCompile(`(?mi)^##\s+[lq]\d+-\d+:\s*(.+)`)

// parseLiteFinding parses the lite-mode markdown format with bold list items.
func parseLiteFinding(af *Finding, content string) {
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

func applyColdVerify(base, overlay *Finding) {
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

// toDBFinding is preserved for callers/tests that don't pass a FindingSource.
// It applies the default vigolium-audit metadata.
func toDBFinding(af *Finding, auditID, agenticScanUUID, projectUUID, repoName string) *database.Finding {
	return toDBFindingWithSource(af, auditID, agenticScanUUID, projectUUID, repoName, DefaultSource())
}

func toDBFindingWithSource(af *Finding, auditID, agenticScanUUID, projectUUID, repoName string, src FindingSource) *database.Finding {
	moduleID := fmt.Sprintf("%s:%s", src.IDPrefix, strings.ToLower(af.FindingID))

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

	// findings-theoretical/ and findings-draft/ entries are informational
	// context, not confirmed bugs: pin them to INFO severity and tentative
	// confidence regardless of the severity recorded in their draft body.
	if af.Provenance != "" {
		severity = "info"
		confidence = "tentative"
	}

	// Build tags
	tags := []string{src.Tag, fmt.Sprintf("phase-%s", af.Phase)}
	if af.Provenance != "" {
		tags = append(tags, af.Provenance)
	}
	if af.Verdict != "" {
		tags = append(tags, strings.ToLower(af.Verdict))
	}
	if af.PoCStatus != "" {
		tags = append(tags, fmt.Sprintf("poc-%s", strings.ToLower(af.PoCStatus)))
	}
	if af.CWE != "" {
		tags = append(tags, af.CWE)
	}
	if af.PoCFile != "" {
		tags = append(tags, "poc-available")
	}
	if af.IsVariant && af.OriginFindingID != "" {
		tags = append(tags, fmt.Sprintf("variant-of:%s", af.OriginFindingID))
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

	// Build description: body + PoC content if available.
	// Sanitize trailing orphaned code fences (common LLM output artifact).
	description := sanitizeTrailingFences(af.Body)
	if af.PoCContent != "" {
		ext := ""
		if af.PoCFile != "" {
			ext = strings.TrimPrefix(filepath.Ext(af.PoCFile), ".")
		}
		if ext == "" {
			ext = "text"
		}
		// Use a fence longer than any backtick run inside the PoC content so
		// nested code blocks (e.g. a poc.md containing a ```json block) cannot
		// prematurely close the outer fence under CommonMark rules.
		fence := strings.Repeat("`", maxBacktickRun(af.PoCContent)+1)
		description += "\n\n---\n## Proof of Concept (`" + af.PoCFile + "`)\n\n" + fence + ext + "\n" + af.PoCContent
		if !strings.HasSuffix(af.PoCContent, "\n") {
			description += "\n"
		}
		description += fence + "\n"
	}

	return &database.Finding{
		ProjectUUID:     projectUUID,
		HTTPRecordUUIDs: []string{},
		AgenticScanUUID: agenticScanUUID,
		ModuleID:        moduleID,
		ModuleName:      af.Title,
		ModuleType:      database.ModuleTypeWhitebox,
		FindingSource:   database.FindingSourceAudit,
		ModuleShort:     af.Slug,
		Description:     description,
		Severity:        severity,
		Confidence:      confidence,
		Tags:            tags,
		CWEID:           cweID,
		SourceFile:      sourceFile,
		RepoName:        repoName,
		MatchedAt:       af.Locations,
		FindingHash:     hash,
		Remediation:     af.Remediation,
		Status:          database.StatusDraft,
		FoundAt:         time.Now(),
	}
}

// resolveRepoName determines the repository name from available sources.
// Priority: audit-state.json repo_url → repo → commit-recon-report.md → folder basename.
func resolveRepoName(state *State, folderPath string) string {
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
	fileLocRegex = regexp.MustCompile(`\*\*File\*\*:\s*` + "`" + `([^` + "`" + `]+)` + "`")
	codeLocRegex = regexp.MustCompile("`" + `([^` + "`" + `]+\.\w+:\d+(?:-\d+)?)` + "`" + `\s*--`)
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

// sanitizeTrailingFences removes orphaned trailing code fences from markdown.
// LLM-generated content sometimes emits an extra ``` after a properly closed
// fenced code block. We detect this by walking through all fence markers: if
// the total count is odd the last fence is unmatched, so we strip it.
// maxBacktickRun returns the longest run of consecutive backticks in s, or 2
// when no backticks are present (so callers can default to a 3-backtick fence
// via maxBacktickRun(s)+1).
func maxBacktickRun(s string) int {
	max, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			if cur > max {
				max = cur
			}
		} else {
			cur = 0
		}
	}
	if max < 2 {
		return 2
	}
	return max
}

func sanitizeTrailingFences(s string) string {
	lines := strings.Split(s, "\n")

	inCodeBlock := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCodeBlock = !inCodeBlock
		}
	}

	if !inCodeBlock {
		return s
	}

	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n")
}
