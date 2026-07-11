package audit

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vigolium/vigolium/pkg/database"
)

// flexTime wraps time.Time with lenient JSON unmarshaling that accepts
// RFC3339 ("2006-01-02T15:04:05Z07:00"), timezone-less datetime
// ("2006-01-02T15:04:05"), and date-only ("2006-01-02") formats.
// LLM-generated audit-state.json files frequently omit timezone information.
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
	// Fall back to a timezone-less datetime. With no offset to preserve, use
	// UTC so imports remain deterministic across machines.
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
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
