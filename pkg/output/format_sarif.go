package output

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SARIF 2.1.0 export.
//
// The point of this format is interchange: GitHub code scanning, DefectDojo,
// VS Code's SARIF Viewer, Azure DevOps and most SAST/DAST aggregators read it,
// so it is how a Vigolium run gets into someone else's tooling without a custom
// parser. The structs below are hand-rolled rather than pulled from a library
// because the schema is plain JSON and the mapping — not the encoding — is
// where all the decisions live.
//
// Three of those decisions are load-bearing:
//
//   - A finding's primary location is its SOURCE FILE when it has one and its
//     URL otherwise. Vigolium emits both kinds: audit/piolium findings are
//     file-anchored (and only a file-anchored result can be annotated onto a
//     diff by GitHub code scanning), while the native module fleet is
//     URL-anchored. Emitting the URL as `artifactLocation.uri` is valid — the
//     spec takes any URI — and a consumer that cannot resolve it still shows
//     the alert rather than dropping it.
//   - The raw exchange rides in `webRequest`/`webResponse`, which SARIF 2.1.0
//     defines for exactly this purpose, NOT in the message text. A viewer that
//     understands DAST results renders them as a request/response pair; one
//     that does not simply ignores them, and neither ends up with an 8 KB HTTP
//     dump pasted into the alert title.
//   - `partialFingerprints` carries the finding hash, which is what lets a
//     consumer track one finding across re-scans instead of closing and
//     reopening an alert every run.
const (
	sarifVersion = "2.1.0"
	// sarifSchemaURI is OASIS's own published errata01 schema. Deliberately not
	// the raw.githubusercontent.com/oasis-tcs/sarif-spec URL that most tools
	// copied from GitHub's docs: that one is branch-qualified and already 404s
	// since the repo renamed master to main, so a validator that dereferences
	// $schema fails on it. The docs.oasis-open.org path is a permanent
	// publication URL.
	sarifSchemaURI      = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	sarifToolName       = "Vigolium"
	sarifInformationURI = "https://docs.vigolium.com"

	// sarifMaxBodyBytes caps each embedded request/response body. A SARIF file
	// is an upload target (GitHub rejects one over 10 MB gzipped), and a scan
	// with a few thousand findings each carrying a full response would blow
	// past that long before the results themselves did. Truncation is recorded
	// in the result's properties rather than being silent.
	sarifMaxBodyBytes = 4096
	// sarifMaxMessageBytes caps the description folded into the result message.
	sarifMaxMessageBytes = 8192
	// sarifMaxEvidenceBytes caps each free-text evidence string in a result's
	// properties. Uncapped, these defeat the body cap entirely — the HTML report
	// already learned this (trimReportFindingJSON caps additional_evidence
	// alongside the bodies), because finding evidence, not record bodies, was
	// what blew up report size.
	sarifMaxEvidenceBytes = 4096
	// sarifMaxHeadBytes bounds the prefix handed to the header lexer.
	sarifMaxHeadBytes = 64 << 10
	// sarifTextProbeBytes is how much of a body isReadableText samples.
	sarifTextProbeBytes = 2048
	// sarifBinaryPercent is the share of unreadable characters at which a body is
	// treated as binary rather than text.
	sarifBinaryPercent = 10
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool               `json:"tool"`
	AutomationDetails *sarifAutomationDetails `json:"automationDetails,omitempty"`
	Invocations       []sarifInvocation       `json:"invocations,omitempty"`
	Results           []sarifResult           `json:"results"`
	Properties        map[string]any          `json:"properties,omitempty"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

// sarifMessage doubles as SARIF's `message` and `multiformatMessageString`:
// both are {text, markdown?}, and text is required on both.
type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     *sarifMessage    `json:"shortDescription,omitempty"`
	FullDescription      *sarifMessage    `json:"fullDescription,omitempty"`
	Help                 *sarifMessage    `json:"help,omitempty"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Rank                *float64          `json:"rank,omitempty"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	RelatedLocations    []sarifLocation   `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	WebRequest          *sarifWebRequest  `json:"webRequest,omitempty"`
	WebResponse         *sarifWebResponse `json:"webResponse,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	ID               int                    `json:"id,omitempty"`
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *sarifMessage          `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifArtifactContent struct {
	Text string `json:"text,omitempty"`
}

type sarifWebRequest struct {
	Protocol string                `json:"protocol,omitempty"`
	Version  string                `json:"version,omitempty"`
	Target   string                `json:"target,omitempty"`
	Method   string                `json:"method,omitempty"`
	Headers  map[string]string     `json:"headers,omitempty"`
	Body     *sarifArtifactContent `json:"body,omitempty"`
}

type sarifWebResponse struct {
	Protocol     string                `json:"protocol,omitempty"`
	Version      string                `json:"version,omitempty"`
	StatusCode   int                   `json:"statusCode,omitempty"`
	ReasonPhrase string                `json:"reasonPhrase,omitempty"`
	Headers      map[string]string     `json:"headers,omitempty"`
	Body         *sarifArtifactContent `json:"body,omitempty"`
}

// GenerateSARIFReport writes the run's findings as a SARIF 2.1.0 log. It shares
// the signature of every other report generator (GenerateHTMLReport,
// GenerateMarkdownReport, …) so it drops into reportGenerator and the scan
// commands' reportFormats table unchanged.
func GenerateSARIFReport(items []any, outputPath string, meta HTMLReportMeta) error {
	log := buildSARIFLog(items, meta)

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	// SARIF carries URLs and raw HTML/JS evidence throughout; Go's default
	// HTML-escaping would rewrite &, < and > inside every one of them, which
	// survives a round-trip but makes the file unreadable and mangles any
	// consumer that string-matches the payload it is shown.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("failed to encode SARIF: %w", err)
	}
	return nil
}

// buildSARIFLog converts the export envelope stream into a SARIF log.
// Unexported along with the types it returns: an out-of-package caller could
// not name the value anyway.
func buildSARIFLog(items []any, meta HTMLReportMeta) sarifLog {
	data := buildReportData(items, meta.Title, meta)

	b := &sarifBuilder{
		// Non-nil so the run serializes as `[]` on a clean scan: an absent array
		// reads to a consumer as a malformed run, not as zero findings.
		rules:      []sarifRule{},
		results:    make([]sarifResult, 0, data.TotalFindings),
		ruleIndex:  make(map[string]int, len(data.Modules)),
		moduleDesc: make(map[string]string, len(data.Modules)),
	}
	for _, m := range data.Modules {
		b.moduleDesc[m.ID] = firstNonEmpty(m.Description, m.ShortDescription)
	}

	// Severity order matters here: results land in the file most-severe first,
	// which is the order a reader scanning the raw JSON wants and the order
	// viewers that do not sort themselves will display.
	for _, group := range [][]ReportFinding{
		data.CriticalFindings, data.HighFindings, data.MediumFindings,
		data.LowFindings, data.InfoFindings,
	} {
		for i := range group {
			b.addFinding(&group[i])
		}
	}

	props := map[string]any{}
	if meta.ScanTarget != "" {
		props["target"] = meta.ScanTarget
	}
	if meta.ScanDuration != "" {
		props["scanDuration"] = meta.ScanDuration
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           sarifToolName,
			Version:        meta.Version,
			InformationURI: sarifInformationURI,
			Rules:          b.rules,
		}},
		Invocations: []sarifInvocation{{
			ExecutionSuccessful: true,
			EndTimeUTC:          sarifTimestamp(meta.GeneratedAt),
		}},
		// Results is non-omitempty on purpose: SARIF requires the property.
		Results: b.results,
	}
	if meta.ScanTarget != "" {
		run.AutomationDetails = &sarifAutomationDetails{ID: meta.ScanTarget}
	}
	if len(props) > 0 {
		run.Properties = props
	}

	return sarifLog{Schema: sarifSchemaURI, Version: sarifVersion, Runs: []sarifRun{run}}
}

// sarifBuilder accumulates results and the deduplicated rule table they index
// into. Rules are discovered from findings rather than from the module registry
// because the module envelopes are excluded from `vigolium export` by default —
// a SARIF file must describe its own rules whether or not they were exported.
type sarifBuilder struct {
	rules     []sarifRule
	ruleIndex map[string]int
	// ruleRank is parallel to rules and holds the highest severity rank seen for
	// each. Kept alongside rather than recovered from the emitted
	// DefaultConfiguration.Level, which is a lossy projection — critical and high
	// share one level, so decoding it back would make every later critical
	// finding compare as an upgrade and overwrite the rule's first CVSS.
	ruleRank []severity.Severity
	results  []sarifResult
	// moduleDesc holds the resolved rule description per module ID — the only
	// thing the module list is consulted for.
	moduleDesc map[string]string
}

func (b *sarifBuilder) addFinding(f *ReportFinding) {
	idx := b.ruleFor(f)
	primary, related := sarifAnchors(f)

	res := sarifResult{
		RuleID:           b.rules[idx].ID,
		RuleIndex:        idx,
		Level:            sarifLevel(f.Severity),
		Message:          sarifResultMessage(f),
		Locations:        primary,
		RelatedLocations: related,
	}
	if f.FindingHash != "" {
		// Versioned key: a change to how the hash is computed must not silently
		// re-key existing alerts, it must present as a new fingerprint scheme.
		// v2: finding identity v2 (schema v6) — insertion-point findings hash
		// their location, not their prose (output.ResultEvent.IdentityKey).
		res.PartialFingerprints = map[string]string{"vigoliumFindingHash/v2": f.FindingHash}
	}
	if f.CVSSScore > 0 {
		// SARIF rank is 0-100; CVSS is 0-10.
		rank := f.CVSSScore * 10
		res.Rank = &rank
	}
	res.WebRequest = parseSARIFWebRequest(f.Request)
	res.WebResponse = parseSARIFWebResponse(f.Response)
	res.Properties = sarifResultProperties(f)

	b.results = append(b.results, res)
}

// ruleFor returns the index of the rule for this finding's module, creating the
// immutable shell on first sight. Every finding — including the one that
// created the rule — then goes through mergeRule, so the per-finding property
// writes exist once rather than once per branch.
func (b *sarifBuilder) ruleFor(f *ReportFinding) int {
	id := f.ModuleID
	if id == "" {
		id = "vigolium-finding"
	}
	idx, ok := b.ruleIndex[id]
	if !ok {
		// Name is the compact rule label viewers show next to the id, so it takes
		// the module's own name rather than ReportFinding.ModuleName — the latter
		// is the *display* name, which prefers the short description and reads as
		// a full sentence.
		rule := sarifRule{
			ID:         id,
			Name:       firstNonEmpty(f.ModuleTitle, f.ModuleName, id),
			Properties: map[string]any{"tags": dedupeStrings(append([]string{"security"}, f.Tags...))},
		}
		if f.ModuleName != "" {
			rule.ShortDescription = &sarifMessage{Text: f.ModuleName}
		}
		if desc := b.moduleDesc[id]; desc != "" {
			rule.FullDescription = &sarifMessage{Text: collapseToText(desc)}
		}
		b.rules = append(b.rules, rule)
		// Undefined-1 seeds the rank below every real severity — including
		// Undefined itself — so the first finding always sets the band.
		b.ruleRank = append(b.ruleRank, severity.Undefined-1)
		idx = len(b.rules) - 1
		b.ruleIndex[id] = idx
	}
	b.mergeRule(idx, f)
	return idx
}

// mergeRule folds one finding into its rule: information a later finding
// carries but earlier ones did not (a remediation, a CWE), plus the widening to
// the most severe band seen. A module whose findings differ in severity keeps
// the most severe as its default configuration — each result still carries its
// own level, which is what a consumer reports on.
func (b *sarifBuilder) mergeRule(idx int, f *ReportFinding) {
	rule := &b.rules[idx]
	if rule.Help == nil && f.Remediation != "" {
		rule.Help = &sarifMessage{Text: collapseToText(f.Remediation), Markdown: f.Remediation}
	}
	if cwes := sarifCWETags(f.CWE); len(cwes) > 0 {
		existing, _ := rule.Properties["tags"].([]string)
		rule.Properties["tags"] = dedupeStrings(append(existing, cwes...))
	}
	// Strictly-greater, so an equal-severity later finding does not overwrite the
	// band (and with it the first finding's explicit CVSS) with its own.
	rank, band := sarifBandFor(f.Severity)
	if rank <= b.ruleRank[idx] {
		return
	}
	b.ruleRank[idx] = rank
	rule.DefaultConfiguration = &sarifRuleConfig{Level: band.level}
	rule.Properties["problem.severity"] = band.problem
	// GitHub code scanning reads security-severity off the RULE (not the result)
	// to bucket an alert as critical/high/medium/low; without it every alert
	// lands in the same bucket regardless of level.
	if ss := sarifSecuritySeverity(f.Severity, f.CVSSScore); ss != "" {
		rule.Properties["security-severity"] = ss
	}
}

// sarifResultMessage builds the alert body: the finding title, then its
// description. The description is markdown in the database, so it is offered
// verbatim as `markdown` and flattened for the required plain `text`.
func sarifResultMessage(f *ReportFinding) sarifMessage {
	title := f.Title
	if title == "" {
		title = firstNonEmpty(f.ModuleName, f.ModuleID, "Finding")
	}
	msg := sarifMessage{Text: title}
	if f.Description != "" {
		desc := truncateStr(f.Description, sarifMaxMessageBytes)
		msg.Text = title + "\n\n" + collapseToText(desc)
		msg.Markdown = "**" + title + "**\n\n" + desc
	}
	return msg
}

// sarifAnchors resolves all of a finding's locations in ONE walk: the primary
// anchor and the secondary ones, sharing a single seen-set.
//
// Deriving them separately is what makes them drift — the primary and related
// sets then each re-implement the precedence rule, and a finding whose only
// anchor is an evidence URL gets that URL emitted twice, once as its location
// and again as a related location.
//
// Precedence: source file, then URL, then the first URI-shaped evidence string.
// Source file wins because only a file-anchored result can be annotated onto a
// diff; a code finding's URL is secondary context and lands in related.
func sarifAnchors(f *ReportFinding) (primary, related []sarifLocation) {
	seen := make(map[string]bool, len(f.MatchedAt)+1)
	add := func(raw, label string) {
		loc, ok := sarifURILocation(raw)
		if !ok || seen[raw] {
			return
		}
		seen[raw] = true
		if primary == nil {
			primary = []sarifLocation{loc}
			return
		}
		loc.Message = &sarifMessage{Text: label}
		loc.ID = len(related) + 1
		related = append(related, loc)
	}

	if loc, ok := sarifSourceLocation(f.SourceFile, f.RepoName); ok {
		primary = []sarifLocation{loc}
	}
	add(f.URL, "Request URL")
	for _, m := range f.MatchedAt {
		add(m, "Matched at")
	}
	return primary, related
}

// sarifSourceLocation turns a "path" or "path:line[:col]" source reference into
// a physical location, splitting the trailing line/column off the path.
func sarifSourceLocation(sourceFile, repoName string) (sarifLocation, bool) {
	sourceFile = strings.TrimSpace(sourceFile)
	if sourceFile == "" {
		return sarifLocation{}, false
	}
	file, line, col := splitSourceRef(sourceFile)
	if file == "" {
		return sarifLocation{}, false
	}
	loc := sarifLocation{PhysicalLocation: &sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: sarifSourceURI(file, repoName)},
	}}
	if line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: line, StartColumn: col}
	}
	return loc, true
}

// splitSourceRef peels a trailing ":line" or ":line:col" off a source path.
// A Windows drive letter ("C:\src\a.cs") is not a line number, so only a
// trailing all-digit segment counts, and only when what precedes it is not
// empty.
func splitSourceRef(ref string) (file string, line, col int) {
	file = ref
	for range 2 {
		idx := strings.LastIndexByte(file, ':')
		if idx <= 0 || idx == len(file)-1 {
			break
		}
		n, err := strconv.Atoi(file[idx+1:])
		if err != nil || n <= 0 {
			break
		}
		// Walking right to left, the first number found is the column when a
		// second one follows it.
		col = line
		line = n
		file = file[:idx]
	}
	return file, line, col
}

// sarifSourceURI normalizes a source path into a SARIF artifact URI. A relative
// path is used as-is, which is what GitHub code scanning needs to annotate a
// file. An absolute path is made repo-relative when repoName names a directory
// in it — audit findings record absolute paths like
// "/opt/repos/shop-api/app/routes/auth.py", and the "/shop-api/" segment is the
// only reliable marker of where the checkout root was. Without a match the
// absolute path is kept verbatim rather than guessed at: a wrong prefix strip
// silently points the annotation at the wrong file.
func sarifSourceURI(file, repoName string) string {
	uri := filepathToSlash(file)
	if !strings.HasPrefix(uri, "/") && !hasWindowsDrive(uri) {
		return path.Clean(uri)
	}
	if name := repoDirName(repoName); name != "" {
		if idx := strings.Index(uri, "/"+name+"/"); idx >= 0 {
			return path.Clean(uri[idx+len(name)+2:])
		}
	}
	return uri
}

// repoDirName reduces a repo reference ("shop-api", "git@host:org/shop-api.git",
// "https://host/org/shop-api") to the directory name a checkout would use.
func repoDirName(repoName string) string {
	name := strings.TrimSpace(repoName)
	if name == "" {
		return ""
	}
	name = strings.TrimSuffix(name, "/")
	name = strings.TrimSuffix(name, ".git")
	if idx := strings.LastIndexAny(name, "/:"); idx >= 0 {
		name = name[idx+1:]
	}
	if name == "" || strings.ContainsAny(name, " \t") {
		return ""
	}
	return name
}

func filepathToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func hasWindowsDrive(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

// sarifURILocation wraps a URL (or any URI-shaped evidence string) as a
// physical location. Rejects values that are not URI-shaped — a bare parameter
// name is evidence, not a location, and emitting it as an artifact URI produces
// a viewer entry pointing at a file that cannot exist.
func sarifURILocation(raw string) (sarifLocation, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return sarifLocation{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return sarifLocation{}, false
	}
	return sarifLocation{PhysicalLocation: &sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: raw},
	}}, true
}

// sarifResultProperties carries every field SARIF has no first-class home for.
// A consumer that only reads the standard fields loses nothing it understands;
// one that reads properties (DefectDojo, custom triage) gets the full finding.
func sarifResultProperties(f *ReportFinding) map[string]any {
	props := make(map[string]any, 14)
	if f.Severity != "" {
		// Already lowercased by parseFinding.
		props["severity"] = f.Severity
	}
	if f.Confidence != "" {
		props["confidence"] = f.Confidence
	}
	if ss := sarifSecuritySeverity(f.Severity, f.CVSSScore); ss != "" {
		props["security-severity"] = ss
	}
	if f.CVSSScore > 0 {
		props["cvssScore"] = f.CVSSScore
	}
	if f.CWE != "" {
		props["cwe"] = f.CWE
	}
	if f.URL != "" {
		props["url"] = f.URL
	}
	if f.ModuleID != "" {
		props["moduleId"] = f.ModuleID
	}
	if f.RepoName != "" {
		props["repository"] = f.RepoName
	}
	if f.FoundAt != "" {
		props["foundAt"] = f.FoundAt
	}
	if f.Remediation != "" {
		props["remediation"] = truncateStr(f.Remediation, sarifMaxEvidenceBytes)
	}
	if len(f.MatchedAt) > 0 {
		props["matchedAt"] = truncateStrings(f.MatchedAt)
	}
	if len(f.ExtractedResults) > 0 {
		props["extractedResults"] = truncateStrings(f.ExtractedResults)
	}
	if len(f.AdditionalEvidence) > 0 {
		props["additionalEvidence"] = truncateStrings(f.AdditionalEvidence)
	}
	if len(f.Tags) > 0 {
		props["tags"] = f.Tags
	}
	if len(f.Request) > sarifMaxBodyBytes || len(f.Response) > sarifMaxBodyBytes {
		props["evidenceTruncated"] = true
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

// parseHTTPDump splits a raw HTTP message into its start line, headers and
// body. The split itself is delegated to httpmsg, the repo's canonical lexer
// and the only one that handles CRLF, bare LF and mixed line endings in one
// pass — a local re-derivation would be the fourth copy of that logic.
//
// Only a bounded prefix is handed to the lexer: headers live at the front of a
// message, so this avoids copying a multi-megabyte body into a []byte purely to
// find where it starts. It also severs retention — the lexer's lines are fresh
// strings, so the returned header values do not pin the whole raw message.
//
// ok is false when there is nothing parseable.
func parseHTTPDump(raw string) (startLine string, headers map[string]string, body string, ok bool) {
	if strings.TrimSpace(raw) == "" {
		return "", nil, "", false
	}
	probe := raw
	if len(probe) > sarifMaxHeadBytes {
		probe = probe[:sarifMaxHeadBytes]
	}
	lines, _, bodyStart, err := httpmsg.ExtractAllHeaders([]byte(probe))
	if err != nil || len(lines) == 0 {
		return "", nil, "", false
	}
	return lines[0], parseHeaderLines(lines), raw[bodyStart:], true
}

// parseSARIFWebRequest turns a raw HTTP request dump into SARIF's webRequest.
// Best-effort by design: a malformed record still yields whatever parsed,
// because dropping the exchange entirely loses more than a partial one costs.
func parseSARIFWebRequest(raw string) *sarifWebRequest {
	startLine, headers, body, ok := parseHTTPDump(raw)
	if !ok {
		return nil
	}
	req := &sarifWebRequest{Protocol: "http", Headers: headers, Body: sarifBody(body)}
	// Request line: METHOD SP target SP HTTP/version
	if parts := strings.Fields(startLine); len(parts) >= 2 {
		req.Method, req.Target = parts[0], parts[1]
		if len(parts) >= 3 {
			req.Protocol, req.Version = splitHTTPToken(parts[2])
		}
	}
	return req
}

// parseSARIFWebResponse turns a raw HTTP response dump into SARIF's webResponse.
func parseSARIFWebResponse(raw string) *sarifWebResponse {
	startLine, headers, body, ok := parseHTTPDump(raw)
	if !ok {
		return nil
	}
	resp := &sarifWebResponse{Protocol: "http", Headers: headers, Body: sarifBody(body)}
	// Status line: HTTP/version SP code [SP reason]
	if parts := strings.SplitN(startLine, " ", 3); len(parts) >= 2 {
		resp.Protocol, resp.Version = splitHTTPToken(parts[0])
		if code, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
			resp.StatusCode = code
		}
		if len(parts) == 3 {
			resp.ReasonPhrase = strings.TrimSpace(parts[2])
		}
	}
	return resp
}

// sarifBody prepares a message body for embedding, dropping one that is not
// readable text. The scanner sends its own Accept-Encoding, so the transport
// leaves gzip responses compressed and findings persist them that way; a binary
// or still-compressed body carries nothing a consumer can read while costing
// several bytes per character to encode, against a format whose whole reason
// for capping bodies is an upload limit.
//
// The test is replacement-character density, NOT utf8.ValidString, and the body
// is not gunzipped here — both because findings reach this renderer through
// buildReportData's json.Marshal round-trip, which has already rewritten every
// invalid byte as U+FFFD. By the time a body arrives it is therefore *valid*
// UTF-8 and mostly U+FFFD, and the gzip magic bytes that would identify it are
// gone. Anything that wants the real bytes has to read them upstream of that
// round-trip.
func sarifBody(body string) *sarifArtifactContent {
	if body == "" || !isReadableText(body) {
		return nil
	}
	return &sarifArtifactContent{Text: truncateStr(body, sarifMaxBodyBytes)}
}

// isReadableText reports whether s is mostly intelligible text. Only a prefix is
// sampled: a body's character is settled in its first bytes, and scanning all of
// a multi-megabyte response to learn it is binary is work the answer does not
// need.
func isReadableText(s string) bool {
	if len(s) > sarifTextProbeBytes {
		s = s[:sarifTextProbeBytes]
	}
	var total, unreadable int
	for _, r := range s {
		total++
		if r == utf8.RuneError || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') {
			unreadable++
		}
	}
	return total == 0 || unreadable*100/total < sarifBinaryPercent
}

// parseHeaderLines folds header lines into SARIF's name→value map. Repeated
// headers (Set-Cookie) are joined with ", " because the schema types headers as
// a string map; joining preserves every value, where last-wins would silently
// drop all but one.
//
// lines is the full ExtractAllHeaders slice including the start line, which
// httpmsg.ParseHeadersFromStrings skips itself — splitting is left to the
// canonical parser rather than re-derived here.
//
// Values accumulate into a slice and are joined once at the end: rebuilding the
// joined string per repeat is O(n²) in the number of same-named headers, and the
// input is target-controlled up to the sarifMaxHeadBytes probe.
func parseHeaderLines(lines []string) map[string]string {
	parsed := httpmsg.ParseHeadersFromStrings(lines)
	if len(parsed) == 0 {
		return nil
	}
	order := make([]string, 0, len(parsed))
	values := make(map[string][]string, len(parsed))
	for _, h := range parsed {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		if _, seen := values[name]; !seen {
			order = append(order, name)
		}
		values[name] = append(values[name], strings.TrimSpace(h.Value))
	}
	if len(order) == 0 {
		return nil
	}
	headers := make(map[string]string, len(order))
	for _, name := range order {
		headers[name] = strings.Join(values[name], ", ")
	}
	return headers
}

// splitHTTPToken splits "HTTP/1.1" into SARIF's separate protocol and version
// fields. One function because the two are always needed together, off the same
// token.
func splitHTTPToken(token string) (protocol, version string) {
	idx := strings.IndexByte(token, '/')
	if idx <= 0 {
		return "http", ""
	}
	return strings.ToLower(token[:idx]), token[idx+1:]
}

// sarifSeverityBand is the SARIF projection of one Vigolium severity: the
// `level` a result reports at, the `problem.severity` CodeQL-style consumers
// read from rule properties, and the numeric `security-severity` GitHub buckets
// alerts by.
//
// One table rather than a switch per projection: they are always resolved
// together, and a severity added to pkg/types/severity then has exactly one
// place to land instead of three that can each be forgotten independently.
type sarifSeverityBand struct {
	level    string
	problem  string
	security string
}

// sarifSeverityBands is keyed by the ordered severity enum, so the single
// lookup that yields the projections also yields the rank — the enum's
// declaration order IS the ordering, which is why this does not re-type the
// ladder locally.
//
// SARIF has no "critical", so critical and high share `error`; the distinction
// survives in security-severity. Info and Suspect deliberately carry no
// security-severity: a 0.0 reads to a consumer as "no security impact rating"
// and buckets unpredictably, so the property is omitted instead.
var sarifSeverityBands = map[severity.Severity]sarifSeverityBand{
	severity.Critical: {level: "error", problem: "error", security: "9.5"},
	severity.High:     {level: "error", problem: "error", security: "7.5"},
	severity.Medium:   {level: "warning", problem: "warning", security: "5.5"},
	severity.Low:      {level: "note", problem: "recommendation", security: "3.0"},
	severity.Suspect:  {level: "note", problem: "recommendation"},
	severity.Info:     {level: "note", problem: "recommendation"},
}

// sarifUnknownBand is what an unrecognized severity reports as. "note" rather
// than "none" for the same reason info is: "none" means the rule did not fire,
// and consumers filter those out entirely, which would erase the finding from
// the export.
var sarifUnknownBand = sarifSeverityBand{level: "note", problem: "recommendation"}

// sarifBandFor resolves a severity name to its rank and SARIF projection.
func sarifBandFor(name string) (severity.Severity, sarifSeverityBand) {
	rank := severity.ToSeverity(name)
	if band, ok := sarifSeverityBands[rank]; ok {
		return rank, band
	}
	return rank, sarifUnknownBand
}

// sarifLevel maps a Vigolium severity onto SARIF's level vocabulary.
func sarifLevel(name string) string {
	_, band := sarifBandFor(name)
	return band.level
}

// sarifSecuritySeverity renders the numeric CVSS-scale string GitHub uses to
// bucket alerts (>=9.0 critical, >=7.0 high, >=4.0 medium, >0 low). The
// finding's own CVSS wins when it has one; otherwise the severity band's
// representative value is used.
func sarifSecuritySeverity(name string, cvss float64) string {
	if cvss > 0 {
		return strconv.FormatFloat(cvss, 'f', 1, 64)
	}
	_, band := sarifBandFor(name)
	return band.security
}

// sarifCWETags renders a CWE reference as the "external/cwe/cwe-079" tags
// GitHub links to MITRE. The stored field is free-form and may list several
// ("CWE-79, CWE-80"), so every number in it is emitted. Zero-padding to three
// digits is GitHub's convention, not decoration — an unpadded tag does not
// resolve.
func sarifCWETags(cwe string) []string {
	if strings.TrimSpace(cwe) == "" {
		return nil
	}
	var tags []string
	for _, token := range strings.FieldsFunc(cwe, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '|'
	}) {
		digits := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(token)), "cwe-")
		digits = strings.TrimPrefix(digits, "cwe")
		digits = strings.TrimLeft(digits, "-_:")
		n, err := strconv.Atoi(digits)
		if err != nil || n <= 0 {
			continue
		}
		tags = append(tags, fmt.Sprintf("external/cwe/cwe-%03d", n))
	}
	return tags
}

// collapseToText flattens markdown into the plain string SARIF requires for
// `text`. It strips fenced code blocks' fences and heading markers rather than
// rendering, because the goal is a readable single string, not HTML.
func collapseToText(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			continue
		}
		trimmed = strings.TrimLeft(trimmed, "#")
		out = append(out, strings.TrimSpace(trimmed))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// truncateStrings caps each entry of an evidence list at sarifMaxEvidenceBytes.
// Evidence lists are the other half of the size problem the body cap addresses:
// a single extracted secret or response diff can dwarf the bodies it sits next
// to, and nothing else bounds them.
func truncateStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = truncateStr(s, sarifMaxEvidenceBytes)
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// sarifTimestamp renders the invocation end time. SARIF requires RFC3339 with a
// Z offset, so the report's display-formatted GeneratedAt ("2006-01-02 15:04
// UTC") cannot be passed through — only an already-RFC3339 value (what
// `--report-generated-at` takes) is reused, and anything else falls back to now.
func sarifTimestamp(generatedAt string) string {
	if generatedAt != "" {
		if t, err := time.Parse(time.RFC3339, generatedAt); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}
