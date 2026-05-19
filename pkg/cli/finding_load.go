package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	findingLoadFile string
	findingLoadScan string
)

var findingLoadCmd = &cobra.Command{
	Use:   "load [file]",
	Short: "Import findings from a file or stdin",
	Long: `Import findings from JSON, JSONL, or markdown-wrapped agent output.

Supports multiple formats with auto-detection:
  - Agent findings: {"findings": [...]} or markdown-wrapped variants
  - Single finding:  {"title": "...", "severity": "..."}
  - ResultEvent JSONL: one Nuclei-compatible JSON per line
  - Database findings: direct Finding JSON objects

Input sources (in priority order):
  1. Positional argument:  vigolium finding load findings.json
  2. --finding-file flag:  vigolium finding load --finding-file findings.json
  3. Stdin pipe:           cat findings.json | vigolium finding load`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFindingLoad,
}

func init() {
	f := findingLoadCmd.Flags()
	f.StringVar(&findingLoadFile, "finding-file", "", "Path to findings file")
	f.StringVar(&findingLoadScan, "scan-uuid", "", "Associate imported findings with a scan UUID")
}

func runFindingLoad(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	raw, err := readFindingInput(args)
	if err != nil {
		return err
	}

	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty input: provide a file path, --finding-file, or pipe data via stdin")
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	findings, formatName, err := detectAndParse(raw, findingLoadScan, projectUUID)
	if err != nil {
		return fmt.Errorf("failed to parse findings: %w", err)
	}

	if len(findings) == 0 {
		fmt.Printf("%s No findings found in input\n", terminal.WarningSymbol())
		return nil
	}

	ctx := context.Background()
	repo := database.NewRepository(db)
	saved, skipped := 0, 0
	for _, f := range findings {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			// Check if the error indicates a constraint violation (unlikely with ON CONFLICT DO NOTHING)
			skipped++
			continue
		}
		if f.ID == 0 {
			// ON CONFLICT DO NOTHING: no row inserted, ID not assigned
			skipped++
		} else {
			saved++
		}
	}

	if globalJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"format":  formatName,
			"total":   len(findings),
			"saved":   saved,
			"skipped": skipped,
		})
	}

	fmt.Printf("%s Loaded %d findings from %s format (%d new, %d duplicates skipped)\n",
		terminal.SuccessSymbol(), len(findings), formatName, saved, skipped)
	return nil
}

// readFindingInput reads finding data from positional arg, --finding-file, or stdin.
func readFindingInput(args []string) (string, error) {
	// Priority 1: positional argument
	if len(args) == 1 {
		return readFileContent(args[0])
	}

	// Priority 2: --finding-file flag
	if findingLoadFile != "" {
		return readFileContent(findingLoadFile)
	}

	// Priority 3: stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input provided; use a file path, --finding-file, or pipe data via stdin")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read stdin: %w", err)
	}
	return string(data), nil
}

func readFileContent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return string(data), nil
}

// detectAndParse tries multiple format parsers and returns the first successful result.
func detectAndParse(raw string, scanUUID string, projectUUID string) ([]*database.Finding, string, error) {
	// 1. Try agent findings format (handles markdown fences, {"findings":[...]}, bare arrays)
	if findings, err := tryParseAgentFindings(raw, scanUUID, projectUUID); err == nil && len(findings) > 0 {
		return findings, "agent-findings", nil
	}

	// 2. Try single AgentFinding
	if finding, err := tryParseSingleAgentFinding(raw, scanUUID, projectUUID); err == nil {
		return []*database.Finding{finding}, "agent-finding", nil
	}

	// 3. Try ResultEvent JSONL (multiple lines)
	if findings, err := tryParseResultEventJSONL(raw, scanUUID, projectUUID); err == nil && len(findings) > 0 {
		return findings, "jsonl", nil
	}

	// 4. Try single ResultEvent
	if finding, err := tryParseSingleResultEvent(raw, scanUUID, projectUUID); err == nil {
		return []*database.Finding{finding}, "result-event", nil
	}

	// 5. Try database Finding JSON (array or single)
	if findings, err := tryParseDBFindings(raw, projectUUID); err == nil && len(findings) > 0 {
		return findings, "db-finding", nil
	}

	return nil, "", fmt.Errorf("could not detect input format; expected agent findings, ResultEvent JSONL, or database Finding JSON")
}

// tryParseAgentFindings uses the agent parser which handles markdown fences and {"findings":[...]} wrappers.
func tryParseAgentFindings(raw string, scanUUID string, projectUUID string) ([]*database.Finding, error) {
	agentFindings, err := agent.ParseFindings(raw)
	if err != nil || len(agentFindings) == 0 {
		return nil, fmt.Errorf("not agent findings format")
	}

	findings := make([]*database.Finding, 0, len(agentFindings))
	for _, af := range agentFindings {
		f := agent.ToDBFinding(af, "import", scanUUID, projectUUID)
		f.FindingSource = "import"
		findings = append(findings, f)
	}
	return findings, nil
}

// tryParseSingleAgentFinding tries to parse the input as a single AgentFinding object.
func tryParseSingleAgentFinding(raw string, scanUUID string, projectUUID string) (*database.Finding, error) {
	raw = strings.TrimSpace(raw)

	var af agent.AgentFinding
	if err := json.Unmarshal([]byte(raw), &af); err != nil {
		return nil, err
	}
	if af.Title == "" {
		return nil, fmt.Errorf("not a valid AgentFinding: missing title")
	}

	f := agent.ToDBFinding(af, "import", scanUUID, projectUUID)
	f.FindingSource = "import"
	return f, nil
}

// tryParseResultEventJSONL tries to parse the input as newline-delimited ResultEvent JSON.
func tryParseResultEventJSONL(raw string, scanUUID string, projectUUID string) ([]*database.Finding, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("empty input")
	}

	var findings []*database.Finding
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var event output.ResultEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("not JSONL format: %w", err)
		}
		// Detect ResultEvent by its distinctive field
		if event.ModuleID == "" {
			return nil, fmt.Errorf("not a ResultEvent: missing template-id")
		}

		f := &database.Finding{
			ScanUUID:    scanUUID,
			ProjectUUID: projectUUID,
		}
		if err := f.FromResultEvent(&event); err != nil {
			return nil, err
		}
		if f.FindingSource == "" {
			f.FindingSource = "import"
		}
		f.Status = database.StatusDraft
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("no valid ResultEvents found")
	}
	return findings, nil
}

// tryParseSingleResultEvent tries to parse the input as a single ResultEvent object.
func tryParseSingleResultEvent(raw string, scanUUID string, projectUUID string) (*database.Finding, error) {
	raw = strings.TrimSpace(raw)

	var event output.ResultEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return nil, err
	}
	if event.ModuleID == "" {
		return nil, fmt.Errorf("not a ResultEvent: missing template-id")
	}

	f := &database.Finding{
		ScanUUID:    scanUUID,
		ProjectUUID: projectUUID,
	}
	if err := f.FromResultEvent(&event); err != nil {
		return nil, err
	}
	if f.FindingSource == "" {
		f.FindingSource = "import"
	}
	f.Status = database.StatusDraft
	return f, nil
}

// tryParseDBFindings tries to parse the input as database Finding JSON (single or array).
func tryParseDBFindings(raw string, projectUUID string) ([]*database.Finding, error) {
	raw = strings.TrimSpace(raw)

	// Try as array first
	var arr []*database.Finding
	if err := json.Unmarshal([]byte(raw), &arr); err == nil && len(arr) > 0 {
		for _, f := range arr {
			if f.ProjectUUID == "" {
				f.ProjectUUID = projectUUID
			}
		}
		return arr, nil
	}

	// Try as single object
	var f database.Finding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return nil, err
	}
	// Validate it looks like a DB finding (has module_id or finding_hash)
	if f.ModuleID == "" && f.FindingHash == "" {
		return nil, fmt.Errorf("not a valid database Finding")
	}
	if f.ProjectUUID == "" {
		f.ProjectUUID = projectUUID
	}
	return []*database.Finding{&f}, nil
}
