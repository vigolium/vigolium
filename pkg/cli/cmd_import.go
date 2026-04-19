package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var importCmd = &cobra.Command{
	Use:   "import <path>",
	Short: "Import scan data from archon output folder or JSONL file",
	Long: `Import scan data into the database from various sources.

Supported inputs:
  - Archon output folder: contains audit-state.json and findings-draft/
  - JSONL file: exported data with {"type": "...", "data": {...}} envelopes
    Supports http_record and finding types (e.g. from 'vigolium export --format jsonl')

Examples:
  vigolium import /path/to/archon-output-harbor/
  vigolium import /tmp/demo/juice-shop.jsonl
  vigolium import scan-results.jsonl`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	inputPath := args[0]

	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}

	if info.IsDir() {
		return runImportArchon(inputPath)
	}

	return runImportJSONL(inputPath)
}

func runImportArchon(folderPath string) error {
	result, err := archon.ParseAuditFolder(folderPath)
	if err != nil {
		return fmt.Errorf("failed to parse archon output: %w", err)
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	repo := database.NewRepository(db)

	agentRun := archon.BuildAgentRun(result.State, folderPath, projectUUID)
	if err := repo.CreateAgentRun(ctx, agentRun); err != nil {
		return fmt.Errorf("failed to create agent run: %w", err)
	}

	auditID := result.State.Audits[0].AuditID
	findings := archon.BuildFindings(result.RawFindings, auditID, agentRun.UUID, projectUUID, result.RepoName)

	saved, skipped := 0, 0
	for _, f := range findings {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			skipped++
			continue
		}
		if f.ID == 0 {
			skipped++
		} else {
			saved++
		}
	}

	agentRun.SavedCount = saved
	agentRun.FindingCount = len(findings)
	_ = repo.UpdateAgentRun(ctx, agentRun)

	sevCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[f.Severity]++
	}

	if globalJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"agent_run_uuid": agentRun.UUID,
			"total":          len(findings),
			"saved":          saved,
			"skipped":        skipped,
			"severity":       sevCounts,
		})
	}

	fmt.Printf("%s Imported archon audit: %d findings (%d new, %d duplicates skipped)\n",
		terminal.SuccessSymbol(), len(findings), saved, skipped)
	fmt.Printf("  Agent run: %s (mode=%s, status=%s)\n", agentRun.UUID, agentRun.Mode, agentRun.Status)
	if sevCounts["high"] > 0 || sevCounts["critical"] > 0 || sevCounts["medium"] > 0 || sevCounts["low"] > 0 {
		fmt.Printf("  Severity: %s, %s, %s, %s\n",
			terminal.BoldMagenta(fmt.Sprintf("%d critical", sevCounts["critical"])),
			terminal.BoldRed(fmt.Sprintf("%d high", sevCounts["high"])),
			terminal.BoldYellow(fmt.Sprintf("%d medium", sevCounts["medium"])),
			terminal.BoldGreen(fmt.Sprintf("%d low", sevCounts["low"])),
		)
	}
	return nil
}

func runImportJSONL(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	repo := database.NewRepository(db)

	var (
		records       []*database.HTTPRecord
		findings      []*database.Finding
		lineNum       int
		parseErrors   int
		skippedTypes  = map[string]int{}
	)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			parseErrors++
			continue
		}

		switch envelope.Type {
		case "http_record":
			var rec database.HTTPRecord
			if err := json.Unmarshal(envelope.Data, &rec); err != nil {
				parseErrors++
				continue
			}
			rec.ProjectUUID = projectUUID
			if rec.UUID == "" {
				rec.UUID = uuid.New().String()
			}
			if rec.SentAt.IsZero() {
				rec.SentAt = time.Now()
			}
			if rec.CreatedAt.IsZero() {
				rec.CreatedAt = time.Now()
			}
			records = append(records, &rec)

		case "finding":
			var finding database.Finding
			if err := json.Unmarshal(envelope.Data, &finding); err != nil {
				parseErrors++
				continue
			}
			finding.ProjectUUID = projectUUID
			if finding.FindingSource == "" {
				finding.FindingSource = "import"
			}
			if finding.FoundAt.IsZero() {
				finding.FoundAt = time.Now()
			}
			if finding.CreatedAt.IsZero() {
				finding.CreatedAt = time.Now()
			}
			findings = append(findings, &finding)

		default:
			skippedTypes[envelope.Type]++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	if len(records) == 0 && len(findings) == 0 {
		return fmt.Errorf("no importable data found in %s (parsed %d lines, %d errors)", filePath, lineNum, parseErrors)
	}

	// Import HTTP records in batches
	recordsSaved := 0
	const batchSize = 500
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		uuids, err := repo.SaveRecordsBatch(ctx, records[i:end])
		if err != nil {
			return fmt.Errorf("failed to save HTTP records batch: %w", err)
		}
		recordsSaved += len(uuids)
	}

	// Import findings with dedup
	findingsSaved, findingsSkipped := 0, 0
	for _, finding := range findings {
		if err := repo.SaveFindingDirect(ctx, finding); err != nil {
			findingsSkipped++
			continue
		}
		if finding.ID == 0 {
			findingsSkipped++
		} else {
			findingsSaved++
		}
	}

	sevCounts := map[string]int{}
	for _, finding := range findings {
		sevCounts[finding.Severity]++
	}

	if globalJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"records_imported":  recordsSaved,
			"findings_total":    len(findings),
			"findings_saved":    findingsSaved,
			"findings_skipped":  findingsSkipped,
			"severity":          sevCounts,
			"parse_errors":      parseErrors,
		})
	}

	fmt.Printf("%s Imported JSONL data from %s\n", terminal.SuccessSymbol(), filePath)
	if recordsSaved > 0 {
		fmt.Printf("  HTTP records: %d imported\n", recordsSaved)
	}
	if len(findings) > 0 {
		fmt.Printf("  Findings: %d total (%d new, %d duplicates skipped)\n", len(findings), findingsSaved, findingsSkipped)
	}
	if sevCounts["high"] > 0 || sevCounts["critical"] > 0 || sevCounts["medium"] > 0 || sevCounts["low"] > 0 {
		fmt.Printf("  Severity: %s, %s, %s, %s\n",
			terminal.BoldMagenta(fmt.Sprintf("%d critical", sevCounts["critical"])),
			terminal.BoldRed(fmt.Sprintf("%d high", sevCounts["high"])),
			terminal.BoldYellow(fmt.Sprintf("%d medium", sevCounts["medium"])),
			terminal.BoldGreen(fmt.Sprintf("%d low", sevCounts["low"])),
		)
	}
	if parseErrors > 0 {
		fmt.Printf("  %s %d lines could not be parsed\n", terminal.WarningSymbol(), parseErrors)
	}
	for typ, count := range skippedTypes {
		fmt.Printf("  Skipped %d %q entries\n", count, typ)
	}
	return nil
}
