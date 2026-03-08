package harness

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules"
)

// GenerateCoverageReport compares registered modules against benchmark definitions.
func GenerateCoverageReport(definitionDirs ...string) (*CoverageReport, error) {
	// Collect all module IDs referenced in YAML definitions
	coveredModules := make(map[string][]string) // moduleID -> []appName
	totalTestCases := 0

	for _, dir := range definitionDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, fmt.Errorf("failed to glob %s: %w", dir, err)
		}

		// Also check subdirectories (e.g., blackbox/)
		subFiles, err := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
		if err == nil {
			files = append(files, subFiles...)
		}

		for _, f := range files {
			def, err := LoadDefinition(f)
			if err != nil {
				return nil, fmt.Errorf("failed to load %s: %w", f, err)
			}

			for _, tc := range def.TestCases {
				totalTestCases++
				for _, modID := range tc.Modules {
					if !contains(coveredModules[modID], def.App.Name) {
						coveredModules[modID] = append(coveredModules[modID], def.App.Name)
					}
				}
			}
		}
	}

	// Build coverage entries for all registered modules
	var entries []CoverageEntry

	activeIDs := modules.GetActiveModulesID()
	passiveIDs := modules.GetPassiveModulesID()

	for _, id := range activeIDs {
		apps := coveredModules[id]
		entries = append(entries, CoverageEntry{
			ModuleID:   id,
			ModuleType: "active",
			Apps:       apps,
			TestCount:  len(apps),
			Covered:    len(apps) > 0,
		})
	}

	for _, id := range passiveIDs {
		apps := coveredModules[id]
		entries = append(entries, CoverageEntry{
			ModuleID:   id,
			ModuleType: "passive",
			Apps:       apps,
			TestCount:  len(apps),
			Covered:    len(apps) > 0,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ModuleType != entries[j].ModuleType {
			return entries[i].ModuleType < entries[j].ModuleType
		}
		return entries[i].ModuleID < entries[j].ModuleID
	})

	// Calculate totals
	report := &CoverageReport{
		Entries:        entries,
		TotalActive:    len(activeIDs),
		TotalPassive:   len(passiveIDs),
		TotalTestCases: totalTestCases,
	}

	for _, e := range entries {
		if e.Covered {
			if e.ModuleType == "active" {
				report.CoveredActive++
			} else {
				report.CoveredPassive++
			}
		}
	}

	return report, nil
}

// FormatCoverageMarkdown generates a markdown table from a coverage report.
func FormatCoverageMarkdown(report *CoverageReport) string {
	var sb strings.Builder

	sb.WriteString("# Vigolium Module Benchmark Coverage\n\n")
	fmt.Fprintf(&sb, "**Total test cases:** %d\n\n", report.TotalTestCases)
	fmt.Fprintf(&sb, "**Active modules:** %d/%d (%.0f%%)\n\n",
		report.CoveredActive, report.TotalActive,
		percentage(report.CoveredActive, report.TotalActive))
	fmt.Fprintf(&sb, "**Passive modules:** %d/%d (%.0f%%)\n\n",
		report.CoveredPassive, report.TotalPassive,
		percentage(report.CoveredPassive, report.TotalPassive))

	sb.WriteString("## Coverage Matrix\n\n")
	sb.WriteString("| Module ID | Type | Covered | Apps |\n")
	sb.WriteString("|-----------|------|---------|------|\n")

	for _, e := range report.Entries {
		covered := "No"
		if e.Covered {
			covered = "Yes"
		}
		apps := strings.Join(e.Apps, ", ")
		if apps == "" {
			apps = "-"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n",
			e.ModuleID, e.ModuleType, covered, apps)
	}

	// Uncovered modules section
	sb.WriteString("\n## Uncovered Modules\n\n")
	uncovered := 0
	for _, e := range report.Entries {
		if !e.Covered {
			fmt.Fprintf(&sb, "- `%s` (%s)\n", e.ModuleID, e.ModuleType)
			uncovered++
		}
	}
	if uncovered == 0 {
		sb.WriteString("All modules have benchmark coverage!\n")
	}

	return sb.String()
}

func percentage(covered, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(covered) / float64(total) * 100
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
