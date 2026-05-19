package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// SwarmCoverageReport is the JSON document written to
// {sessionDir}/coverage.json. Every list is sorted deterministically so
// reports are diffable across runs.
type SwarmCoverageReport struct {
	GeneratedAt     time.Time `json:"generated_at"`
	AgenticScanUUID string    `json:"agentic_scan_uuid,omitempty"`
	TargetURL       string    `json:"target_url,omitempty"`
	Intensity       string    `json:"intensity,omitempty"`

	TotalRecords int              `json:"total_records"`
	Prefixes     []PrefixCoverage `json:"prefixes,omitempty"`

	Plan SwarmCoveragePlan `json:"plan"`

	FindingsByModule   map[string]int `json:"findings_by_module,omitempty"`
	FindingsByEndpoint map[string]int `json:"findings_by_endpoint,omitempty"`
	TotalFindings      int            `json:"total_findings"`

	Warnings []string `json:"warnings,omitempty"`
}

type PrefixCoverage struct {
	Prefix      string `json:"prefix"`
	RecordCount int    `json:"record_count"`
	InFocus     bool   `json:"in_focus"`
}

type SwarmCoveragePlan struct {
	ModuleTags []string `json:"module_tags,omitempty"`
	ModuleIDs  []string `json:"module_ids,omitempty"`
	// False when the scan ran against the full registry rather than a
	// plan-filtered subset — explicit so "no filter" isn't mistaken for
	// a misconfig.
	ModuleFilterApplied bool     `json:"module_filter_applied"`
	FocusAreas          []string `json:"focus_areas,omitempty"`
	Notes               string   `json:"notes,omitempty"`
	ExtensionsCount     int      `json:"extensions_count"`
	NeedsExtensions     bool     `json:"needs_extensions"`
	ExtensionAgentError string   `json:"extension_agent_error,omitempty"`
}

type CoverageReportInputs struct {
	AgenticScanUUID    string
	TargetURL          string
	Intensity          string
	Plan               *SwarmPlan
	Records            []*httpmsg.HttpRequestResponse
	TotalFindings      int
	FindingsByModule   map[string]int
	FindingsByEndpoint map[string]int
	Warnings           []string
}

func BuildSwarmCoverageReport(in CoverageReportInputs) *SwarmCoverageReport {
	report := &SwarmCoverageReport{
		GeneratedAt:        time.Now().UTC(),
		AgenticScanUUID:    in.AgenticScanUUID,
		TargetURL:          in.TargetURL,
		Intensity:          in.Intensity,
		TotalRecords:       len(in.Records),
		TotalFindings:      in.TotalFindings,
		FindingsByModule:   in.FindingsByModule,
		FindingsByEndpoint: in.FindingsByEndpoint,
		Warnings:           in.Warnings,
	}

	if in.Plan != nil {
		report.Plan = SwarmCoveragePlan{
			ModuleTags:          sortedCopy(in.Plan.ModuleTags),
			ModuleIDs:           sortedCopy(in.Plan.ModuleIDs),
			ModuleFilterApplied: len(in.Plan.ModuleTags) > 0 || len(in.Plan.ModuleIDs) > 0,
			FocusAreas:          append([]string(nil), in.Plan.FocusAreas...),
			Notes:               in.Plan.Notes,
			ExtensionsCount:     len(in.Plan.Extensions),
			NeedsExtensions:     in.Plan.NeedsExtensions,
			ExtensionAgentError: in.Plan.ExtensionAgentError,
		}
	}

	if len(in.Records) > 0 {
		mentioned := map[string]bool{}
		if in.Plan != nil {
			mentioned = planMentionedPrefixes(in.Plan)
		}
		counts := map[string]int{}
		for _, rr := range in.Records {
			prefix := recordPathPrefix(rr)
			if prefix == "" {
				continue
			}
			counts[prefix]++
		}
		prefixes := make([]PrefixCoverage, 0, len(counts))
		for prefix, count := range counts {
			prefixes = append(prefixes, PrefixCoverage{
				Prefix:      prefix,
				RecordCount: count,
				InFocus:     prefixIsCovered(prefix, mentioned),
			})
		}
		sort.Slice(prefixes, func(i, j int) bool {
			return prefixes[i].Prefix < prefixes[j].Prefix
		})
		report.Prefixes = prefixes
	}

	return report
}

// WriteSwarmCoverageReport writes the report to {sessionDir}/coverage.json
// and returns the path. I/O errors are logged and "" returned — a
// serialization hiccup must not fail a 12-hour scan.
func WriteSwarmCoverageReport(sessionDir string, report *SwarmCoverageReport) string {
	if sessionDir == "" || report == nil {
		return ""
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal coverage report", zap.Error(err))
		return ""
	}
	path := filepath.Join(sessionDir, "coverage.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		zap.L().Warn("Failed to write coverage report", zap.String("path", path), zap.Error(err))
		return ""
	}
	return path
}

// findingAggregatesFromDB returns finding counts grouped by module_id and
// by URL. Uses two SQL GROUP BY queries — bounded by distinct-value count,
// not finding count — so it scales to projects with thousands of findings.
func findingAggregatesFromDB(ctx context.Context, repo *database.Repository, projectUUID string) (byModule, byEndpoint map[string]int) {
	if repo == nil {
		return nil, nil
	}
	mod, err := database.CountFindingsByModule(ctx, repo.DB(), projectUUID)
	if err != nil {
		zap.L().Debug("findingAggregatesFromDB: CountFindingsByModule failed", zap.Error(err))
	} else if len(mod) > 0 {
		byModule = make(map[string]int, len(mod))
		for k, v := range mod {
			byModule[k] = int(v)
		}
	}
	url, err := database.CountFindingsByURL(ctx, repo.DB(), projectUUID)
	if err != nil {
		zap.L().Debug("findingAggregatesFromDB: CountFindingsByURL failed", zap.Error(err))
	} else if len(url) > 0 {
		byEndpoint = make(map[string]int, len(url))
		for k, v := range url {
			byEndpoint[k] = int(v)
		}
	}
	return byModule, byEndpoint
}
