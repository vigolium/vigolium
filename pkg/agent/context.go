package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"go.uber.org/zap"
)

// moduleContextCache caches the serialized module list and tags JSON.
// Modules don't change during a process lifetime, so this is computed once.
type moduleContextCache struct {
	once     sync.Once
	listJSON string
	tagsJSON string
}

var globalModuleCache moduleContextCache

func (mc *moduleContextCache) get() (listJSON, tagsJSON string) {
	mc.once.Do(func() {
		var entries []contextModuleEntry
		tagSet := make(map[string]struct{})

		for _, m := range modules.GetActiveModules() {
			entries = append(entries, contextModuleEntry{
				ID:          m.ID(),
				Name:        m.Name(),
				Type:        "active",
				Description: m.ShortDescription(),
				Severity:    m.Severity().String(),
			})
			for _, tag := range m.Tags() {
				tagSet[tag] = struct{}{}
			}
		}
		for _, m := range modules.GetPassiveModules() {
			entries = append(entries, contextModuleEntry{
				ID:          m.ID(),
				Name:        m.Name(),
				Type:        "passive",
				Description: m.ShortDescription(),
				Severity:    m.Severity().String(),
			})
			for _, tag := range m.Tags() {
				tagSet[tag] = struct{}{}
			}
		}

		if b, err := json.Marshal(entries); err == nil {
			mc.listJSON = string(b)
		}

		tags := make([]string, 0, len(tagSet))
		for tag := range tagSet {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		if b, err := json.Marshal(tags); err == nil {
			mc.tagsJSON = string(b)
		}
	})
	return mc.listJSON, mc.tagsJSON
}

// Compact JSON structs for context data (unexported).

type contextModuleEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type contextFindingEntry struct {
	ModuleID    string   `json:"module_id"`
	ModuleName  string   `json:"module_name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	MatchedAt   []string `json:"matched_at,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type contextEndpointEntry struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Path       string `json:"path"`
}

type contextHighRiskEndpointEntry struct {
	Method     string   `json:"method"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Path       string   `json:"path"`
	RiskScore  int      `json:"risk_score"`
	Remarks    []string `json:"remarks,omitempty"`
}

// variablesDeclared returns true if name appears in the template's Variables list.
func variablesDeclared(vars []string, name string) bool {
	for _, v := range vars {
		if v == name {
			return true
		}
	}
	return false
}

// enrichContextFromDB populates PreviousFindings, DiscoveredEndpoints, and ScanStats
// from the database. Only queries fields that the template declares in its variables list.
// Limits are read from the provided ContextLimits config; zero values use defaults.
func enrichContextFromDB(ctx context.Context, data *TemplateData, repo *database.Repository, hostname string, templateVars []string, limits config.ContextLimits, cache *ContextCache) {
	if repo == nil {
		return
	}
	db := repo.DB()

	// Previous findings
	if variablesDeclared(templateVars, "PreviousFindings") {
		limit := limits.EffectiveMaxFindings()
		cached := false
		if cache != nil {
			if val, ok := cache.Get(hostname, "PreviousFindings", limit); ok {
				data.PreviousFindings = val
				cached = true
			}
		}
		if !cached {
			filters := database.QueryFilters{Limit: limit}
			if hostname != "" {
				filters.HostPattern = hostname
			}
			fqb := database.NewFindingsQueryBuilder(db, filters)
			findings, err := fqb.Execute(ctx)
			if err != nil {
				zap.L().Debug("Failed to query findings for context", zap.Error(err))
			} else if len(findings) > 0 {
				entries := make([]contextFindingEntry, 0, len(findings))
				for _, f := range findings {
					entries = append(entries, contextFindingEntry{
						ModuleID:    f.ModuleID,
						ModuleName:  f.ModuleName,
						Description: f.Description,
						Severity:    f.Severity,
						Confidence:  f.Confidence,
						MatchedAt:   f.MatchedAt,
						Tags:        f.Tags,
					})
				}
				if b, err := json.Marshal(entries); err == nil {
					data.PreviousFindings = string(b)
					if cache != nil {
						cache.Set(hostname, "PreviousFindings", limit, data.PreviousFindings)
					}
				}
			}
		}
	}

	// Discovered endpoints
	if variablesDeclared(templateVars, "DiscoveredEndpoints") {
		limit := limits.EffectiveMaxEndpoints()
		cached := false
		if cache != nil {
			if val, ok := cache.Get(hostname, "DiscoveredEndpoints", limit); ok {
				data.DiscoveredEndpoints = val
				cached = true
			}
		}
		if !cached {
			filters := database.QueryFilters{Limit: limit}
			if hostname != "" {
				filters.HostPattern = hostname
			}
			qb := database.NewQueryBuilder(db, filters)
			records, err := qb.Execute(ctx)
			if err != nil {
				zap.L().Debug("Failed to query HTTP records for context", zap.Error(err))
			} else if len(records) > 0 {
				entries := make([]contextEndpointEntry, 0, len(records))
				for _, r := range records {
					entries = append(entries, contextEndpointEntry{
						Method:     r.Method,
						URL:        r.URL,
						StatusCode: r.StatusCode,
						Path:       r.Path,
					})
				}
				if b, err := json.Marshal(entries); err == nil {
					data.DiscoveredEndpoints = string(b)
					if cache != nil {
						cache.Set(hostname, "DiscoveredEndpoints", limit, data.DiscoveredEndpoints)
					}
				}
			}
		}
	}

	// Scan stats
	if variablesDeclared(templateVars, "ScanStats") {
		cached := false
		if cache != nil {
			if val, ok := cache.Get(hostname, "ScanStats", 0); ok {
				data.ScanStats = val
				cached = true
			}
		}
		if !cached {
			filters := database.QueryFilters{}
			if hostname != "" {
				filters.HostPattern = hostname
			}
			stats, err := db.GetStats(ctx, filters)
			if err != nil {
				zap.L().Debug("Failed to query scan stats for context", zap.Error(err))
			} else if stats != nil {
				if b, err := json.Marshal(stats); err == nil {
					data.ScanStats = string(b)
					if cache != nil {
						cache.Set(hostname, "ScanStats", 0, data.ScanStats)
					}
				}
			}
		}
	}

	// High risk endpoints (top-N by risk_score)
	if variablesDeclared(templateVars, "HighRiskEndpoints") {
		limit := limits.EffectiveMaxHighRisk()
		cached := false
		if cache != nil {
			if val, ok := cache.Get(hostname, "HighRiskEndpoints", limit); ok {
				data.HighRiskEndpoints = val
				cached = true
			}
		}
		if !cached {
			filters := database.QueryFilters{
				Limit:        limit,
				MinRiskScore: limits.EffectiveMinRiskScore(),
				SortBy:       "risk_score",
			}
			if hostname != "" {
				filters.HostPattern = hostname
			}
			qb := database.NewQueryBuilder(db, filters)
			records, err := qb.Execute(ctx)
			if err != nil {
				zap.L().Debug("Failed to query high risk endpoints for context", zap.Error(err))
			} else if len(records) > 0 {
				entries := make([]contextHighRiskEndpointEntry, 0, len(records))
				for _, r := range records {
					entries = append(entries, contextHighRiskEndpointEntry{
						Method:     r.Method,
						URL:        r.URL,
						StatusCode: r.StatusCode,
						Path:       r.Path,
						RiskScore:  r.RiskScore,
						Remarks:    r.Remarks,
					})
				}
				if b, err := json.Marshal(entries); err == nil {
					data.HighRiskEndpoints = string(b)
					if cache != nil {
						cache.Set(hostname, "HighRiskEndpoints", limit, data.HighRiskEndpoints)
					}
				}
			}
		}
	}
}

// enrichContextModules populates ModuleList and/or ModuleTags depending on which
// variables the template declares. Uses a process-lifetime cache since the module
// registry is static after initialization.
func enrichContextModules(data *TemplateData, templateVars []string) {
	needList := variablesDeclared(templateVars, "ModuleList")
	needTags := variablesDeclared(templateVars, "ModuleTags")
	if !needList && !needTags {
		return
	}

	listJSON, tagsJSON := globalModuleCache.get()

	if needList {
		data.ModuleList = listJSON
	}
	if needTags {
		data.ModuleTags = tagsJSON
	}
}

// enrichContextCommands populates AvailableCommands with a hardcoded CLI command
// reference. Only runs if the template declares the AvailableCommands variable.
func enrichContextCommands(data *TemplateData, templateVars []string) {
	if !variablesDeclared(templateVars, "AvailableCommands") {
		return
	}

	data.AvailableCommands = `Available vigolium CLI commands for scanning:

  vigolium scan-url <url> [flags]
    Scan a single URL for vulnerabilities.
    Flags:
      --method <METHOD>    HTTP method (default: GET)
      --body <BODY>        Request body
      -H, --header <HDR>   Custom header (repeatable, e.g. -H 'Cookie: x=1')
      --no-passive         Skip passive modules
      --no-insertion-points  Skip insertion point testing
      --json               Output results as JSON

  vigolium scan-request [flags]
    Scan using a raw HTTP request from file or stdin.
    Flags:
      --raw-file <FILE>    Path to raw HTTP request file
      --target <URL>       Target base URL (required with --raw-file)
      --stdin              Read raw request from stdin
      --json               Output results as JSON

  vigolium module ls [flags]
    List available scanner modules.
    Flags:
      --json               Output as JSON

Output format: When --json is used, scan commands return:
  {"target": "...", "method": "...", "scan_duration_ms": N, "modules_run": N, "findings": [...]}
Each finding contains: module_id, matched, info.name, info.severity, info.description.`
}

// hostnameFromURL extracts the host (including port when non-standard) from a raw URL string.
// Returns host:port for non-standard ports (e.g. "localhost:3005"), bare hostname otherwise.
func hostnameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}
