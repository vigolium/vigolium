package cli

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "One-screen orientation: database, project, scope, running scans, counts, proxy",
	Long: `Print where vigolium stands, in one small document (under 2 KB with -j):
the database it reads and the project selected (and where that selection
came from), how many scope rules each scope component has, up to 5 running
scans with their liveness, record/finding/scan counts for the project, the
proxy requests would go through (and where it came from), and whether an
installed copy of the agent skill is stale.

It makes no network calls and runs no tool checks; 'vigolium doctor' does
those.`,
	Example: FormatExamples(
		"# Orientation for a coding agent",
		"vigolium status -j",
	),
	Args: cobra.NoArgs,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
	registerCommandSchema(contract.Command{Name: "status", Item: statusView{}, ItemsKind: contract.ItemsObject,
		Description: "Orientation: database path, project and its source, scope rule counts per component, up to 5 running scans with liveness, record/finding/scan counts, the effective proxy and its source, skill staleness. No network calls."})
}

// statusRunningLimit caps the running scans listed.
const statusRunningLimit = 5

// statusView is the one item `status -j` reports. Kept small on purpose: it is
// the first thing an agent reads.
type statusView struct {
	DBPath        string `json:"db_path"`
	DBError       string `json:"db_error,omitempty"`
	ProjectUUID   string `json:"project_uuid"`
	ProjectName   string `json:"project_name,omitempty"`
	ProjectSource string `json:"project_source"`
	// Scope counts the include/exclude rules of each scope component that
	// differs from "everything in scope".
	Scope         statusScopeView   `json:"scope"`
	Running       []statusRunScan   `json:"running"`
	RunningTotal  int               `json:"running_total"`
	Counts        *statusCountsView `json:"counts"`
	Proxy         statusProxyView   `json:"proxy"`
	SkillStale    bool              `json:"skill_stale"`
	ConfigPath    string            `json:"config_path"`
	SessionsDir   string            `json:"sessions_dir"`
	GeneratedHint string            `json:"hint,omitempty"`
}

type statusScopeView struct {
	OriginMode string `json:"origin_mode"`
	// Components maps a component (host, path, status_code, …) to its
	// non-default rule counts; a component with only the default include-all
	// rule is absent.
	Components map[string]statusRuleCount `json:"components"`
	Methods    []string                   `json:"methods,omitempty"`
}

type statusRuleCount struct {
	Include int `json:"include"`
	Exclude int `json:"exclude"`
}

type statusRunScan struct {
	ScanUUID        string `json:"scan_uuid"`
	Target          string `json:"target,omitempty"`
	EffectiveStatus string `json:"effective_status"`
	Phase           string `json:"phase,omitempty"`
	LastWriteAt     string `json:"last_write_at,omitempty"`
	PID             int    `json:"pid,omitempty"`
}

type statusCountsView struct {
	Records  int `json:"records"`
	Findings int `json:"findings"`
	Scans    int `json:"scans"`
}

type statusProxyView struct {
	// URL is the proxy with any credentials redacted, "" for a direct
	// connection.
	URL    string `json:"url"`
	Source string `json:"source"`
}

// statusProxyResolver names the proxy a send would use and where it came
// from, through the HTTP stack's own resolver so status and the senders agree.
var statusProxyResolver = effectiveProxy

// redactProxyURL drops the password from a proxy URL.
func redactProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	return u.Redacted()
}

func runStatus(cmd *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	view := statusView{
		Running:     []statusRunScan{},
		Scope:       statusScopeOf(settings.Scope),
		ConfigPath:  config.ContractPath(effectiveConfigPath()),
		SessionsDir: config.ContractPath(settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()),
		SkillStale:  doctorSkillStale(),
	}
	pURL, pSource := statusProxyResolver(globalProxy)
	view.Proxy = statusProxyView{URL: redactProxyURL(pURL), Source: pSource}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, dbErr := openReadDB(globDBSkipSet{Records: false})
	projectUUID := ""
	if dbErr == nil {
		if !statelessReadRequested() {
			if projectUUID, err = resolveProjectUUID(); err != nil {
				return err
			}
		}
		view.DBPath = config.ContractPath(resolvedReadDBPath())
		repo := database.NewRepository(db)
		if p := clicommon.ResolvedProject(); p != nil && p.UUID == projectUUID {
			view.ProjectName = p.Name
		} else if projectUUID != "" {
			if p, err := repo.GetProjectByUUID(ctx, projectUUID); err == nil && p != nil {
				view.ProjectName = p.Name
			}
		}
		view.Counts = statusCounts(ctx, db, projectUUID)
		view.Running, view.RunningTotal = statusRunning(ctx, repo, projectUUID, settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir())
	} else {
		view.DBError = dbErr.Error()
	}
	view.ProjectUUID = projectUUID
	view.ProjectSource, _ = currentProjectSource()
	if view.SkillStale {
		view.GeneratedHint = "an installed agent skill is stale: vigolium doctor --fix --only skill"
	}

	if globalJSON {
		return emitObject(cmd, "", view, withDBPath(view.DBPath), withProjectScope(projectUUID))
	}
	printStatusHuman(view)
	return nil
}

// statusScopeOf counts the non-default rules per scope component.
func statusScopeOf(s config.ScopeConfig) statusScopeView {
	out := statusScopeView{OriginMode: s.CLIOriginMode, Components: map[string]statusRuleCount{}, Methods: s.Methods}
	if out.OriginMode == "" {
		out.OriginMode = "balanced"
	}
	for name, r := range map[string]config.ScopeRule{
		"host": s.Host, "path": s.Path, "status_code": s.StatusCode,
		"request_content_type": s.RequestContentType, "response_content_type": s.ResponseContentType,
		"request_string": s.RequestString, "response_string": s.ResponseString,
	} {
		inc := 0
		for _, v := range r.Include {
			if strings.TrimSpace(v) != "*" && strings.TrimSpace(v) != "" {
				inc++
			}
		}
		if inc == 0 && len(r.Exclude) == 0 {
			continue
		}
		out.Components[name] = statusRuleCount{Include: inc, Exclude: len(r.Exclude)}
	}
	return out
}

// statusCounts is three plain COUNT queries, scoped to the project.
func statusCounts(ctx context.Context, db *database.DB, projectUUID string) *statusCountsView {
	count := func(table string) int {
		q := db.NewSelect().TableExpr(table)
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		n, err := q.Count(ctx)
		if err != nil {
			return -1
		}
		return int(n)
	}
	return &statusCountsView{Records: count("http_records"), Findings: count("findings"), Scans: count("scans")}
}

// statusRunning lists up to statusRunningLimit scans whose row says running,
// with the shared liveness verdict.
func statusRunning(ctx context.Context, repo *database.Repository, projectUUID, sessionsDir string) ([]statusRunScan, int) {
	rows, err := repo.ListRunningScans(ctx, projectUUID)
	if err != nil {
		return []statusRunScan{}, 0
	}
	out := []statusRunScan{}
	shown := rows
	if len(shown) > statusRunningLimit {
		shown = shown[:statusRunningLimit]
	}
	lastLogs := lastScanLogTimes(ctx, repo, shown)
	for _, s := range shown {
		statusFile := runner.SessionStatusPath(sessionsDir, s.UUID)
		lv := sessionLiveness(s, statusFile, resolveSessionLogPath(filepath.Join(sessionsDir, s.UUID)), lastLogs[s.UUID])
		item := statusRunScan{ScanUUID: s.UUID, Target: truncateStatusTarget(s.Target),
			EffectiveStatus: effectiveStatus(s.Status, s.ErrorMessage, lv), Phase: s.CurrentPhase, PID: s.PID}
		if t := formatLivenessTime(lv.LastWriteAt); t != nil {
			item.LastWriteAt = *t
		}
		out = append(out, item)
	}
	return out, len(rows)
}

func truncateStatusTarget(t string) string {
	if len(t) > 80 {
		return t[:77] + "..."
	}
	return t
}

func printStatusHuman(v statusView) {
	db := v.DBPath
	if db == "" {
		db = "unavailable (" + v.DBError + ")"
	}
	fmt.Printf("%-10s %s\n", "database", db)
	project := v.ProjectUUID
	if v.ProjectName != "" {
		project = v.ProjectName + " (" + v.ProjectUUID + ")"
	}
	fmt.Printf("%-10s %s [%s]\n", "project", project, v.ProjectSource)
	if len(v.Scope.Components) == 0 {
		fmt.Printf("%-10s everything (origin mode %s)\n", "scope", v.Scope.OriginMode)
	} else {
		var parts []string
		for name, c := range v.Scope.Components {
			parts = append(parts, fmt.Sprintf("%s +%d/-%d", name, c.Include, c.Exclude))
		}
		fmt.Printf("%-10s %s (origin mode %s)\n", "scope", strings.Join(parts, ", "), v.Scope.OriginMode)
	}
	if v.Counts != nil {
		fmt.Printf("%-10s %d records, %d findings, %d scans\n", "counts", v.Counts.Records, v.Counts.Findings, v.Counts.Scans)
	}
	fmt.Printf("%-10s %d\n", "running", v.RunningTotal)
	for _, r := range v.Running {
		fmt.Printf("  %s %s %s %s\n", r.ScanUUID, r.EffectiveStatus, r.Phase, r.Target)
	}
	proxy := "direct"
	if v.Proxy.URL != "" {
		proxy = v.Proxy.URL + " (" + v.Proxy.Source + ")"
	}
	fmt.Printf("%-10s %s\n", "proxy", proxy)
	if v.SkillStale {
		fmt.Printf("%s %s\n", terminal.WarningSymbol(), v.GeneratedHint)
	}
}
