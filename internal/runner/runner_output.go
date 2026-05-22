package runner

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corestats "github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// setPhaseTag sets the phase label on the output writer for console prefix,
// and updates the teeWriter's phase for trace-level log entries.
func (r *Runner) setPhaseTag(tag string) {
	if sw, ok := r.output.(*output.StandardWriter); ok {
		sw.PhaseTag = tag
	}
	if r.teeWriter != nil {
		r.teeWriter.SetPhase(tag)
	}
}

// printPhaseStart prints a phase start message to stderr.
func (r *Runner) printPhaseStart(phase, detail string) {
	if r.options.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s %s  %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue(phase), terminal.Muted(detail))
}

// printPhaseDetail prints an indented detail line under a phase header.
func (r *Runner) printPhaseDetail(detail string) {
	if r.options.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), detail)
}

// formatTargetCounts builds a standardized "Targets: N (M CLI | K HTTP Records)" string.
// Only HTTP records whose hostname matches the CLI targets are counted.
func (r *Runner) formatTargetCounts(ctx context.Context, cliCount int) string {
	var dbCount int64
	if r.repository != nil {
		hostnames := r.getInScopeDBHostnamesList(ctx)
		dbCount, _ = r.repository.CountRecordsAfterCursor(ctx, time.Time{}, "", hostnames...)
	}
	total := int64(cliCount) + dbCount
	return fmt.Sprintf("Targets: %s (%s CLI | %s HTTP Records)",
		terminal.Orange(fmt.Sprintf("%d", total)),
		terminal.Orange(fmt.Sprintf("%d", cliCount)),
		terminal.Orange(fmt.Sprintf("%d", dbCount)))
}

// printTargetDetail prints an indented target detail line using SymbolTarget.
func (r *Runner) printTargetDetail(detail string) {
	if r.options.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), detail)
}

// printPhaseComplete prints a phase completion message with elapsed time.
func (r *Runner) printPhaseComplete(phase, detail string) {
	if r.options.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Aqua(terminal.SymbolSuccess), terminal.Aqua(phase), terminal.Muted(detail))
}

// printPhaseFeedback prints an informational feedback line during a phase.
func (r *Runner) printPhaseFeedback(phase, detail string) {
	if r.options.Silent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s  %s\n", terminal.Orange(terminal.SymbolStart), terminal.Orange(phase), terminal.Muted(detail))
}

// formatStatusCodeArray formats a [5]int status code array (1xx..5xx) with colors.
func formatStatusCodeArray(codes [5]int) string {
	return fmt.Sprintf("2xx: %s  3xx: %s  4xx: %s  5xx: %s",
		terminal.Green(fmt.Sprintf("%d", codes[1])),
		terminal.Cyan(fmt.Sprintf("%d", codes[2])),
		terminal.Yellow(fmt.Sprintf("%d", codes[3])),
		terminal.Red(fmt.Sprintf("%d", codes[4])))
}

// formatStatusCodeMap formats a map[int]int64 of status codes into a colored summary.
func formatStatusCodeMap(codes map[int]int64) string {
	var buckets [5]int
	for code, count := range codes {
		idx := code/100 - 1
		if idx < 0 {
			idx = 0
		}
		if idx > 4 {
			idx = 4
		}
		buckets[idx] += int(count)
	}
	return formatStatusCodeArray(buckets)
}

// makeOnTraffic returns a callback that prints HTTP traffic lines to stderr
// using the same format as the spidering phase output.
func (r *Runner) makeOnTraffic(phaseTag string) func(method, url string, statusCode int, contentType string) {
	seen := make(map[string]struct{})
	var mu sync.Mutex
	// Discovery phase generates many 404s during path probing.
	// Suppress them unless --verbose is set to keep the output clean.
	suppress404 := phaseTag == "discovery" && !r.options.Debug
	return func(method, url string, statusCode int, contentType string) {
		if r.options.Silent {
			return
		}
		if suppress404 && statusCode == 404 {
			return
		}
		key := method + " " + url
		mu.Lock()
		if _, dup := seen[key]; dup {
			mu.Unlock()
			return
		}
		seen[key] = struct{}{}
		mu.Unlock()
		printTrafficLine(phaseTag, method, url, statusCode, contentType)
	}
}

func (r *Runner) makeOnTrafficVerbose(phaseTag string) func(method, url string, statusCode int, contentType string) {
	if !r.options.Verbose {
		return nil
	}
	return r.makeOnTraffic(phaseTag)
}

// printTrafficLine prints an HTTP traffic line to stderr with phase prefix and colors.
func printTrafficLine(phaseTag, method, url string, statusCode int, contentType string) {
	fmt.Fprint(os.Stderr, formatTrafficLine(phaseTag, method, url, statusCode, contentType))
}

// formatTrafficLine returns the ANSI-colored traffic line used by
// printTrafficLine. Split out so the same content can be routed to the session
// log file without also going through stderr.
func formatTrafficLine(phaseTag, method, url string, statusCode int, contentType string) string {
	// Phase prefix
	prefix := terminal.Muted(terminal.SymbolChevron+" "+phaseTag+" "+terminal.SymbolPipe) + " "
	prefixVisibleLen := len(phaseTag) + 5

	// Status
	status := strconv.Itoa(statusCode)
	sColor := statusColorCode(statusCode)

	// Content type (short form)
	ct := parseContentType(contentType)
	if ct == "" {
		ct = "-"
	}

	// Truncate URL to fit terminal width
	contentLen := len(status) + len(method) + len(ct) + 6
	totalPrefixLen := prefixVisibleLen + contentLen
	if termWidth := terminal.TerminalWidth(); termWidth > 0 && totalPrefixLen < termWidth {
		url = terminal.Truncate(url, termWidth-totalPrefixLen)
	}

	return fmt.Sprintf("%s%s[%s]\033[0m %s%s\033[0m %s%s\033[0m %s\n",
		prefix,
		sColor, status,
		methodColorCode(method), method,
		contentTypeColorCode(ct), ct,
		url)
}

func methodColorCode(method string) string {
	switch method {
	case "GET":
		return "\033[32m"
	case "POST":
		return "\033[33m"
	case "PUT", "PATCH":
		return "\033[36m"
	case "DELETE":
		return "\033[31m"
	default:
		return "\033[35m"
	}
}

func statusColorCode(status int) string {
	switch {
	case status >= 500:
		return "\033[31m"
	case status >= 400:
		return "\033[33m"
	case status >= 300:
		return "\033[36m"
	default:
		return "\033[32m"
	}
}

func contentTypeColorCode(ct string) string {
	switch {
	case strings.Contains(ct, "html"):
		return "\033[32m"
	case strings.Contains(ct, "json"):
		return "\033[33m"
	case strings.Contains(ct, "javascript"), strings.Contains(ct, "css"):
		return "\033[36m"
	default:
		return "\033[35m"
	}
}

func parseContentType(ct string) string {
	if idx := strings.Index(ct, ";"); idx != -1 {
		return strings.TrimSpace(ct[:idx])
	}
	return ct
}

// fmtDuration formats a duration in a human-friendly way (e.g. "2m30s", "45s").
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm%ds", m, s)
}

// logModuleMetrics logs the top modules by total time and findings at debug level.
func logModuleMetrics(metrics map[string]corestats.ModuleStatsSnapshot) {
	// Sort by total time descending for top-5 slowest
	type entry struct {
		id   string
		snap corestats.ModuleStatsSnapshot
	}
	entries := make([]entry, 0, len(metrics))
	for id, snap := range metrics {
		entries = append(entries, entry{id, snap})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].snap.TotalTime > entries[j].snap.TotalTime
	})

	limit := 5
	if len(entries) < limit {
		limit = len(entries)
	}
	for i := 0; i < limit; i++ {
		e := entries[i]
		zap.L().Debug("Module metrics",
			zap.String("module", e.id),
			zap.Int64("invocations", e.snap.Invocations),
			zap.Int64("findings", e.snap.Findings),
			zap.Int64("errors", e.snap.Errors),
			zap.Duration("total_time", e.snap.TotalTime))
	}
}

// printScanConfig prints a human-readable scan configuration summary to stderr.
// This provides the same information the CLI's printScanSummary shows, ensuring
// API-triggered scans also display the effective configuration.
func (r *Runner) printScanConfig() {
	if r.options.Silent || r.options.ScanConfigPrinted {
		return
	}

	opts := r.options
	settings := r.settings

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue("Scan Configuration"))
	if opts.Stateless {
		statelessLine := "Stateless mode: using temporary database"
		if opts.Verbose && settings.Database.SQLite.Path != "" {
			statelessLine += " " + terminal.Gray("("+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), statelessLine)
	}

	if opts.ProjectUUID != "" {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}

	strategy := settings.ScanningStrategy.DefaultStrategy
	if strategy == "" {
		strategy = "default"
	}
	fmt.Fprintf(os.Stderr, "  %s Strategy: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(strategy))

	if opts.ScanningProfile != "" {
		fmt.Fprintf(os.Stderr, "  %s Profile: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanningProfile))
	}

	// Targets
	targetsLine := fmt.Sprintf("Targets: %s", terminal.Orange(fmt.Sprintf("%d", len(opts.Targets))))
	if r.repository != nil {
		ctx := context.Background()
		hostnames := r.getInScopeDBHostnamesList(ctx)
		if dbCount, err := r.repository.CountRecordsAfterCursor(ctx, time.Time{}, "", hostnames...); err == nil && dbCount > 0 {
			targetsLine += fmt.Sprintf(" (CLI: %s | HTTP Records: %s)",
				terminal.Orange(fmt.Sprintf("%d", len(opts.Targets))),
				terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)

	// Phase labels with duration info
	phaseLabel := func(name, phasePaceKey string, enabled bool) string {
		label := name
		if !enabled {
			return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(label)
		}
		resolved := settings.ScanningPace.ResolvePhase(phasePaceKey)
		var paceDetail string
		if resolved.MaxDuration > 0 {
			paceDetail = resolved.MaxDuration.String()
		}
		if resolved.DurationFactor > 0 {
			if paceDetail != "" {
				paceDetail += fmt.Sprintf(", x%.1f", resolved.DurationFactor)
			} else {
				paceDetail = fmt.Sprintf("x%.1f", resolved.DurationFactor)
			}
		}
		if paceDetail != "" {
			label += " " + terminal.Gray("("+paceDetail+")")
		}
		return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(label)
	}

	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		phaseLabel("ExternalHarvest", "external_harvester", opts.ExternalHarvestEnabled),
		phaseLabel("Spidering", "spidering", opts.SpideringEnabled),
		phaseLabel("Discovery", "discovery", opts.DiscoverEnabled))
	fmt.Fprintf(os.Stderr, "           %s | %s\n",
		phaseLabel("KnownIssueScan", "known-issue-scan", opts.KnownIssueScanEnabled),
		phaseLabel("DynamicAssessment", "dynamic-assessment", !opts.SkipDynamicAssessment))

	// Heuristics
	heuristicsDesc := map[string]string{
		"basic":    "probe target root pages to detect content type (HTML, JSON, blank) and skip spidering for non-HTML targets",
		"advanced": "basic checks + deep HTML analysis to detect SPA frameworks and optimize phase selection",
		"none":     "skip all heuristic probes, run all enabled phases unconditionally",
	}
	if desc, ok := heuristicsDesc[opts.HeuristicsCheck]; ok {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck),
			terminal.Gray(desc))
	} else if opts.HeuristicsCheck != "" {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck))
	}

	// Speed
	rateLimit := settings.ScanningPace.RateLimit
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", rateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))

	// Scope
	scopeOrigin := "relaxed"
	if settings.Scope.CLIOriginMode != "" {
		scopeOrigin = settings.Scope.CLIOriginMode
	}
	if opts.ScopeOriginMode != "" {
		scopeOrigin = opts.ScopeOriginMode
	}
	originDesc := map[string]string{
		"relaxed":  "host must contain the target's keyword",
		"all":      "no origin restriction, all hosts are in scope",
		"balanced": "host must share the target's eTLD+1",
		"strict":   "host must exactly match the target host",
	}
	originDescStr := ""
	if desc, ok := originDesc[scopeOrigin]; ok {
		originDescStr = " " + terminal.Gray(desc)
	}
	fmt.Fprintf(os.Stderr, "  %s Scope: origin=%s | ignore-static=%s%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiPurple(scopeOrigin),
		terminal.HiPurple(fmt.Sprintf("%v", settings.Scope.IgnoreStaticFile)),
		originDescStr)

	// Modules
	var activeCount int
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeCount = len(modules.GetActiveModules())
	} else {
		activeCount = len(modules.GetActiveModulesByIDs(opts.Modules))
	}
	passiveCount := len(modules.GetPassiveModules())
	fmt.Fprintf(os.Stderr, "  %s Modules: %s active, %s passive\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", activeCount)),
		terminal.Orange(fmt.Sprintf("%d", passiveCount)))

	// Extensions
	extEnabled := settings != nil && settings.DynamicAssessment.Extensions.Enabled
	if extEnabled {
		extCount := 0
		if r.sharedInfra != nil && r.sharedInfra.JSEngine != nil {
			extCount = len(r.sharedInfra.JSEngine.ActiveModules()) + len(r.sharedInfra.JSEngine.PassiveModules())
		}
		fmt.Fprintf(os.Stderr, "  %s Extensions: %s | %s loaded\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiGreen("enabled"),
			terminal.HiTeal(fmt.Sprintf("%d", extCount)))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Extensions: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("disabled"))
	}

	// Session authentication
	printSessionAuth := func(detail string) {
		fmt.Fprintf(os.Stderr, "  %s Session auth: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiGreen("enabled"),
			terminal.Gray(detail))
	}
	totalAuth := len(opts.AuthFiles) + len(opts.AuthInline)
	switch {
	case totalAuth == 1 && len(opts.AuthFiles) == 1:
		printSessionAuth("from " + terminal.ShortenHome(opts.AuthFiles[0]))
	case totalAuth == 1 && len(opts.AuthInline) == 1:
		printSessionAuth("from inline auth")
	case totalAuth > 1:
		printSessionAuth(fmt.Sprintf("from %d auth source(s)", totalAuth))
	default:
		fmt.Fprintf(os.Stderr, "  %s Session auth: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("none"))
	}
}

// logConfigSnapshot stores the effective scan configuration as a structured
// metadata entry in the scan logs. This allows API consumers to inspect what
// settings were active for any historical scan.
func (r *Runner) logConfigSnapshot() {
	opts := r.options
	settings := r.settings

	strategy := ""
	rateLimit := 0
	if settings != nil {
		strategy = settings.ScanningStrategy.DefaultStrategy
		rateLimit = settings.ScanningPace.RateLimit
	}

	var activeCount int
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeCount = len(modules.GetActiveModules())
	} else {
		activeCount = len(modules.GetActiveModulesByIDs(opts.Modules))
	}
	passiveCount := len(modules.GetPassiveModules())

	meta := map[string]interface{}{
		"project_uuid":             opts.ProjectUUID,
		"targets":                  opts.Targets,
		"strategy":                 strategy,
		"scanning_profile":         opts.ScanningProfile,
		"concurrency":              opts.Concurrency,
		"rate_limit":               rateLimit,
		"max_per_host":             opts.MaxPerHost,
		"heuristics_check":         opts.HeuristicsCheck,
		"scope_origin_mode":        opts.ScopeOriginMode,
		"active_modules":           activeCount,
		"passive_modules":          passiveCount,
		"spidering_enabled":        opts.SpideringEnabled,
		"discovery_enabled":        opts.DiscoverEnabled,
		"known_issue_scan_enabled": opts.KnownIssueScanEnabled,
		"external_harvest":         opts.ExternalHarvestEnabled,
		"skip_dynamic":             opts.SkipDynamicAssessment,
	}
	r.scanLogger.InfoWithMeta("config", "scan configuration snapshot", meta)
}

// printVerboseTargets prints up to the first 10 targets when verbose mode is enabled.
func (r *Runner) printVerboseTargets(targets []string) {
	if !r.options.Verbose || r.options.Silent || len(targets) == 0 {
		return
	}
	limit := 10
	if len(targets) < limit {
		limit = len(targets)
	}
	for _, t := range targets[:limit] {
		fmt.Fprintf(os.Stderr, "    %s %s\n", terminal.Muted(terminal.SymbolChevron), terminal.Muted(t))
	}
	if len(targets) > 10 {
		fmt.Fprintf(os.Stderr, "    %s\n", terminal.Muted(fmt.Sprintf("... and %d more", len(targets)-10)))
	}
}
