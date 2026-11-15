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

	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	corestats "github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
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

// findingsVisibleOnStdout reports whether findings written via r.output already
// render to stdout in human-readable form (console format). When false — jsonl/
// html defer their output to post-scan files, or the run is silent — live
// findings are otherwise invisible during the scan; see echoLiveFinding.
func (r *Runner) findingsVisibleOnStdout() bool {
	if s, ok := r.output.(interface{ ShowsFindingsOnStdout() bool }); ok {
		return s.ShowsFindingsOnStdout()
	}
	return false
}

// echoLiveFinding renders a finding to stderr (and the session log) as it's
// discovered, so a scan shows live results even when the stdout result stream is
// deferred to files (jsonl/html). It's a no-op when findings already stream to
// stdout in human-readable form (console format), when silent, or for a captured
// -P child (whose stdout IS the per-target log). The phase status heartbeat,
// traffic lines, and tech-detect lines all reach stderr independent of --format;
// this gives findings the same treatment.
func (r *Runner) echoLiveFinding(phaseTag string, result *output.ResultEvent) {
	if result == nil || r.options.Silent || r.options.CapturedConsole {
		return
	}
	if r.findingsVisibleOnStdout() {
		return
	}
	line := output.FormatPhaseFindingLine(phaseTag, result)
	r.writeSessionLog(line)
	fmt.Fprint(os.Stderr, line)
}

// FormatBlockNoticeLine renders the one-line WAF/CDN block warning (with a
// trailing newline) shown when the edge starts filtering scan traffic. It is
// shared by every scan front-end so the message and the "unrecognized vendor"
// fallback stay identical whether the scan runs through the Runner or the direct
// scan-url/scan-request path.
// NoticeMarkerBlock and NoticeMarkerPacing are the bracketed tags the two
// operator notices are rendered with. Exported because a reader has to find them
// again in a rendered log (`vigolium log` reprints any that fell above the tail
// window) — matching on the marker rather than the prose is deliberate, since
// the prose is a sentence that gets reworded and the marker is what it tags.
const (
	NoticeMarkerBlock  = "[waf-block-detected]"
	NoticeMarkerPacing = "[waf-pacing-armed]"
)

func FormatBlockNoticeLine(n http.BlockNotice) string {
	vendor := n.WAFType
	if vendor == "" || vendor == "generic" {
		vendor = "WAF/CDN"
	}
	return fmt.Sprintf("%s %s %s %s %s %s\n",
		terminal.BoldYellow(terminal.SymbolWarning),
		terminal.BoldYellow(NoticeMarkerBlock),
		terminal.HiBlue(n.Host),
		terminal.Muted("→"),
		terminal.Yellow(fmt.Sprintf("%s (HTTP %d)", vendor, n.Status)),
		terminal.Muted("edge is filtering scan traffic — results for this host may be incomplete"))
}

// attachWAFBlockNotifier wires a one-time-per-host WAF/CDN block warning onto the
// scan's HTTP requester. The first time any scan request to a host comes back as
// a captcha / bot-detection / challenge page, a prominent warning is printed to
// stderr (and the session log) so the operator knows the edge is filtering
// traffic and results against that host are likely incomplete. Fires across every
// phase (discovery, spidering, dynamic-assessment) since all traffic flows
// through the shared requester. No-op in silent mode or without a requester.
// The machine event stream is NOT gated on Silent: --silent asks for a quiet
// terminal, and a driver that passed both --silent and --events wants exactly
// that — no console, full stream. So the notifier is installed whenever either
// consumer wants it, and each consumer decides for itself.
func (r *Runner) attachWAFBlockNotifier(requester *http.Requester) {
	if requester == nil {
		return
	}
	console := !r.options.Silent
	if !console && !scanevents.On() {
		return
	}
	requester.SetBlockNotifier(func(n http.BlockNotice) {
		if console {
			r.emitNoticeLine(FormatBlockNoticeLine(n))
		}
		emitBlockEvent(n)
	})
}

// emitNoticeLine writes a preformatted operator notice to both the session log and
// stderr — the shared tail of the WAF block/pacing notifiers.
func (r *Runner) emitNoticeLine(line string) {
	r.writeSessionLog(line)
	fmt.Fprint(os.Stderr, line)
}

// FormatEdgePaceLine renders the one-line notice shown when a host is fingerprinted
// behind a CDN/WAF edge and its active-scan concurrency is proactively paced to keep
// a burst from arming a rate-based WAF. It spells out the concurrency drop so the
// operator understands the scan will run slower against that host. Companion to
// FormatBlockNoticeLine — a caution, not a failure: the scan continues, just gentler.
func FormatEdgePaceLine(n hostlimit.PreArmNotice) string {
	vendor := n.Vendor
	if vendor == hostlimit.PreArmVendorLocal {
		return fmt.Sprintf("%s %s %s %s %s %s\n",
			terminal.Yellow(terminal.SymbolSnow),
			terminal.BoldYellow(NoticeMarkerPacing),
			terminal.HiBlue(n.Host),
			terminal.Muted("→"),
			terminal.Yellow("local host"),
			terminal.Muted(fmt.Sprintf("starting per-host concurrency at %d (of %d) and ramping up on clean answers, so a small server is not overrun (disable with --no-waf-pacing)", n.Start, n.From)))
	}
	if vendor == "" {
		vendor = "WAF/CDN"
	}
	detail := fmt.Sprintf("pacing per-host concurrency %d→%d to avoid tripping a rate-based WAF — scanning this host will be slower (disable with --no-waf-pacing)",
		n.From, n.Start)
	return fmt.Sprintf("%s %s %s %s %s %s\n",
		terminal.Yellow(terminal.SymbolSnow),
		terminal.BoldYellow(NoticeMarkerPacing),
		terminal.HiBlue(n.Host),
		terminal.Muted("→"),
		terminal.Yellow(fmt.Sprintf("%s edge", vendor)),
		terminal.Muted(detail))
}

// attachWAFPacingNotifier wires a one-time-per-host notice onto the scan's host
// limiter for proactive CDN/WAF pacing. The first time any phase's traffic to a host
// reveals a CDN/WAF edge (e.g. CloudFront/Cloudflare headers on a clean 200), the host
// limiter drops that host's per-host concurrency so the later active phase paces from
// its first request instead of bursting the edge into a rate-based block. The notice
// hangs off the limiter — the single shared object every requester feeds — so it fires
// exactly once per host no matter which requester (heuristics, auth prep, discovery)
// first tripped the pre-arm. The throttle itself is applied regardless; this only
// surfaces the operator warning. No-op without a limiter, or when neither the
// console (silent mode) nor the machine event stream wants the notice.
func (r *Runner) attachWAFPacingNotifier(limiter *hostlimit.HostRateLimiter) {
	if limiter == nil {
		return
	}
	console := !r.options.Silent
	if !console && !scanevents.On() {
		return
	}
	limiter.SetPreArmNotifier(func(n hostlimit.PreArmNotice) {
		if console {
			r.emitNoticeLine(FormatEdgePaceLine(n))
		}
		emitPacingEvent(n.Host, n.Vendor, n.From, n.Start)
	})
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

// formatTargetCounts builds a standardized "Targets: N (M input | K HTTP Records)" string.
// Only HTTP records whose hostname matches the CLI targets are counted.
func (r *Runner) formatTargetCounts(ctx context.Context, cliCount int) string {
	var dbCount int64
	if r.repository != nil {
		hosts := r.getInScopeDBHosts(ctx)
		dbCount, _ = r.repository.CountRecordsAfterCursor(ctx, r.options.ProjectUUID, time.Time{}, "", hosts...)
	}
	// A -T/--target-file (or -i) run carries its targets in the input source, not
	// in options.Targets, so counting the CLI slice alone printed "0 input" for a
	// scan that was about to hit dozens of hosts. Take whichever is larger: the
	// caller's count wins when it is a phase-local target list the source can't
	// know about.
	seeded := int64(cliCount)
	// A database-backed input source (full-scan-on-receive) counts http_records,
	// which dbCount already reports; adding it as "input" would count them twice.
	if _, fromDB := r.inputSource.(*database.DBInputSource); !fromDB {
		if n := source.GetTotal(r.inputSource); n > seeded {
			seeded = n
		}
	}
	return fmt.Sprintf("Targets: %s (%s input | %s HTTP Records)",
		terminal.Orange(fmt.Sprintf("%d", seeded+dbCount)),
		terminal.Orange(fmt.Sprintf("%d", seeded)),
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

// logModuleMetrics logs the top modules by total time and findings.
//
// Info, not Debug: five lines per round, and the only view of where a phase's time
// went. It is emitted next to the pool and clusterer stats, which are already Info
// — there is no reason this one alone should need --debug.
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
		zap.L().Info("Module metrics",
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
	// In stateless mode the scan lives in a throwaway database, so the UUID
	// can't be used to query results later — printing it is just noise.
	if opts.ScanUUID != "" && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Scan ID: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanUUID))
	}
	if opts.Stateless {
		statelessLine := "Stateless mode: using temporary database"
		if opts.Verbose && settings.Database.SQLite.Path != "" {
			statelessLine += " " + terminal.Gray("("+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), statelessLine)
	}

	// Only surface the project when it's a real, operator-chosen one. The
	// auto-created default project is implementation noise — printing its UUID
	// just clutters the header for the common single-project case — and in
	// stateless mode the project lives in a throwaway database anyway.
	if opts.ProjectUUID != "" && opts.ProjectUUID != database.DefaultProjectUUID && !opts.Stateless {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}

	// The strategy ApplyScanStrategy resolved for this scan (a REST request's
	// "strategy" included); the configured default only when none was applied.
	strategy := opts.ScanningStrategy
	if strategy == "" {
		strategy = settings.ScanningStrategy.DefaultStrategy
	}
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
		hosts := r.getInScopeDBHosts(ctx)
		if dbCount, err := r.repository.CountRecordsAfterCursor(ctx, r.options.ProjectUUID, time.Time{}, "", hosts...); err == nil && dbCount > 0 {
			targetsLine += fmt.Sprintf(" (CLI: %s | HTTP Records: %s)",
				terminal.Orange(fmt.Sprintf("%d", len(opts.Targets))),
				terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)

	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		PhaseLabel(settings, "ExternalHarvest", "external_harvester", opts.ExternalHarvestEnabled, 0),
		PhaseLabel(settings, "Spidering", "spidering", opts.SpideringEnabled, SpideringBudget(settings, opts)),
		PhaseLabel(settings, "Discovery", "discovery", opts.DiscoverEnabled, DiscoveryBudget(settings, opts)))
	fmt.Fprintf(os.Stderr, "           %s | %s\n",
		PhaseLabel(settings, "KnownIssueScan", "known-issue-scan", opts.KnownIssueScanEnabled, 0),
		PhaseLabel(settings, "DynamicAssessment", "dynamic-assessment", !opts.SkipDynamicAssessment, 0))

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

	// Speed — same source as the limiter that enforces it (effectiveRateLimit).
	rateLimit := effectiveRateLimit(opts)
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", rateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))

	// Scope
	scopeOrigin := r.resolvedScopeOriginMode()
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
	if pol := opts.TrafficPolicy; pol != nil && len(pol.AllowedMethods) > 0 {
		fmt.Fprintf(os.Stderr, "  %s Methods: %s%s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiPurple(strings.Join(settings.Scope.Methods, ",")),
			terminal.Gray(map[bool]string{true: " (read-only: no form submission, logins or uploads)", false: ""}[pol.ReadOnly()]))
	}
	if r.offline() {
		fmt.Fprintf(os.Stderr, "  %s Offline: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("no OAST, external lookups, template or browser downloads, or update checks"))
	}

	// Modules
	var activeMods []modules.ActiveModule
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeMods = modules.GetActiveModules()
	} else {
		activeMods = modules.GetActiveModulesByIDs(opts.Modules)
	}
	passiveMods := modules.GetPassiveModules()
	activeCount, passiveCount, hygieneNote := HygieneBannerCounts(opts, settings, activeMods, passiveMods)
	if hygieneNote != "" {
		hygieneNote = " " + hygieneNote
	}
	fmt.Fprintf(os.Stderr, "  %s Modules: %s active, %s passive%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", activeCount)),
		terminal.Orange(fmt.Sprintf("%d", passiveCount)),
		hygieneNote)

	// Extensions
	extEnabled := settings != nil && settings.DynamicAssessment.Extensions.Enabled
	if extEnabled {
		// No count here: the extension engine is built later, in
		// buildInfrastructure, so a "N loaded" figure printed now could only
		// ever have said 0.
		fmt.Fprintf(os.Stderr, "  %s Extensions: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiGreen("enabled"))
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
	r.scanLogger.InfoWithMeta("config", "scan configuration snapshot", r.configSnapshotMeta())
}

// configSnapshotMeta builds the snapshot's key/value map. Split out from the log
// call so a test can assert what the snapshot claims without a logger, which is
// how the rate-limit disagreement went unnoticed: the snapshot reported the
// configured pace while the scan ran at the option's rate.
func (r *Runner) configSnapshotMeta() map[string]any {
	opts := r.options
	settings := r.settings

	strategy := ""
	kisRateLimit := 0
	if settings != nil {
		strategy = settings.ScanningStrategy.DefaultStrategy
		kisRateLimit = settings.ScanningPace.ResolvePhase("known-issue-scan").RateLimit
	}

	var activeMods []modules.ActiveModule
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeMods = modules.GetActiveModules()
	} else {
		activeMods = modules.GetActiveModulesByIDs(opts.Modules)
	}
	passiveMods := modules.GetPassiveModules()

	// The snapshot records what actually ran, so the suppressed hardening
	// advisories come out of the counts the same way the banner subtracts them.
	activeCount, passiveCount, _ := HygieneBannerCounts(opts, settings, activeMods, passiveMods)
	hygieneSuppressed := (len(activeMods) - activeCount) + (len(passiveMods) - passiveCount)

	meta := map[string]any{
		"project_uuid":     opts.ProjectUUID,
		"targets":          opts.Targets,
		"strategy":         strategy,
		"scanning_profile": opts.ScanningProfile,
		"concurrency":      opts.Concurrency,
		// The rate the scan's limiter actually enforces, not the configured pace.
		"rate_limit": effectiveRateLimit(opts),
		// Known-issue-scan builds its own limiter from the resolved phase pace, so
		// it is the one phase whose rate can legitimately differ from the above.
		"rate_limit_known_issue_scan": kisRateLimit,
		"max_per_host":                opts.MaxPerHost,
		"heuristics_check":            opts.HeuristicsCheck,
		"scope_origin_mode":           r.resolvedScopeOriginMode(),
		"active_modules":              activeCount,
		"passive_modules":             passiveCount,
		"hygiene_modules_off":         hygieneSuppressed,
		"spidering_enabled":           opts.SpideringEnabled,
		"discovery_enabled":           opts.DiscoverEnabled,
		"known_issue_scan_enabled":    opts.KnownIssueScanEnabled,
		"external_harvest":            opts.ExternalHarvestEnabled,
		"skip_dynamic":                opts.SkipDynamicAssessment,
	}
	return meta
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
