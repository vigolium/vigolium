package runner

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	corestats "github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/useragent"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	secret_detect "github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// maxFeedbackRounds limits re-scanning of newly discovered URLs in the dynamic-assessment phase.
const maxFeedbackRounds = 1

// kingfisherBatchSize is the number of records per batch when scanning response bodies for secrets.
const kingfisherBatchSize = 500

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	options           *types.Options
	settings          *config.Settings
	inputSource       source.InputSource
	dedupManager      *dedup.Manager
	repository        *database.Repository // Optional: database storage
	heuristicsResults map[string]*HeuristicsResult
	scanLogger        *database.ScanLogger // Optional: structured scan logging
	teeWriter         *teeWriter           // Optional: captures stderr for trace logging
	sessionLogFile    *os.File             // Optional: runtime.log handle for verbose file-only writes
	sessionLogMu      sync.Mutex           // serializes concurrent writes to sessionLogFile
	sharedInfra       *SharedInfra         // Optional: pre-built infrastructure for reuse across rescans

	ctx       context.Context       // cancellable context for graceful shutdown
	cancel    context.CancelFunc    // cancels ctx to signal workers to stop
	done      chan struct{}         // closed when RunNativeScan finishes
	pauseCtrl *core.PauseController // cooperative pause/resume for workers
}

// phaseInfra holds shared resources across all scan phases.
type phaseInfra struct {
	svc           *services.Services
	httpRequester *http.Requester
	scopeMatcher  *config.ScopeMatcher
	hostLimiter   *hostlimit.HostRateLimiter
	notifier      *notify.Manager
	hookChain     *jsext.HookChain
	jsEngine      *jsext.Engine
	scanUUID      string

	// Multi-session support for IDOR/BOLA testing
	compareSessions []compareSession
}

// compareSession pairs a named session with its dedicated HTTP requester.
type compareSession struct {
	Name     string
	Client   *http.Requester
	Hostname string // hostname this session is associated with (empty = all hosts)
}

// Close releases infrastructure resources.
func (p *phaseInfra) Close() {
	if p.hostLimiter != nil {
		_ = p.hostLimiter.Close()
	}
	if p.notifier != nil {
		p.notifier.Close()
	}
}

// SharedInfra holds reusable infrastructure components that can be shared across
// multiple scan runs (e.g., rescans in agent swarm mode). This avoids rebuilding
// expensive resources like HTTP requesters and scope matchers for each rescan.
type SharedInfra struct {
	HTTPRequester *http.Requester
	ScopeMatcher  *config.ScopeMatcher
	HostLimiter   *hostlimit.HostRateLimiter
	Services      *services.Services
	JSEngine      *jsext.Engine
	HookChain     *jsext.HookChain
}

// Close releases resources held by SharedInfra.
func (s *SharedInfra) Close() {
	if s.HostLimiter != nil {
		_ = s.HostLimiter.Close()
	}
}

// BuildSharedInfra creates a SharedInfra from the given options and settings.
// It extracts the reusable portions of buildInfrastructure.
func BuildSharedInfra(opts *types.Options, settings *config.Settings, repo *database.Repository) (*SharedInfra, error) {
	infra := &SharedInfra{}

	svc := &services.Services{
		Options: opts,
	}

	if opts.ShouldUseHostError() {
		cache := hosterrors.New(
			opts.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(opts.Verbose)
		svc.HostErrors = cache
	}

	maxPerHost := opts.MaxPerHost
	if settings != nil && !opts.MaxPerHostExplicitlySet && settings.ScanningPace.MaxPerHost > 0 {
		maxPerHost = settings.ScanningPace.MaxPerHost
	}
	if maxPerHost <= 0 {
		maxPerHost = 10
	}
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    maxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc.HostLimiter = hostLimiter
	infra.HostLimiter = hostLimiter
	infra.Services = svc

	var errs []error

	httpRequester, err := http.NewRequester(opts, svc)
	if err != nil {
		zap.L().Warn("Failed to create HTTP requester for SharedInfra", zap.Error(err))
		errs = append(errs, fmt.Errorf("could not create http requester: %w", err))
	} else {
		infra.HTTPRequester = httpRequester
	}

	if settings != nil {
		infra.ScopeMatcher = config.NewScopeMatcher(settings.Scope, opts.Targets...)
	}

	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   opts.ScanUUID,
			Repository: repo,
		}
		if settings != nil {
			scopeCfg := settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(settings.Scope, opts.Targets...)
		}
		jsEngine, jsErr := jsext.NewEngine(&settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if jsErr != nil {
			zap.L().Warn("Failed to initialize JS extensions for SharedInfra", zap.Error(jsErr))
			errs = append(errs, fmt.Errorf("could not create js engine: %w", jsErr))
		} else {
			infra.JSEngine = jsEngine
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.HookChain = jsext.NewHookChain(preHooks, postHooks)
			}
		}
	}

	if len(errs) > 0 {
		return infra, fmt.Errorf("partial SharedInfra (%d failures): %w", len(errs), stderrors.Join(errs...))
	}
	return infra, nil
}

// SetSharedInfra allows the runner to reuse pre-built infrastructure instead of building fresh.
func (r *Runner) SetSharedInfra(infra *SharedInfra) {
	r.sharedInfra = infra
}

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:               options.Targets,
		FilePath:              options.TargetsFilePath,
		Format:                options.InputFileMode,
		UseStdin:              options.Stdin,
		SkipFormatValidation:  options.SkipFormatValidation,
		FormatUseRequiredOnly: options.FormatUseRequiredOnly,
		BufferSize:            100,
		EnableModules:         options.Modules,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create input source")
	}

	// Configure OpenAPI options if using OpenAPI/Swagger format
	if options.InputFileMode == "openapi" || options.InputFileMode == "swagger" {
		if fs, ok := inputSource.(*source.FileSource); ok {
			if openapiFormat, ok := fs.Format().(*openapi.Format); ok {
				oaOpts := openapi.Options{
					BaseURL:              options.OpenAPIBaseURL,
					UseSpecServers:       options.OpenAPIUseSpecServers,
					Headers:              parseHeaders(options.SpecHeaders),
					Variables:            parseVariables(options.OpenAPIVariables),
					DefaultFallbackValue: options.OpenAPIDefaultParam,
				}

				// Load field type defaults from config
				if cfg, err := config.LoadSettings(options.ConfigPath); err == nil {
					oaOpts.FieldTypeDefaults = cfg.MutationStrategy.FieldTypeDefaults.ToMap()
				}

				openapiFormat.SetOpenAPIOptions(oaOpts)
			}
		}
	}

	return NewWithInputSource(options, inputSource)
}

// parseHeaders parses header strings in "Name: Value" format.
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// parseVariables parses variable strings in "key=value" format.
func parseVariables(variables []string) map[string]string {
	result := make(map[string]string)
	for _, v := range variables {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// NewWithInputSource creates a new Runner with a custom InputSource.
// Used by server mode to provide queue-based input.
func NewWithInputSource(options *types.Options, inputSource source.InputSource) (*Runner, error) {
	if err := network.Init(options); err != nil {
		return nil, errors.Wrap(err, "failed to initialize network")
	}

	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}

	setupUserAgents()

	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		options:      options,
		inputSource:  inputSource,
		output:       outputWriter,
		dedupManager: dedup.NewManager(),
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		pauseCtrl:    core.NewPauseController(),
	}, nil
}

// setupUserAgents initializes global user agents for HTTP requests.
func setupUserAgents() {
	filters := []useragent.Filter{useragent.Windows}
	userAgents, err := useragent.PickWithFilters(30, filters...)
	if err != nil {
		zap.L().Error("Error picking user agent", zap.Error(err))
		userAgents = []*useragent.UserAgent{
			{
				Raw:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
				Tags: []string{"Chrome"},
			},
		}
	}
	useragent.UserAgents = userAgents
}

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

// getInScopeDBHostnamesList returns the list of hostnames from the database that are
// in scope according to the CLI targets and origin mode. When no targets are configured,
// returns nil (meaning no hostname filter — all records are included).
func (r *Runner) getInScopeDBHostnamesList(ctx context.Context) []string {
	if len(r.options.Targets) == 0 || r.repository == nil {
		return nil
	}

	// Build a scope matcher from current settings and CLI targets
	var scopeMatcher *config.ScopeMatcher
	if r.settings != nil {
		scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
	}

	hosts, err := r.repository.GetDistinctHosts(ctx, r.options.ProjectUUID)
	if err != nil {
		return nil
	}

	var hostnames []string
	seen := make(map[string]struct{})
	for _, h := range hosts {
		if _, exists := seen[h.Hostname]; exists {
			continue
		}
		seen[h.Hostname] = struct{}{}

		if scopeMatcher != nil && !scopeMatcher.InScopeRequest(h.Hostname, "/", "", "") {
			continue
		}
		hostnames = append(hostnames, h.Hostname)
	}

	return hostnames
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

// deduplicateFindings runs finding deduplication and prints feedback if any were removed.
func (r *Runner) deduplicateFindings(ctx context.Context, phase string) {
	if r.repository == nil {
		return
	}
	deleted, grouped, err := r.repository.DeduplicateFindings(ctx, r.options.ProjectUUID)
	if err != nil {
		zap.L().Warn("Finding deduplication failed", zap.String("phase", phase), zap.Error(err))
	} else if deleted > 0 {
		r.printPhaseFeedback(phase, fmt.Sprintf("grouped %s findings into %s (deduplicated %s redundant findings with identical module/URL)",
			terminal.Orange(fmt.Sprintf("%d", deleted+grouped)),
			terminal.Orange(fmt.Sprintf("%d", grouped)),
			terminal.Orange(fmt.Sprintf("%d", deleted))))
		r.scanLogger.Info(phase, fmt.Sprintf("grouped %d findings into %d (%d duplicates merged)", deleted+grouped, grouped, deleted))
	}
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

// RunNativeScan orchestrates the native scan plan:
//
//	HeuristicsCheck   — optional root-page probe to optimize downstream phase selection
//	ExternalHarvest   — harvest URLs from external intelligence sources (opt-in)
//	Spidering         — browser-based crawling (opt-in)
//	Discovery         — ingest all input + deparos content discovery into DB (no modules)
//	Seed              — ingest CLI targets when discovery is skipped but DB-backed phases still need records
//	KnownIssueScan    — nuclei + kingfisher batch (opt-in via --known-issue-scan)
//	DynamicAssessment — modules + extensions scan DB records
//
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

func (r *Runner) RunNativeScan() error {
	defer close(r.done)
	ctx := r.ctx

	infra, err := r.buildInfrastructure()
	if err != nil {
		return err
	}
	defer infra.Close()

	// Initialize scan logger (must happen before printScanConfig so the tee captures it)
	r.scanLogger = database.NewScanLogger(r.repository, infra.scanUUID)
	r.scanLogger.StartBatcher()
	defer r.scanLogger.Close()

	// Create scan record in the database so every scan is tracked with its lifecycle.
	// Skip when ScanOnReceive — the server already created the scan record.
	if r.repository != nil && !r.options.ScanOnReceive {
		target := strings.Join(r.options.Targets, ", ")
		scan := &database.Scan{
			UUID:        infra.scanUUID,
			ProjectUUID: r.options.ProjectUUID,
			Name:        "cli-scan",
			Status:      "running",
			Target:      target,
			Threads:     r.options.Concurrency,
			ScanSource:  "cli",
			ScanMode:    "full",
			StartedAt:   time.Now(),
		}
		if err := r.repository.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}
	if r.repository != nil {
		defer func() {
			var errMsg string
			if r.ctx.Err() != nil {
				errMsg = "cancelled"
			}
			if completeErr := r.repository.CompleteScan(ctx, infra.scanUUID, errMsg); completeErr != nil {
				zap.L().Warn("Failed to complete scan record", zap.Error(completeErr))
			}
		}()
	}

	// Set up TeeWriter to capture raw stderr output as trace-level scan logs.
	if r.repository != nil {
		origStderr := os.Stderr
		// Optionally mirror raw console output to ~/.vigolium/native-sessions/{uuid}/run.log.
		var sessionLogFile *os.File
		var teeInner io.Writer = origStderr
		if r.settings != nil && r.settings.ScanningStrategy.ScanLogs.IsPersistLogsEnabled() {
			sessionDir := filepath.Join(r.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), infra.scanUUID)
			if mkErr := os.MkdirAll(sessionDir, 0o755); mkErr == nil {
				logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
				if f, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); openErr == nil {
					sessionLogFile = f
					r.sessionLogFile = f
					teeInner = io.MultiWriter(origStderr, sessionLogFile)
				} else {
					zap.L().Warn("Failed to open native session log file", zap.String("path", logPath), zap.Error(openErr))
				}
			} else {
				zap.L().Warn("Failed to create native session directory", zap.String("path", sessionDir), zap.Error(mkErr))
			}
		}
		r.teeWriter = newTeeWriter(teeInner, r.scanLogger)
		pr, pw, err := os.Pipe()
		if err == nil {
			os.Stderr = pw
			// Goroutine reads from the pipe and writes through the tee.
			go func() {
				buf := make([]byte, 4096)
				for {
					n, readErr := pr.Read(buf)
					if n > 0 {
						_, _ = r.teeWriter.Write(buf[:n])
					}
					if readErr != nil {
						break
					}
				}
			}()
			defer func() {
				_ = pw.Close()
				// Allow goroutine to drain.
				time.Sleep(50 * time.Millisecond)
				_ = pr.Close()
				os.Stderr = origStderr
				r.teeWriter.Flush()
				if sessionLogFile != nil {
					r.sessionLogMu.Lock()
					r.sessionLogFile = nil
					r.sessionLogMu.Unlock()
					_ = sessionLogFile.Close()
				}
			}()
		} else if sessionLogFile != nil {
			// Pipe setup failed; still close the log file we opened.
			defer func() { _ = sessionLogFile.Close() }()
		}
	}

	// Print scan configuration summary
	r.printScanConfig()

	r.scanLogger.Info("", "scan started")

	// Log scan configuration snapshot as structured metadata.
	r.logConfigSnapshot()

	// Banner the scan lifecycle on stderr so operators see at a glance when
	// scanning kicks off and wraps up. Suppressed by --silent; defers to the
	// printScanConfig banner above for CLI runs (which already shows targets),
	// so this marker is most useful for scan-on-receive where the server is
	// otherwise quiet between 2-minute status ticks.
	scanStartedAt := time.Now()
	if !r.options.Silent {
		target := strings.Join(r.options.Targets, ", ")
		if target == "" {
			target = "(continuous, awaiting ingested records)"
		}
		fmt.Fprintf(os.Stderr, "  %s Scan started %s %s\n",
			terminal.Green(terminal.SymbolStart),
			terminal.BoldCyan(infra.scanUUID),
			terminal.Gray("target: "+target))
		defer func() {
			duration := time.Since(scanStartedAt)
			findingSummary := ""
			if r.repository != nil {
				if scan, err := r.repository.GetScanByUUID(context.Background(), infra.scanUUID); err == nil && scan != nil {
					findingSummary = fmt.Sprintf(", findings: %d", scan.TotalFindings)
				}
			}
			fmt.Fprintf(os.Stderr, "  %s Scan finished %s %s\n",
				terminal.SuccessSymbol(),
				terminal.BoldCyan(infra.scanUUID),
				terminal.Gray(fmt.Sprintf("duration: %s%s", fmtDuration(duration), findingSummary)))
		}()
	}

	// Panic recovery with notification
	defer func() {
		if rec := recover(); rec != nil {
			stack := make([]byte, 4096)
			length := goruntime.Stack(stack, false)
			stackTrace := string(stack[:length])

			errorMessage := fmt.Sprintf(
				"Recovered from panic in runner execution: %+v\nStack Trace:\n%s",
				rec,
				stackTrace,
			)
			zap.L().Error(errorMessage)
			r.scanLogger.Error("", "panic recovered: "+fmt.Sprintf("%+v", rec))
			if infra.notifier != nil {
				_ = infra.notifier.SendRaw(errorMessage)
			}
		}
	}()

	plan := BuildNativeScanPlan(r.options)

	// Full-scan-on-receive: loop waiting for new records, then run all phases
	// on just the new batch. Each iteration swaps r.inputSource to a one-shot
	// DB source so Discovery processes only newly arrived records.
	if r.options.FullNativeScanOnReceive && r.repository != nil {
		for ctx.Err() == nil {
			if err := r.waitForNewRecords(ctx, infra.scanUUID, 2*time.Second); err != nil {
				break
			}
			r.inputSource = database.NewOneShotDBInputSource(r.repository.DB(), r.repository, infra.scanUUID)
			for _, step := range plan.Steps {
				if !step.Enabled {
					continue
				}
				if ctx.Err() != nil {
					break
				}
				if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
					zap.L().Error("Full-scan-on-receive: phase error", zap.Error(err))
					break
				}
			}
		}
		r.scanLogger.Info("", "scan finished")
		return nil
	}

	for _, step := range plan.Steps {
		if !step.Enabled {
			continue
		}
		if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
			return err
		}
	}
	if r.options.SkipIngestion && !r.options.KnownIssueScanEnabled && r.options.SkipDynamicAssessment {
		zap.L().Info("Discovery skipped, no downstream phases need DB records")
		r.scanLogger.Info("discovery", "skipped, no downstream phases need DB records")
	}
	if r.options.SkipDynamicAssessment {
		zap.L().Info("Dynamic-assessment skipped by scanning strategy")
		r.scanLogger.Info("dynamic-assessment", "skipped by scanning strategy")
	}

	r.scanLogger.Info("", "scan finished")
	return nil
}

func (r *Runner) executeNativePhase(ctx context.Context, infra *phaseInfra, phase NativePhase) error {
	switch phase {
	case PhaseHeuristicsCheck:
		r.setPhaseTag("heuristics")
		r.scanLogger.Info("heuristics", "phase started")
		results, err := r.runHeuristicsCheckPhase(ctx, infra)
		if err != nil {
			zap.L().Error("HeuristicsCheck phase failed", zap.Error(err))
			r.scanLogger.Error("heuristics", "phase failed: "+err.Error())
		} else {
			r.heuristicsResults = results
			r.scanLogger.Info("heuristics", "phase completed")
		}
	case PhaseExternalHarvest:
		r.setPhaseTag("harvest")
		r.scanLogger.Info("harvest", "phase started")
		if err := r.runExternalHarvestPhase(ctx, infra); err != nil {
			zap.L().Error("ExternalHarvest phase failed", zap.Error(err))
			r.scanLogger.Error("harvest", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("harvest", "phase completed")
		}
	case PhaseSpidering:
		r.setPhaseTag("spider")
		r.scanLogger.Info("spidering", "phase started")
		if err := r.runSpideringPhase(ctx, infra); err != nil {
			zap.L().Error("Spidering phase failed", zap.Error(err))
			r.scanLogger.Error("spidering", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("spidering", "phase completed")
		}
	case PhaseDiscovery:
		r.setPhaseTag("discovery")
		r.scanLogger.Info("discovery", "phase started")
		if err := r.runDiscoveryPhase(ctx, infra); err != nil {
			r.scanLogger.Error("discovery", "phase failed: "+err.Error())
			return fmt.Errorf("discovery phase failed: %w", err)
		}
		r.scanLogger.Info("discovery", "phase completed")
		if r.repository != nil {
			softDeleted, statusCodes, softErr := r.repository.DeduplicateSoftDeparosRecords(ctx, r.options.ProjectUUID)
			if softErr != nil {
				zap.L().Warn("Deparos soft deduplication failed", zap.Error(softErr))
			} else if softDeleted > 0 {
				detail := fmt.Sprintf("soft-deduplicated %s similar records",
					terminal.Orange(fmt.Sprintf("%d", softDeleted)))
				if len(statusCodes) > 0 {
					detail += " — " + formatStatusCodeMap(statusCodes)
				}
				r.printPhaseFeedback("Discovery", detail)
				r.scanLogger.Info("discovery", fmt.Sprintf("soft-deduplicated %d similar records", softDeleted))
			}
		}
	case PhaseSeed:
		r.setPhaseTag("seed")
		r.scanLogger.Info("seed", "seeding CLI targets")
		if err := r.seedCLITargets(ctx, infra); err != nil {
			r.scanLogger.Error("seed", "CLI target seeding failed: "+err.Error())
			return fmt.Errorf("CLI target seeding failed: %w", err)
		}
		r.scanLogger.Info("seed", "seeding completed")
	case PhaseKnownIssueScan:
		r.setPhaseTag("known-issue-scan")
		r.scanLogger.Info("known-issue-scan", "phase started")
		if err := r.runKnownIssueScanPhase(ctx, infra); err != nil {
			zap.L().Error("KnownIssueScan phase failed", zap.Error(err))
			r.scanLogger.Error("known-issue-scan", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("known-issue-scan", "phase completed")
			r.deduplicateFindings(ctx, "KnownIssueScan")
		}
	case PhaseDynamicAssessment:
		r.setPhaseTag("dynamic-assessment")
		activeModules, passiveModules := r.resolveAllModules(infra)
		if len(activeModules) > 0 || len(passiveModules) > 0 {
			r.scanLogger.InfoWithMeta("dynamic-assessment", "phase started", map[string]interface{}{
				"active_modules":  len(activeModules),
				"passive_modules": len(passiveModules),
			})
			if err := r.runDynamicAssessmentPhase(ctx, infra, activeModules, passiveModules); err != nil {
				zap.L().Error("Dynamic-assessment phase failed", zap.Error(err))
				r.scanLogger.Error("dynamic-assessment", "phase failed: "+err.Error())
			} else {
				r.scanLogger.Info("dynamic-assessment", "phase completed")
			}
		} else {
			zap.L().Info("No modules to execute")
			r.scanLogger.Info("dynamic-assessment", "skipped, no modules to execute")
		}
	}
	return nil
}

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
func (r *Runner) buildInfrastructure() (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-uuid
	scanUUID := r.options.ScanUUID
	if scanUUID == "" {
		scanUUID = uuid.New().String()
		r.options.ScanUUID = scanUUID
	}

	infra := &phaseInfra{
		scanUUID: scanUUID,
	}

	// If SharedInfra is available, reuse its components instead of building fresh
	if r.sharedInfra != nil {
		infra.httpRequester = r.sharedInfra.HTTPRequester
		infra.scopeMatcher = r.sharedInfra.ScopeMatcher
		infra.hostLimiter = r.sharedInfra.HostLimiter
		infra.svc = r.sharedInfra.Services
		infra.jsEngine = r.sharedInfra.JSEngine
		infra.hookChain = r.sharedInfra.HookChain
		// Still need to initialize sessions
		if err := r.initSessions(infra); err != nil {
			if len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0 {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			zap.L().Warn("Failed to initialize sessions", zap.Error(err))
		}
		return infra, nil
	}

	// Create notifier with backends. Each backend is gated by the
	// notify.provider selector — empty means "all", a specific value
	// activates only that channel.
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend
		notifyCfg := &r.settings.Notify

		// Telegram backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderTelegram) {
			tgOpts := r.buildTelegramOptions()
			if tg, err := telegram.NewBackend(tgOpts...); err == nil {
				backends = append(backends, tg)
				zap.L().Info("[Notify] Telegram backend enabled")
			}
		}

		// Discord backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderDiscord) {
			webhookURL := notifyCfg.Discord.WebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
			}
			if webhookURL != "" {
				if dc, err := discord.NewBackend(webhookURL); err == nil {
					backends = append(backends, dc)
					zap.L().Info("[Notify] Discord backend enabled")
				} else {
					zap.L().Warn("[Notify] Failed to create Discord backend", zap.Error(err))
				}
			}
		}

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: notifyCfg.Severities,
			})
		}
	}

	// Create runtime services
	svc := &services.Services{
		Options:      r.options,
		Notifier:     infra.notifier,
		DedupManager: r.dedupManager,
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrors.New(
			r.options.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(r.options.Verbose)
		svc.HostErrors = cache
	}

	// Create HostLimiter for per-host concurrency control
	maxPerHost := r.options.MaxPerHost
	if r.settings != nil && !r.options.MaxPerHostExplicitlySet && r.settings.ScanningPace.MaxPerHost > 0 {
		maxPerHost = r.settings.ScanningPace.MaxPerHost
	}
	if maxPerHost <= 0 {
		maxPerHost = 10
	}
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    maxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc.HostLimiter = hostLimiter
	infra.hostLimiter = hostLimiter
	infra.svc = svc

	httpRequester, err := http.NewRequester(r.options, svc)
	if err != nil {
		infra.Close()
		return nil, errors.Wrap(err, "could not create http requester")
	}
	infra.httpRequester = httpRequester

	// Create scope matcher from settings, passing CLI targets for cli_origin_mode filtering
	if r.settings != nil {
		infra.scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
	}

	// Initialize JS extension engine
	if r.settings != nil && r.settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   r.options.ScanUUID,
			Repository: r.repository,
		}
		if r.settings != nil {
			scopeCfg := r.settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
		}
		jsEngine, err := jsext.NewEngine(&r.settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if err != nil {
			zap.L().Warn("Failed to initialize JS extensions", zap.Error(err))
		} else {
			// Create hook chain if hooks are defined
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.hookChain = jsext.NewHookChain(preHooks, postHooks)
				zap.L().Info("JS hooks loaded",
					zap.Int("pre_hooks", len(preHooks)),
					zap.Int("post_hooks", len(postHooks)))
			}
			// Store the engine in infra for module resolution
			infra.jsEngine = jsEngine
		}
	}

	// Initialize multi-session support for IDOR/BOLA testing
	if err := r.initSessions(infra); err != nil {
		// If the user explicitly configured sessions, surface the error clearly
		hasCLIAuth := len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0
		if hasCLIAuth && !r.options.AuthBestEffort {
			return nil, fmt.Errorf("session initialization failed: %w", err)
		}
		zap.L().Warn("Failed to initialize sessions, continuing without session support", zap.Error(err))
	}

	return infra, nil
}

// initSessions loads, validates, hydrates sessions and creates compare requesters.
// Sources (in priority order): --auth-file/--auth flags → DB authentication_hostnames fallback.
func (r *Runner) initSessions(infra *phaseInfra) error {
	opts := r.options
	sessionCfg := r.settings.ScanningStrategy.Session
	hasCLISessions := len(opts.AuthFiles) > 0 || len(opts.AuthInline) > 0

	var sessions []*authentication.Session
	var sessionHostnameMap map[string]string // session name → hostname (from DB)
	fromDB := false

	if hasCLISessions {
		if len(opts.AuthFiles) > 0 {
			loaded, err := authentication.LoadFromAuthFiles(opts.AuthFiles, sessionCfg.SessionDir)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
		if len(opts.AuthInline) > 0 {
			loaded, err := authentication.LoadFromAuthInline(opts.AuthInline)
			if err != nil {
				return err
			}
			sessions = append(sessions, loaded...)
		}
	} else {
		// Fallback: load from DB authentication_hostnames for this project's target hostnames
		sessions, sessionHostnameMap, fromDB = r.loadSessionsFromDB()
		if len(sessions) == 0 {
			return nil
		}
	}

	mgr, err := authentication.NewManager(sessions, authentication.WithSessionDir(sessionCfg.SessionDir))
	if err != nil {
		return err
	}

	// Execute login flows (re-hydrate DB sessions to refresh potentially stale tokens)
	if err := mgr.HydrateSessions(); err != nil {
		return fmt.Errorf("session hydration failed: %w", err)
	}

	// Persist CLI sessions to DB for reuse in future scans
	if hasCLISessions {
		r.persistSessionsToDB(mgr.AllSessions())
	}

	// Merge primary session headers into the main requester's options.
	// When use_in_discovery is false, primary headers are only applied to the
	// dynamic-assessment phase requester (handled downstream), not the main one used
	// for discovery and spidering.
	primaryHeaders := mgr.PrimaryHeaders()
	if len(primaryHeaders) > 0 && sessionCfg.UseInDiscovery {
		opts.Headers = append(opts.Headers, primaryHeaders...)
		// Rebuild the main requester with updated headers
		httpRequester, err := http.NewRequester(opts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to rebuild requester with session headers: %w", err)
		}
		infra.httpRequester = httpRequester
	}

	// Create separate requesters for compare sessions (IDOR/BOLA testing)
	if !sessionCfg.CompareEnabled {
		zap.L().Info("Multi-session scanning enabled (compare disabled by config)",
			zap.String("primary", mgr.Primary().Name))
		return nil
	}

	cmpSessions := mgr.CompareSessions()
	if len(cmpSessions) == 0 {
		return nil
	}

	for _, cs := range cmpSessions {
		// Clone options, merge global headers with session-specific auth headers
		compareOpts := *opts
		compareOpts.Headers = append(append([]string{}, opts.Headers...), cs.HeaderSlice()...)
		compareRequester, err := http.NewRequester(&compareOpts, infra.svc)
		if err != nil {
			return fmt.Errorf("failed to create requester for session %q: %w", cs.Name, err)
		}
		cmpEntry := compareSession{
			Name:   cs.Name,
			Client: compareRequester,
		}
		// Preserve per-hostname association from DB sessions
		if sessionHostnameMap != nil {
			cmpEntry.Hostname = sessionHostnameMap[cs.Name]
		}
		infra.compareSessions = append(infra.compareSessions, cmpEntry)
	}

	sourceLabel := "CLI"
	if fromDB {
		sourceLabel = "DB"
	}
	zap.L().Info("Multi-session scanning enabled",
		zap.String("source", sourceLabel),
		zap.String("primary", mgr.Primary().Name),
		zap.Int("compare_sessions", len(cmpSessions)))

	return nil
}

// loadSessionsFromDB loads sessions from the authentication_hostnames table for target hostnames.
// Returns the loaded sessions, a map of session name → hostname for per-host filtering,
// and true if sessions were loaded from DB.
func (r *Runner) loadSessionsFromDB() ([]*authentication.Session, map[string]string, bool) {
	if r.repository == nil || r.options.ProjectUUID == "" {
		return nil, nil, false
	}

	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Extract hostnames from CLI targets
	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		// No specific targets — try loading all project sessions
		rows, err := r.repository.GetAuthenticationHostnamesByProject(ctx, r.options.ProjectUUID)
		if err != nil || len(rows) == 0 {
			return nil, nil, false
		}
		cfg := database.AuthenticationHostnamesToSessionConfig(rows)
		if cfg == nil || len(cfg.Sessions) == 0 {
			return nil, nil, false
		}
		sessions := make([]*authentication.Session, len(cfg.Sessions))
		hostnameMap := make(map[string]string, len(rows))
		for i := range cfg.Sessions {
			sessions[i] = &cfg.Sessions[i]
		}
		for _, row := range rows {
			hostnameMap[row.SessionName] = row.Hostname
		}
		zap.L().Info("Loaded sessions from DB (project-wide)",
			zap.Int("sessions", len(sessions)))
		return sessions, hostnameMap, true
	}

	// Query authentication_hostnames for each target hostname, deduplicate by session name+hostname
	seen := make(map[string]bool)
	hostnameMap := make(map[string]string)
	var sessions []*authentication.Session
	for _, hostname := range hostnames {
		rows, err := r.repository.GetAuthenticationHostnamesByHostname(ctx, r.options.ProjectUUID, hostname)
		if err != nil || len(rows) == 0 {
			continue
		}
		for _, row := range rows {
			key := row.SessionName + ":" + row.Hostname
			if seen[key] {
				continue
			}
			seen[key] = true
			s := database.AuthenticationHostnameToSession(row)
			if s != nil {
				sessions = append(sessions, s)
				hostnameMap[s.Name] = row.Hostname
			}
		}
	}

	if len(sessions) > 0 {
		zap.L().Info("Loaded sessions from DB (authentication_hostnames)",
			zap.Int("sessions", len(sessions)),
			zap.Strings("hostnames", hostnames))
	}
	return sessions, hostnameMap, len(sessions) > 0
}

// persistSessionsToDB saves hydrated CLI sessions to authentication_hostnames for future reuse.
func (r *Runner) persistSessionsToDB(sessions []*authentication.Session) {
	if r.repository == nil || r.options.ProjectUUID == "" || len(sessions) == 0 {
		return
	}

	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	hostnames := r.targetHostnames()
	if len(hostnames) == 0 {
		return
	}

	for _, hostname := range hostnames {
		rows := database.SessionsToAuthenticationHostnames(sessions, r.options.ProjectUUID, hostname)
		if len(rows) == 0 {
			continue
		}
		if err := r.repository.SaveAuthenticationHostnames(ctx, rows); err != nil {
			zap.L().Debug("Failed to persist sessions to DB",
				zap.String("hostname", hostname), zap.Error(err))
		}
	}

	zap.L().Info("Persisted CLI sessions to authentication_hostnames",
		zap.Int("sessions", len(sessions)),
		zap.Strings("hostnames", hostnames))
}

// targetHostnames extracts unique host:port values from CLI targets.
// Includes the port when explicitly present (e.g. "localhost:3005"),
// bare hostname otherwise (e.g. "example.com").
func (r *Runner) targetHostnames() []string {
	if len(r.options.Targets) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(r.options.Targets))
	var hostnames []string
	for _, t := range r.options.Targets {
		u, err := neturl.Parse(t)
		if err != nil || u.Host == "" {
			continue
		}
		h := u.Host
		if !seen[h] {
			seen[h] = true
			hostnames = append(hostnames, h)
		}
	}
	return hostnames
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
// runKnownIssueScanPhase orchestrates nuclei + kingfisher batch scanning.
func (r *Runner) runKnownIssueScanPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("KnownIssueScan", "assess security posture with Nuclei templates and third-party validation checks")
	if r.settings != nil {
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		if knownIssueScanPace.MaxDuration > 0 || knownIssueScanPace.DurationFactor > 0 {
			detail := "Speed:"
			if knownIssueScanPace.MaxDuration > 0 {
				detail += fmt.Sprintf(" max-duration=%s", terminal.HiTeal(knownIssueScanPace.MaxDuration.String()))
			}
			if knownIssueScanPace.DurationFactor > 0 {
				detail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", knownIssueScanPace.DurationFactor)))
			}
			r.printPhaseDetail(detail)
		}
	}
	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}
	if !enrichTargets && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	if r.repository != nil && r.options.Verbose {
		paths, _ := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
		if len(paths) > 0 {
			var knownIssueScanTargets []string
			if enrichTargets {
				knownIssueScanTargets = buildKnownIssueScanTargetsFromPaths(paths)
			} else {
				knownIssueScanTargets = buildKnownIssueScanHostTargets(paths)
			}
			r.printVerboseTargets(knownIssueScanTargets)
		}
	}
	zap.L().Info("KnownIssueScan: running security posture assessment")

	// Track findings by severity
	var mu sync.Mutex
	counts := make(map[severity.Severity]int)

	onResult := func(result *output.ResultEvent) {
		mu.Lock()
		counts[result.Info.Severity]++
		mu.Unlock()

		if err := r.output.Write(result); err != nil {
			zap.L().Error("KnownIssueScan: failed to write result", zap.Error(err))
		}
	}

	// Nuclei scan on distinct hosts
	if err := r.runKnownIssueScan(ctx, onResult); err != nil {
		zap.L().Error("KnownIssueScan: Nuclei scan failed", zap.Error(err))
	}

	// Kingfisher batch scan on all response bodies
	if err := r.runKingfisherBatch(ctx, infra, onResult); err != nil {
		zap.L().Error("KnownIssueScan: Kingfisher batch failed", zap.Error(err))
	}

	// Print summary
	var total int
	for _, c := range counts {
		total += c
	}
	if total > 0 {
		r.printPhaseDetail(formatKnownIssueScanSummary(counts, total))
	}

	// Increment processed_count for KnownIssueScan phase
	if r.repository != nil && total > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(total)); err != nil {
			zap.L().Warn("KnownIssueScan: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("KnownIssueScan", fmt.Sprintf("completed in %s", terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// formatKnownIssueScanSummary builds a compact severity breakdown string for KnownIssueScan findings.
func formatKnownIssueScanSummary(counts map[severity.Severity]int, total int) string {
	var parts []string
	for _, s := range []severity.Severity{
		severity.Critical, severity.High, severity.Medium, severity.Low, severity.Info,
	} {
		if c, ok := counts[s]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s %s", terminal.Orange(fmt.Sprintf("%d", c)), s.String()))
		}
	}
	return fmt.Sprintf("found %s findings — %s", terminal.Orange(fmt.Sprintf("%d", total)), strings.Join(parts, ", "))
}

// runKingfisherBatch scans all response bodies in the database for secrets using Kingfisher.
func (r *Runner) runKingfisherBatch(ctx context.Context, infra *phaseInfra, onResult func(*output.ResultEvent)) error {
	if r.repository == nil {
		return fmt.Errorf("kingfisher batch: database repository required")
	}

	scanner, err := kingfisher.NewScanner(nil)
	if err != nil {
		return fmt.Errorf("kingfisher batch: failed to create scanner: %w", err)
	}
	if err := scanner.EnsureBinary(ctx); err != nil {
		return fmt.Errorf("kingfisher batch: binary unavailable: %w", err)
	}

	zap.L().Info("KnownIssueScan: Kingfisher batch — scanning response bodies for secrets")

	var cursor string
	var totalFindings int
	for {
		records, err := r.repository.GetRecordsWithResponseBody(ctx, r.options.ProjectUUID, cursor, kingfisherBatchSize)
		if err != nil {
			return fmt.Errorf("kingfisher batch: failed to fetch records: %w", err)
		}
		if len(records) == 0 {
			break
		}

		for _, record := range records {
			cursor = record.UUID

			// Filter by content type (reuse IsTextBasedMIME from secret_detect)
			if !secret_detect.IsTextBasedMIME(record.ResponseContentType) {
				continue
			}

			result, scanErr := scanner.Scan(ctx, record.ResponseBodyBytes())
			if scanErr != nil || !result.HasFindings() {
				continue
			}

			for i := range result.Findings {
				f := &result.Findings[i]

				sev := severity.High
				conf := severity.Firm
				if f.IsValidated() {
					sev = severity.Critical
					conf = severity.Certain
				}

				event := &output.ResultEvent{
					ModuleID: "",
					Info: output.Info{
						Name:        f.RuleName(),
						Description: "Leaked secret detected: " + f.RuleID(),
						Severity:    sev,
						Confidence:  conf,
						Tags:        []string{"secret", "credential", "exposure", "known-issue-scan"},
					},
					Host:             record.Hostname,
					URL:              record.URL,
					Matched:          record.URL,
					ExtractedResults: []string{secret_detect.RedactSnippet(f.Snippet())},
					Metadata: map[string]any{
						"rule_id":   f.RuleID(),
						"rule_name": f.RuleName(),
						"validated": f.IsValidated(),
					},
					ModuleType:    database.ModuleTypeSecretScan,
					FindingSource: database.FindingSourceKnownIssueScan,
					ModuleShort:   "Leaked secret detected in HTTP response body",
				}

				// Save to DB
				if saveErr := r.repository.SaveFinding(ctx, event, []string{record.UUID}, infra.scanUUID, r.options.ProjectUUID); saveErr != nil {
					zap.L().Debug("Failed to save kingfisher finding", zap.Error(saveErr))
				}

				// Write to output via callback
				if onResult != nil {
					onResult(event)
				}
				totalFindings++
			}
		}

		if len(records) < kingfisherBatchSize {
			break
		}
	}

	zap.L().Info("KnownIssueScan: Kingfisher batch completed", zap.Int("findings", totalFindings))
	return nil
}

// runDynamicAssessmentPhase runs all modules on DB records with a feedback loop for newly discovered URLs.
func (r *Runner) runDynamicAssessmentPhase(ctx context.Context, infra *phaseInfra, activeModules []modules.ActiveModule, passiveModules []modules.PassiveModule) error {
	phaseStart := time.Now()

	if r.repository == nil {
		return fmt.Errorf("dynamic-assessment: database repository required")
	}

	r.printPhaseStart("DynamicAssessment", "execute dynamic security assessments through coordinated active and passive scanning modules")
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", len(activeModules))),
		terminal.Orange(fmt.Sprintf("%d", len(passiveModules))))
	if infra.jsEngine != nil {
		jsActive := len(infra.jsEngine.ActiveModules())
		jsPassive := len(infra.jsEngine.PassiveModules())
		if jsActive+jsPassive > 0 {
			modulesLine += fmt.Sprintf(" (incl. %s extensions)",
				terminal.HiTeal(fmt.Sprintf("%d", jsActive+jsPassive)))
		}
	}
	r.printPhaseDetail(modulesLine)

	daSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		if daPace.MaxDuration > 0 {
			daSpeedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(daPace.MaxDuration.String()))
		}
		if daPace.DurationFactor > 0 {
			daSpeedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", daPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(daSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))

	// Resolve feedback rounds early so we can show it in the phase header
	feedbackRounds := maxFeedbackRounds
	if r.settings != nil && r.settings.DynamicAssessment.MaxFeedbackRounds > 0 {
		feedbackRounds = r.settings.DynamicAssessment.MaxFeedbackRounds
	}
	r.printPhaseDetail(fmt.Sprintf("Feedback rounds: %s", terminal.HiBlue(fmt.Sprintf("%d", feedbackRounds))))
	if feedbackRounds <= 1 && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("increase feedback rounds to re-scan newly discovered URLs via"), terminal.HiCyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
	}

	zap.L().Info("DynamicAssessment: running modules on database records",
		zap.Int("active", len(activeModules)),
		zap.Int("passive", len(passiveModules)))

	// Log quarantined hosts from prior phases so users see cross-phase propagation
	if infra.svc != nil && infra.svc.HostErrors != nil {
		if qc := infra.svc.HostErrors.QuarantinedCount(); qc > 0 {
			zap.L().Info("DynamicAssessment: carrying forward host errors from prior phases",
				zap.Int("quarantined_hosts", qc))
		}
	}

	// If KnownIssueScan was enabled, filter out secret-detect to avoid duplicate kingfisher findings
	if r.options.KnownIssueScanEnabled {
		passiveModules = filterOutPassiveModule(passiveModules, secret_detect.ModuleID)
	}

	// Wire compare session clients into the authz-compare module
	if len(infra.compareSessions) > 0 {
		clients := make([]*http.Requester, len(infra.compareSessions))
		names := make([]string, len(infra.compareSessions))
		hostnames := make([]string, len(infra.compareSessions))
		for i, cs := range infra.compareSessions {
			clients[i] = cs.Client
			names[i] = cs.Name
			hostnames[i] = cs.Hostname
		}
		for _, mod := range activeModules {
			if ac, ok := mod.(*authz_compare.Module); ok {
				ac.SetCompareClients(clients, names, hostnames)
				break
			}
		}
	}

	// Update the top-level scan record with module info for cursor tracking.
	// The scan record was already created at the start of RunNativeScan().
	if _, err := r.repository.DB().NewUpdate().
		Model((*database.Scan)(nil)).
		Set("modules = ?", r.buildModulesString(activeModules, passiveModules)).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", infra.scanUUID).
		Exec(ctx); err != nil {
		zap.L().Warn("Failed to update scan modules", zap.Error(err))
	}

	// Resolve dynamic-assessment concurrency: scanning_pace.dynamic-assessment overrides global when CLI not explicit
	daConcurrency := r.options.Concurrency
	if r.settings != nil && !r.options.ConcurrencyExplicitlySet {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		if daPace.Concurrency > 0 {
			daConcurrency = daPace.Concurrency
		}
	}

	// Initialize OAST service if enabled
	var oastService *oast.Service
	if r.settings != nil && r.settings.OAST.Enabled {
		onOASTResult := func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write OAST result", zap.Error(err))
			}
		}
		var err error
		oastService, err = oast.New(&r.settings.OAST, onOASTResult, r.repository, infra.scanUUID, r.options.ProjectUUID, nil)
		if err != nil {
			zap.L().Warn("DynamicAssessment: OAST initialization failed, continuing without OAST", zap.Error(err))
		}
		if oastService != nil {
			oastService.Start()
			defer oastService.Close()
			r.printPhaseDetail(fmt.Sprintf("OAST: enabled via %s (out-of-band callback detection active)", oastService.ServerURL()))
		}
	}

	// Compute in-scope hostnames to filter DB records by CLI target hostnames
	inScopeHostnames := r.getInScopeDBHostnamesList(ctx)

	// Shared insertion point cache across feedback rounds to avoid cold-start overhead
	ipCache, _ := lru.New[string, []httpmsg.InsertionPoint](4096)

	// Resolve per-phase settings from scanning pace config (static across rounds)
	var daMaxDuration time.Duration
	daParallelPassive := true // default for dynamic-assessment phase
	var daFeedbackDrain time.Duration
	var daActiveModuleTimeout time.Duration
	if r.settings != nil {
		daPace := r.settings.ScanningPace.ResolvePhase("dynamic-assessment")
		daMaxDuration = daPace.MaxDuration
		daParallelPassive = daPace.ParallelPassive
		daFeedbackDrain = daPace.FeedbackDrainTimeout
		daActiveModuleTimeout = daPace.ActiveModuleTimeout
	}

	// Enforce dynamic-assessment phase deadline across all feedback rounds. Without this wrap
	// each round's executor would start a fresh timeout, letting total phase time
	// reach feedbackRounds × daMaxDuration.
	if daMaxDuration > 0 {
		var phaseCancel context.CancelFunc
		ctx, phaseCancel = context.WithTimeout(ctx, daMaxDuration)
		defer phaseCancel()
	}

	// Reset cursor so dynamic-assessment reads all records from the beginning
	// (seed phase advances the cursor past all records when saving them).
	// Skip reset for scan-on-receive — the cursor tracks which records have been scanned.
	if !r.options.ScanOnReceive {
		if err := r.repository.ResetScanCursor(ctx, infra.scanUUID); err != nil {
			zap.L().Warn("DynamicAssessment: failed to reset scan cursor", zap.Error(err))
		}
	}

	var recordWriter *database.RecordWriter
	if r.repository != nil {
		recordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		defer recordWriter.Close()
	}

	baseExecutorCfg := core.ExecutorConfig{
		Workers:              daConcurrency,
		Services:             infra.svc,
		HTTPRequester:        infra.httpRequester,
		Repository:           r.repository,
		RecordWriter:         recordWriter,
		ScanUUID:             infra.scanUUID,
		ScopeMatcher:         infra.scopeMatcher,
		SkipBaseline:         true,
		PauseCtrl:            r.pauseCtrl,
		MaxFindingsPerModule: r.options.MaxFindingsPerModule,
		TechFilterDisabled:   r.options.NoTechFilter || strings.EqualFold(r.options.Intensity, "deep"),
		OnTechDetected: func(host, tag string) {
			line := fmt.Sprintf("%s %s %s %s %s %s\n",
				terminal.Muted(terminal.SymbolChevron+" tech-stack "+terminal.SymbolPipe),
				terminal.BoldCyan("[detected]"),
				terminal.HiBlue(host),
				terminal.Muted("→"),
				terminal.Yellow(tag),
				terminal.Muted("(skips incompatible modules unless --no-tech-filter)"))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		},
		// Phase-level ctx already carries the dynamic-assessment deadline; leaving this at 0
		// prevents each feedback round from starting a fresh per-round timeout.
		MaxDuration:          0,
		ParallelPassive:      daParallelPassive,
		FeedbackDrainTimeout: daFeedbackDrain,
		ActiveModuleTimeout:  daActiveModuleTimeout,
		IPCache:              ipCache,
		OnTraffic:            r.makeOnTrafficVerbose("dynamic-assessment"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
		OnStatus: func(processed, total, findings, distinctModules, activeCount, passiveCount int64, elapsed time.Duration) {
			if r.options.Silent {
				return
			}
			prefix := terminal.Muted(terminal.SymbolChevron + " dynamic-assessment " + terminal.SymbolPipe)
			var recordsStr string
			if total > 0 {
				recordsStr = fmt.Sprintf("%d/%d", processed, total)
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}
			totalModules := activeCount + passiveCount
			modulesStr := fmt.Sprintf("%d/%d (%d active, %d passive)",
				distinctModules, totalModules, activeCount, passiveCount)
			fmt.Fprintf(os.Stderr, "%s %s Records: %s | Findings: %s | Modules: %s | Runtime: %s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)))
		},
		StatusInterval: 1 * time.Minute,
	}
	if oastService != nil {
		baseExecutorCfg.OASTProvider = oastService
		baseExecutorCfg.OASTService = oastService
	}
	if infra.hookChain != nil {
		baseExecutorCfg.Hooks = infra.hookChain
	}

	// Continuous scan-on-receive mode: use a polling DBInputSource that waits
	// indefinitely for new records instead of snapshot-based feedback rounds.
	if r.options.ScanOnReceive && !r.options.FullNativeScanOnReceive {
		sorCfg := baseExecutorCfg
		// scan-on-receive scans each ingested request exactly once with no
		// fan-out. Feedback is disabled so passive-module URL discoveries
		// (link extractors, redirect followers) don't persist new work items;
		// RecordWriter is nil so the executor doesn't write scanner-produced
		// rows that would get polled back into the scan. For targeted one-
		// request scans drive /api/scan-request directly.
		sorCfg.DisableFeedback = true
		sorCfg.RecordWriter = nil
		// In server mode the console stays terse (status line at a 2-minute cadence
		// is the only stderr output by default). The same events are always written
		// verbosely to runtime.log so operators can reconstruct activity after the
		// fact — see runner.writeSessionLog.
		// Fire the first status tick at 30s so users see progress quickly when
		// a scan kicks off, then fall back to the 2-minute cadence.
		sorCfg.StatusInterval = 2 * time.Minute
		sorCfg.FirstStatusInterval = 30 * time.Second
		origOnResult := sorCfg.OnResult
		sorCfg.OnTraffic = func(method, url string, statusCode int, contentType string) {
			line := formatTrafficLine("scan-on-receive", method, url, statusCode, contentType)
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		sorCfg.OnResult = func(result *output.ResultEvent) {
			if origOnResult != nil {
				origOnResult(result)
			}
			if result == nil {
				return
			}
			line := fmt.Sprintf("  %s %s [%s] %s — %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("finding"),
				terminal.Orange(result.Info.Severity.String()),
				terminal.BoldCyan(result.ModuleID),
				terminal.Gray(result.URL))
			r.writeSessionLog(line)
			if !r.options.Silent {
				fmt.Fprint(os.Stderr, line)
			}
		}
		shortScanID := strings.TrimPrefix(infra.scanUUID, "scan-")
		if len(shortScanID) > 8 {
			shortScanID = shortScanID[:8]
		}

		// Threshold for treating a fetch as a "resume from idle" event. Below
		// this, batches are considered back-to-back and we stay silent to avoid
		// spamming the console while the scan is steadily processing.
		const activityIdleThreshold = 5 * time.Second

		// Restrict the DB poller to records that came from user ingestion.
		// Without this, "finding" records persisted by the executor's
		// emitResult (executor.go:1474-1488 — one row per finding with an
		// attached request/response pair) would get polled back into the
		// scan and fan out 1 ingested request → hundreds of re-scanned rows.
		sorSourceFilter := database.IngestRecordSources

		continuousSource := database.NewDBInputSource(r.repository.DB(), r.repository, infra.scanUUID, 2*time.Second).
			WithHostnames(inScopeHostnames).
			WithIncludeSources(sorSourceFilter).
			WithIdleTimeout(r.options.ScanOnReceiveIdleTimeout).
			WithOnActivity(func(records int, idleFor time.Duration, firstBatch bool) {
				// Print a one-line confirmation that the scan is actively processing
				// records. Two cases qualify: the very first batch ever (so the user
				// knows the scan started without waiting for the 2-min status tick),
				// or any batch that arrives after a quiet period.
				if !firstBatch && idleFor < activityIdleThreshold {
					return
				}
				prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
				var line string
				if firstBatch {
					line = fmt.Sprintf("%s %s scan-%s picked up %s — scanning started\n",
						prefix,
						terminal.BoldGreen("[start]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)))
				} else {
					line = fmt.Sprintf("%s %s scan-%s picked up %s after %s idle\n",
						prefix,
						terminal.BoldGreen("[resume]"),
						shortScanID,
						terminal.HiBlue(fmt.Sprintf("%d record(s)", records)),
						terminal.Gray(fmtDuration(idleFor)))
				}
				r.writeSessionLog(line)
				// Always surface start/resume to stderr — even in server mode
				// where Silent is true — so the user sees confirmation that an
				// ingested request was picked up for scanning. Without this the
				// ingest HTTP log is the only signal, and the 2-min status tick
				// is too late.
				fmt.Fprint(os.Stderr, line)
			})

		// Forward-declared so OnStatus can query the executor's in-flight counter.
		// Assigned right before Execute() below.
		var sorExecutor *core.Executor

		// Threshold for showing the "idle Ns" suffix in the status line. We only
		// surface idle state once the source has been quiet for at least one poll
		// interval — otherwise the suffix would flicker on/off between ticks.
		const idleDisplayThreshold = 10 * time.Second

		// Tracks the ingested-record count at the previous status tick so we can
		// report the delta ("new ingested records" since last line). Accessed
		// only from the ticker goroutine, so no locking needed.
		var prevIngestedCount int64 = -1

		sorCfg.OnStatus = func(processed, total, findings, distinctModules, activeCount, passiveCount int64, elapsed time.Duration) {
			ctx := context.Background()

			// Count HTTP records ingested since the scan started, scoped to the
			// in-scope hostnames if any were configured. Cheap enough at a
			// 2-minute cadence. Uses scan.StartedAt as the cursor reference.
			var ingestedCount int64 = -1
			var scanRow *database.Scan
			if r.repository != nil {
				if s, err := r.repository.GetScanByUUID(ctx, infra.scanUUID); err == nil && s != nil {
					scanRow = s
					// Count only user-ingested records so the "new ingested
					// records" counter matches what the DB poller will
					// actually scan (see sorSourceFilter above).
					if cnt, cErr := r.repository.CountRecordsAfterCursorBySource(ctx, s.StartedAt, "", sorSourceFilter, inScopeHostnames); cErr == nil {
						ingestedCount = cnt
					}
				}
			}

			// Processed Records: X / Y (new ingested records: Z)
			//   X = records the executor has finished scanning
			//   Y = total records this scan has ever seen (ingested so far)
			//   Z = records that arrived since the previous status tick
			totalModules := activeCount + passiveCount
			var recordsStr string
			if ingestedCount >= 0 {
				delta := ingestedCount
				if prevIngestedCount >= 0 {
					delta = ingestedCount - prevIngestedCount
					if delta < 0 {
						delta = 0
					}
				}
				recordsStr = fmt.Sprintf("%d / %d (new ingested records: %d)",
					processed, ingestedCount, delta)
				prevIngestedCount = ingestedCount
			} else {
				recordsStr = fmt.Sprintf("%d", processed)
			}

			// Modules: <scanned> / <total> — how many enabled modules have been
			// evaluated against any record so far, out of the full set. Counts
			// both modules that ran AND modules whose CanProcess rejected the
			// input shape (e.g., POST-only modules on a GET request) — so the
			// counter can reach parity with the total once every module has been
			// seen, instead of stalling on the "always-rejected" set forever.
			scannedModules := distinctModules
			if sorExecutor != nil {
				scannedModules = sorExecutor.ConsideredModuleCount()
			}
			modulesStr := fmt.Sprintf("%d / %d", scannedModules, totalModules)

			// Optional suffix: when no workers are in-flight and the source has
			// been quiet for a while, surface "idle <duration>" so the user knows
			// the scan is alive but waiting for new ingested records.
			var idleSuffix string
			inFlight := int64(0)
			if sorExecutor != nil {
				inFlight = sorExecutor.InFlight()
			}
			if inFlight == 0 {
				if idleFor := continuousSource.IdleFor(); idleFor >= idleDisplayThreshold {
					idleSuffix = " | " + terminal.Muted(fmt.Sprintf("idle %s", fmtDuration(idleFor)))
				}
			}

			prefix := terminal.Muted(terminal.SymbolChevron + " scan-on-receive " + terminal.SymbolPipe)
			fmt.Fprintf(os.Stderr, "%s %s %s Processed Records: %s | Findings: %s | Modules: %s | Runtime: %s%s\n",
				prefix,
				terminal.BoldCyan("[status]"),
				terminal.Cyan("scan-"+shortScanID),
				terminal.HiBlue(recordsStr),
				terminal.Orange(fmt.Sprintf("%d", findings)),
				terminal.Yellow(modulesStr),
				terminal.Gray(fmtDuration(elapsed)),
				idleSuffix)
			if r.repository != nil && scanRow != nil {
				_ = r.repository.RefreshScanStats(ctx, infra.scanUUID)
			}
		}

		sorExecutor = core.NewExecutor(sorCfg, continuousSource, activeModules, passiveModules)
		executor := sorExecutor
		if oastService != nil {
			oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
		}
		_, err := executor.Execute(ctx)
		if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
			logModuleMetrics(metrics)
		}
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}

	// Feedback loop: re-scan newly discovered URLs
	for round := 0; round < feedbackRounds; round++ {
		processed, err := r.runDynamicAssessmentRound(ctx, infra, round, inScopeHostnames, activeModules, passiveModules, baseExecutorCfg, oastService)
		if err != nil {
			zap.L().Error("DynamicAssessment: executor error", zap.Error(err), zap.Int("round", round))
			break
		}

		// Deduplicate findings after each dynamic-assessment round
		r.deduplicateFindings(ctx, "DynamicAssessment")

		if ctx.Err() != nil {
			zap.L().Info("DynamicAssessment: phase deadline reached, stopping feedback loop",
				zap.Int("round", round+1), zap.Error(ctx.Err()))
			break
		}

		if round < feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHostnames)
			if countErr != nil || newCount == 0 {
				if countErr != nil {
					zap.L().Debug("DynamicAssessment: failed to count remaining records", zap.Error(countErr))
				}
				break
			}
			r.printPhaseFeedback("DynamicAssessment",
				fmt.Sprintf("%s new records discovered, starting round %d", terminal.Orange(fmt.Sprintf("%d", newCount)), round+2))
			zap.L().Info("DynamicAssessment: new records discovered, starting next round",
				zap.Int64("new_records", newCount))
		}

		if processed == 0 {
			break
		}

		if round == feedbackRounds-1 {
			newCount, countErr := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, inScopeHostnames)
			if countErr == nil && newCount > 0 {
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Orange(fmt.Sprintf("%d", newCount)), terminal.Gray(fmt.Sprintf("new records discovered but skipped (max_feedback_rounds=%d)", feedbackRounds)))
				fmt.Fprintf(os.Stderr, "  %s %s %s\n",
					terminal.TipPrefix(), terminal.Gray("enable multi-round scanning via"), terminal.Cyan("vigolium config dynamic-assessment.max_feedback_rounds=3"))
			}
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("DynamicAssessment", fmt.Sprintf("all rounds completed in %s", terminal.HiPurple(fmtDuration(elapsed))))

	return nil
}

func (r *Runner) runDynamicAssessmentRound(
	ctx context.Context,
	infra *phaseInfra,
	round int,
	inScopeHostnames []string,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
	baseCfg core.ExecutorConfig,
	oastService *oast.Service,
) (int64, error) {
	roundStart := time.Now()
	dbSource := database.NewRiskPrioritizedDBInputSource(r.repository.DB(), r.repository, infra.scanUUID).
		WithHostnames(inScopeHostnames)

	executor := core.NewExecutor(baseCfg, dbSource, activeModules, passiveModules)
	if oastService != nil {
		oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
	}
	_, err := executor.Execute(ctx)

	if metrics := executor.ModuleMetrics(); len(metrics) > 0 {
		logModuleMetrics(metrics)
	}
	if c := infra.httpRequester.Clusterer(); c != nil {
		c.LogStats()
	}
	if err != nil {
		return 0, err
	}

	processed := executor.Processed()
	roundElapsed := time.Since(roundStart)
	r.printPhaseComplete("DynamicAssessment",
		fmt.Sprintf("round %d — %s items in %s", round+1, terminal.Orange(fmt.Sprintf("%d", processed)), terminal.HiPurple(fmtDuration(roundElapsed))))
	zap.L().Info("DynamicAssessment: round completed",
		zap.Int("round", round+1),
		zap.Int64("processed", processed))
	return processed, nil
}

func (r *Runner) countRemainingDynamicAssessmentRecords(ctx context.Context, scanUUID string, hostnames []string) (int64, error) {
	currentScan, err := r.repository.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		return 0, err
	}
	return r.repository.CountRecordsAfterCursor(ctx, currentScan.CursorAt, currentScan.CursorUUID, hostnames...)
}

// waitForNewRecords polls until at least one record exists after the scan cursor,
// or the context is cancelled. Used by full-native-scan-on-receive to block between iterations.
func (r *Runner) waitForNewRecords(ctx context.Context, scanUUID string, pollInterval time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		count, err := r.countRemainingDynamicAssessmentRecords(ctx, scanUUID, nil)
		if err != nil {
			zap.L().Debug("waitForNewRecords: query error", zap.Error(err))
		}
		if count > 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// resolveAllModules combines getModulesToExecute() with JS extension modules.
func (r *Runner) resolveAllModules(infra *phaseInfra) ([]modules.ActiveModule, []modules.PassiveModule) {
	var activeModules []modules.ActiveModule
	var passiveModules []modules.PassiveModule

	if !r.options.ExtensionsOnly {
		activeModules, passiveModules = r.getModulesToExecute()
	}

	// Append JS extension modules
	if infra.jsEngine != nil {
		jsMods := infra.jsEngine.ActiveModules()
		if len(jsMods) > 0 {
			activeModules = append(activeModules, jsMods...)
			zap.L().Info("JS active modules loaded", zap.Int("count", len(jsMods)))
		}
		jsPassive := infra.jsEngine.PassiveModules()
		if len(jsPassive) > 0 {
			passiveModules = append(passiveModules, jsPassive...)
			zap.L().Info("JS passive modules loaded", zap.Int("count", len(jsPassive)))
		}
	}

	return activeModules, passiveModules
}

// getModulesToExecute returns the active and passive modules to execute based on options.
func (r *Runner) getModulesToExecute() ([]modules.ActiveModule, []modules.PassiveModule) {
	var activeModules []modules.ActiveModule
	var passiveModules []modules.PassiveModule

	// Get active modules
	activeUsingAll := false
	if len(r.options.Modules) > 0 {
		if r.options.Modules[0] == "all" {
			activeModules = modules.GetActiveModules()
			activeUsingAll = true
		} else {
			activeModules = modules.GetActiveModulesByIDs(r.options.Modules)
		}
	}

	// Get passive modules
	passiveUsingAll := false
	if len(r.options.PassiveModules) > 0 {
		if r.options.PassiveModules[0] == "all" {
			passiveModules = modules.GetPassiveModules()
			passiveUsingAll = true
		} else {
			passiveModules = modules.GetPassiveModulesByIDs(r.options.PassiveModules)
		}
	}

	// Filter modules based on enabled_modules config (only when CLI uses "all")
	if r.settings != nil {
		if activeUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.ActiveModules) {
			activeModules = modules.GetActiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.ActiveModules)
			zap.L().Info("Active modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.ActiveModules))
		}

		if passiveUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.PassiveModules) {
			passiveModules = modules.GetPassiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.PassiveModules)
			zap.L().Info("Passive modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.PassiveModules))
		}
	}

	// Sort by execution priority to keep scheduling policy aligned with the executor.
	if len(activeModules) > 0 {
		sortActiveModulesByPriority(activeModules)
		zap.L().Info("Active modules to execute", zap.Int("count", len(activeModules)))
	}

	if len(passiveModules) > 0 {
		sortPassiveModulesByPriority(passiveModules)
		zap.L().Info("Passive modules to execute", zap.Int("count", len(passiveModules)))
	}

	return activeModules, passiveModules
}

func sortActiveModulesByPriority(mods []modules.ActiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return moduleExecutionPriority(mods[i]) < moduleExecutionPriority(mods[j])
	})
}

func sortPassiveModulesByPriority(mods []modules.PassiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return moduleExecutionPriority(mods[i]) < moduleExecutionPriority(mods[j])
	})
}

func moduleExecutionPriority(m modules.Module) int {
	if prioritized, ok := m.(modules.Prioritized); ok {
		return prioritized.Priority()
	}
	return 100
}

// isAllModules returns true when the list is empty or contains only "all".
func isAllModules(ids []string) bool {
	return len(ids) == 0 || (len(ids) == 1 && ids[0] == "all")
}

// filterOutPassiveModule removes a passive module with the given ID from the list.
func filterOutPassiveModule(mods []modules.PassiveModule, id string) []modules.PassiveModule {
	result := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if m.ID() != id {
			result = append(result, m)
		}
	}
	return result
}

// buildModulesString returns a comma-separated string of module IDs for scan record storage.
func (r *Runner) buildModulesString(active []modules.ActiveModule, passive []modules.PassiveModule) string {
	ids := make([]string, 0, len(active)+len(passive))
	for _, m := range active {
		ids = append(ids, m.ID())
	}
	for _, m := range passive {
		ids = append(ids, m.ID())
	}
	return strings.Join(ids, ",")
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	// Resume if paused — workers must unblock before they can see context cancellation
	if r.pauseCtrl != nil && r.pauseCtrl.IsPaused() {
		r.pauseCtrl.Resume()
	}

	// Signal cancellation to all workers first
	if r.cancel != nil {
		r.cancel()
	}

	// Wait for RunNativeScan to finish (with configurable timeout)
	if r.done != nil {
		shutdownTimeout := r.options.ShutdownTimeout
		if shutdownTimeout <= 0 {
			shutdownTimeout = 30 * time.Second
		}
		select {
		case <-r.done:
		case <-time.After(shutdownTimeout):
			zap.L().Warn("Graceful shutdown timed out, forcing cleanup",
				zap.Duration("timeout", shutdownTimeout))
		}
	}

	if r.output != nil {
		r.output.Close()
	}

	if r.dedupManager != nil {
		r.dedupManager.Close()
	}

	if r.inputSource != nil {
		_ = r.inputSource.Close()
	}

	network.Close()
}

// SetRepository sets the database repository for storing scan results
func (r *Runner) SetRepository(repo *database.Repository) {
	r.repository = repo
}

// SetSettings sets the configuration settings for notifications and other YAML-based config
func (r *Runner) SetSettings(s *config.Settings) {
	r.settings = s
}

// Pause suspends scan processing. Workers finish their current item then block.
// writeSessionLog appends a plain-text line to runtime.log (ANSI stripped,
// timestamped) without routing it through stderr. No-op when session log
// persistence is disabled. Safe for concurrent use.
func (r *Runner) writeSessionLog(line string) {
	r.sessionLogMu.Lock()
	f := r.sessionLogFile
	r.sessionLogMu.Unlock()
	if f == nil {
		return
	}
	plain := terminal.StripANSI(line)
	if !strings.HasSuffix(plain, "\n") {
		plain += "\n"
	}
	ts := time.Now().Format("15:04:05")
	_, _ = f.WriteString("[" + ts + "] " + plain)
}

func (r *Runner) Pause() {
	if r.pauseCtrl != nil {
		r.pauseCtrl.Pause()
		if r.scanLogger != nil {
			r.scanLogger.Info("", "scan paused")
		}
	}
}

// Resume unblocks paused workers and continues scan processing.
func (r *Runner) Resume() {
	if r.pauseCtrl != nil {
		r.pauseCtrl.Resume()
		if r.scanLogger != nil {
			r.scanLogger.Info("", "scan resumed")
		}
	}
}

// IsPaused returns whether the scan is currently paused.
func (r *Runner) IsPaused() bool {
	if r.pauseCtrl != nil {
		return r.pauseCtrl.IsPaused()
	}
	return false
}

// ScanLogger returns the scan logger (may be nil if no repository is set).
func (r *Runner) ScanLogger() *database.ScanLogger {
	return r.scanLogger
}

// buildKnownIssueScanTargetsFromPaths takes distinct path records from the DB and returns
// deduplicated target URLs with path prefixes (last segment stripped).
func buildKnownIssueScanTargetsFromPaths(paths []database.PathTarget) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, p := range paths {
		// Build host base URL
		base := fmt.Sprintf("%s://%s", p.Scheme, p.Hostname)
		if (p.Scheme == "https" && p.Port != 443) || (p.Scheme == "http" && p.Port != 80) {
			base = fmt.Sprintf("%s://%s:%d", p.Scheme, p.Hostname, p.Port)
		}

		// Strip query string and fragment
		path := p.Path
		if idx := strings.IndexAny(path, "?#"); idx != -1 {
			path = path[:idx]
		}

		// Normalize empty path to "/"
		if path == "" {
			path = "/"
		}

		// Strip last path segment: if path doesn't end with "/", remove everything after the last "/"
		if !strings.HasSuffix(path, "/") {
			if idx := strings.LastIndex(path, "/"); idx >= 0 {
				path = path[:idx+1]
			}
		}

		target := base + path
		target = strings.TrimRight(target, "/")
		if _, ok := seen[target]; !ok {
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}

	return targets
}

// buildKnownIssueScanHostTargets returns deduplicated host-level URLs (scheme://host[:port]/)
// without path-prefix expansion. This is faster but provides less granular coverage.
func buildKnownIssueScanHostTargets(paths []database.PathTarget) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, p := range paths {
		base := fmt.Sprintf("%s://%s", p.Scheme, p.Hostname)
		if (p.Scheme == "https" && p.Port != 443) || (p.Scheme == "http" && p.Port != 80) {
			base = fmt.Sprintf("%s://%s:%d", p.Scheme, p.Hostname, p.Port)
		}
		target := base
		if _, ok := seen[target]; !ok {
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}

	return targets
}

// buildDiscoveryTargetsFromPaths returns deduplicated directory-level URLs from DB paths
// for use as additional deparos discovery targets. Strips filenames, keeps directories.
func buildDiscoveryTargetsFromPaths(paths []database.PathTarget) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, p := range paths {
		base := fmt.Sprintf("%s://%s", p.Scheme, p.Hostname)
		if (p.Scheme == "https" && p.Port != 443) || (p.Scheme == "http" && p.Port != 80) {
			base = fmt.Sprintf("%s://%s:%d", p.Scheme, p.Hostname, p.Port)
		}

		path := p.Path
		if idx := strings.IndexAny(path, "?#"); idx != -1 {
			path = path[:idx]
		}
		if path == "" {
			path = "/"
		}

		// Strip last segment to get directory (e.g., /api/users/123 → /api/users/)
		if !strings.HasSuffix(path, "/") {
			if idx := strings.LastIndex(path, "/"); idx >= 0 {
				path = path[:idx+1]
			}
		}

		target := base + path
		if _, ok := seen[target]; !ok {
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}

	return targets
}

// runKnownIssueScan executes known issue scanning using the nuclei Go library.
func (r *Runner) runKnownIssueScan(ctx context.Context, onResult func(*output.ResultEvent)) error {
	if r.repository == nil {
		return fmt.Errorf("known-issue-scan: database repository required")
	}

	// Query distinct paths from DB and build targets
	paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
	if err != nil {
		return fmt.Errorf("known-issue-scan: failed to query paths: %w", err)
	}
	if len(paths) == 0 {
		zap.L().Info("KnownIssueScan: no hosts in database, skipping")
		return nil
	}

	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.KnownIssueScan.EnrichTargets
	}

	var targets []string
	if enrichTargets {
		targets = buildKnownIssueScanTargetsFromPaths(paths)
	} else {
		targets = buildKnownIssueScanHostTargets(paths)
	}

	zap.L().Info("KnownIssueScan: targets from database", zap.Int("count", len(targets)))

	// Build KnownIssueScan config from settings
	cfg := knownissuescan.Config{
		Targets:     targets,
		Concurrency: r.options.Concurrency,
		ScanUUID:    r.options.ScanUUID,
		ProjectUUID: r.options.ProjectUUID,
		ProxyURL:    r.options.ProxyURL,
		Headers:     r.options.Headers,
		OnResult:    onResult,
		Repository:  r.repository,
	}

	// Apply YAML settings
	if r.settings != nil {
		knownIssueScanCfg := &r.settings.KnownIssueScan
		cfg.Tags = knownIssueScanCfg.Tags
		cfg.ExcludeTags = knownIssueScanCfg.ExcludeTags
		cfg.Severities = knownIssueScanCfg.Severities
		if knownIssueScanCfg.TemplatesDir != "" {
			cfg.TemplatesDir = config.ExpandPath(knownIssueScanCfg.TemplatesDir)
		}

		// scanning_pace.known-issue-scan controls speed
		knownIssueScanPace := r.settings.ScanningPace.ResolvePhase("known-issue-scan")
		if !r.options.ConcurrencyExplicitlySet && knownIssueScanPace.Concurrency > 0 {
			cfg.Concurrency = knownIssueScanPace.Concurrency
		}
		if knownIssueScanPace.RateLimit > 0 {
			cfg.RateLimit = knownIssueScanPace.RateLimit
		}
		if knownIssueScanPace.MaxDuration > 0 {
			cfg.Timeout = knownIssueScanPace.MaxDuration
		}
	}

	return knownissuescan.Run(ctx, cfg)
}

// buildDeparosConfig maps YAML DiscoveryConfig + CLI flags into a DeparosDiscoveryConfig.
// additionalTargets are merged (deduplicated) with CLI targets to expand the discovery scope.
func (r *Runner) buildDeparosConfig(additionalTargets []string) source.DeparosDiscoveryConfig {
	// Resolve discovery concurrency: scanning_pace.discovery overrides global when CLI not explicit
	discoveryConcurrency := r.options.Concurrency
	if r.settings != nil && !r.options.ConcurrencyExplicitlySet {
		discPace := r.settings.ScanningPace.ResolvePhase("discovery")
		if discPace.Concurrency > 0 {
			discoveryConcurrency = discPace.Concurrency
		}
	}

	// Merge CLI targets with additional targets (deduplicated)
	targets := dedupTargets(r.options.Targets, additionalTargets)

	cfg := source.DeparosDiscoveryConfig{
		Targets:       targets,
		Concurrency:   discoveryConcurrency,
		MaxDuration:   r.options.DiscoverMaxDuration,
		EnableModules: r.options.Modules,
		// Defaults that match deparos defaults
		RecursionEnabled:     true,
		RecursionDepth:       5,
		SaveResponseBody:     true,
		UseObservedNames:     true,
		UseObservedPaths:     true,
		UseObservedFiles:     true,
		EnableNumericFuzzing: false,
		TestCustom:           true,
		TestObserved:         true,
		TestBackupExtensions: true,
		TestNoExtension:      true,
		CaseSensitivity:      "auto_detect",
	}

	// Apply YAML settings if available
	if r.settings != nil {
		dc := &r.settings.Discovery

		cfg.Mode = dc.Mode
		cfg.ScopeMode = dc.ScopeMode
		cfg.RecursionEnabled = dc.Recursion.Enabled
		if dc.Recursion.MaxDepth > 0 {
			cfg.RecursionDepth = dc.Recursion.MaxDepth
		}
		cfg.SaveResponseBody = dc.SaveResponseBody

		// Wordlists (expand ~ paths)
		if dc.Wordlists.ShortFilePath != "" {
			cfg.ShortFilePath = config.ExpandPath(dc.Wordlists.ShortFilePath)
		}
		if dc.Wordlists.LongFilePath != "" {
			cfg.LongFilePath = config.ExpandPath(dc.Wordlists.LongFilePath)
		}
		if dc.Wordlists.ShortDirPath != "" {
			cfg.ShortDirPath = config.ExpandPath(dc.Wordlists.ShortDirPath)
		}
		if dc.Wordlists.LongDirPath != "" {
			cfg.LongDirPath = config.ExpandPath(dc.Wordlists.LongDirPath)
		}
		if dc.Wordlists.FuzzWordlistPath != "" {
			cfg.FuzzWordlistPath = config.ExpandPath(dc.Wordlists.FuzzWordlistPath)
		}
		cfg.UseObservedNames = dc.Wordlists.UseObservedNames
		cfg.UseObservedPaths = dc.Wordlists.UseObservedPaths
		cfg.UseObservedFiles = dc.Wordlists.UseObservedFiles
		cfg.EnableNumericFuzzing = dc.Wordlists.EnableNumericFuzzing

		// Extensions
		cfg.TestCustom = dc.Extensions.TestCustom
		cfg.CustomList = dc.Extensions.CustomList
		cfg.TestObserved = dc.Extensions.TestObserved
		cfg.TestBackupExtensions = dc.Extensions.TestBackupExtensions
		cfg.BackupExtensions = dc.Extensions.BackupExtensions
		cfg.TestNoExtension = dc.Extensions.TestNoExtension

		// Engine
		cfg.CaseSensitivity = dc.Engine.CaseSensitivity
		cfg.EngineTimeout = dc.EngineTimeoutParsed()
		cfg.CustomHeaders = dc.Engine.CustomHeaders
		cfg.EnableCookieJar = dc.Engine.EnableCookieJar
		cfg.MaxConsecutiveErrors = dc.Engine.MaxConsecutiveErrors
		cfg.MaxConsecutiveWAFBlocks = dc.Engine.MaxConsecutiveWAFBlocks
		if dc.Engine.ObservedMaxItems > 0 {
			cfg.ObservedMaxItems = dc.Engine.ObservedMaxItems
		}
		cfg.DisableKingfisher = dc.Engine.DisableKingfisher

		// Prefix breaker
		cfg.PrefixBreakerEnabled = dc.Engine.PrefixBreaker.Enabled
		cfg.PrefixBreakerMinSamples = dc.Engine.PrefixBreaker.MinSamples
		cfg.PrefixBreakerTripRatio = dc.Engine.PrefixBreaker.TripRatio
		cfg.PrefixBreakerPrefixSegments = dc.Engine.PrefixBreaker.PrefixSegments
		cfg.PrefixBreakerLengthBucket = dc.Engine.PrefixBreaker.LengthBucket

		// Malformed path probe
		cfg.EnableMalformedPathProbe = dc.EnableMalformedPathProbe

		// MaxDuration is resolved via scanning_pace (applied to r.options by scan.go)
	}

	// CLI --fuzz-wordlist override (takes precedence over YAML config)
	if r.options.FuzzWordlistPath != "" {
		cfg.FuzzWordlistPath = config.ExpandPath(r.options.FuzzWordlistPath)
	}

	// CLI --no-prefix-breaker override (takes precedence over YAML config)
	if r.options.NoPrefixBreaker {
		disabled := false
		cfg.PrefixBreakerEnabled = &disabled
	}

	// Proxy support
	if r.options.ProxyURL != "" {
		cfg.ProxyURL = r.options.ProxyURL
	}

	// Pass repository so deparos results are imported to vigolium's DB
	if r.repository != nil {
		cfg.Repository = r.repository
	}
	cfg.ProjectUUID = r.options.ProjectUUID

	return cfg
}

// buildExternalHarvesterSource creates an ExternalHarvesterInputSource from settings.
func (r *Runner) buildExternalHarvesterSource() *source.ExternalHarvesterInputSource {
	cfg := r.settings.ExternalHarvester

	proxyURL := r.options.ProxyURL

	var sources []harvester.Source
	for _, name := range cfg.Sources {
		switch name {
		case "wayback":
			sources = append(sources, harvester.NewWaybackSource(proxyURL))
		case "commoncrawl":
			sources = append(sources, harvester.NewCommonCrawlSource(proxyURL))
		case "alienvault":
			sources = append(sources, harvester.NewAlienVaultSource(proxyURL))
		case "urlscan":
			if cfg.APIKeys.URLScan != "" {
				sources = append(sources, harvester.NewURLScanSource(cfg.APIKeys.URLScan, proxyURL))
			}
		case "virustotal":
			if cfg.APIKeys.VirusTotal != "" {
				sources = append(sources, harvester.NewVirusTotalSource(cfg.APIKeys.VirusTotal, proxyURL))
			}
		}
	}

	if len(sources) == 0 {
		zap.L().Warn("ExternalHarvester enabled but no sources configured")
		return nil
	}

	// Extract domains from targets
	domains := extractDomains(r.options.Targets)
	if len(domains) == 0 {
		zap.L().Warn("ExternalHarvester: no domains could be extracted from targets")
		return nil
	}

	// Resolve timeout from scanning_pace.external_harvester
	timeout := 5 * time.Minute // built-in default
	if r.settings != nil {
		ehPace := r.settings.ScanningPace.ResolvePhase("external_harvester")
		if ehPace.MaxDuration > 0 {
			timeout = ehPace.MaxDuration
		}
	}

	h := harvester.New(sources, timeout)

	zap.L().Info("ExternalHarvester initialized",
		zap.Int("sources", len(sources)),
		zap.Strings("domains", domains),
		zap.Duration("timeout", timeout))

	return source.NewExternalHarvesterInputSource(h, domains, r.options.Modules)
}

// runExternalHarvestPhase runs external intelligence harvesting as a standalone phase.
// Harvested URLs are ingested into the httpRecords table via an Executor with zero modules.
func (r *Runner) runExternalHarvestPhase(ctx context.Context, infra *phaseInfra) error {
	if len(r.options.Targets) == 0 {
		return nil
	}

	phaseStart := time.Now()

	src := r.buildExternalHarvesterSource()
	if src == nil {
		zap.L().Warn("ExternalHarvest: no source could be built, skipping")
		return nil
	}

	r.printPhaseStart("ExternalHarvest", "harvest URLs from external intelligence sources")

	ehSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		ehPace := r.settings.ScanningPace.ResolvePhase("external_harvester")
		if ehPace.MaxDuration > 0 {
			ehSpeedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(ehPace.MaxDuration.String()))
		}
		if ehPace.DurationFactor > 0 {
			ehSpeedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", ehPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(ehSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	zap.L().Info("ExternalHarvest: ingesting harvested URLs into database")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("harvest"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, src, nil, nil)
	_, err := executor.Execute(ctx)
	if err != nil {
		return err
	}

	// Increment processed_count for external harvest phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("ExternalHarvest: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("ExternalHarvest", fmt.Sprintf("completed — %s items ingested in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())), terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("ExternalHarvest: completed", zap.Int64("processed", executor.Processed()))
	return nil
}

// getInScopeHostURLs queries distinct hosts from the DB and filters them by scope.
// Returns a deduplicated list of host URLs (e.g. "https://example.com").
func (r *Runner) getInScopeHostURLs(ctx context.Context, scopeMatcher *config.ScopeMatcher) ([]string, error) {
	if r.repository == nil {
		return nil, nil
	}

	hosts, err := r.repository.GetDistinctHosts(ctx, r.options.ProjectUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to query distinct hosts: %w", err)
	}

	var urls []string
	for _, h := range hosts {
		// Build URL string
		target := fmt.Sprintf("%s://%s", h.Scheme, h.Hostname)
		if (h.Scheme == "https" && h.Port != 443) || (h.Scheme == "http" && h.Port != 80) {
			target = fmt.Sprintf("%s://%s:%d", h.Scheme, h.Hostname, h.Port)
		}

		// Filter by scope if matcher is available
		if scopeMatcher != nil && !scopeMatcher.InScopeRequest(h.Hostname, "/", "", "") {
			continue
		}

		urls = append(urls, target)
	}

	return urls, nil
}

// extractDomains extracts hostnames from target URLs.
func extractDomains(targets []string) []string {
	seen := make(map[string]struct{})
	var domains []string
	for _, t := range targets {
		u, err := neturl.Parse(t)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := u.Hostname()
		if _, exists := seen[host]; !exists {
			seen[host] = struct{}{}
			domains = append(domains, host)
		}
	}
	return domains
}

// dedupTargets merges base targets with additional targets, removing duplicates.
// Returns the deduplicated slice preserving order (base targets first).
// Trailing slashes are stripped for comparison to avoid duplicates like
// "https://example.com/" and "https://example.com".
func dedupTargets(base, additional []string) []string {
	seen := make(map[string]struct{}, len(base)+len(additional))
	result := make([]string, 0, len(base)+len(additional))
	for _, t := range base {
		key := strings.TrimRight(t, "/")
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}
	for _, t := range additional {
		key := strings.TrimRight(t, "/")
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}
	return result
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

// buildTelegramOptions creates Telegram options from settings.
// Falls back to environment variables if settings are not set.
func (r *Runner) buildTelegramOptions() []telegram.Option {
	var opts []telegram.Option

	// Bot token from settings or env
	var token string
	if r.settings != nil {
		token = r.settings.Notify.Telegram.BotToken
	}
	if token == "" {
		token = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	if token != "" {
		opts = append(opts, telegram.WithBotToken(token))
	}

	// Chat ID from settings or env
	var chatIDStr string
	if r.settings != nil {
		chatIDStr = r.settings.Notify.Telegram.ChatID
	}
	if chatIDStr == "" {
		chatIDStr = os.Getenv("TELEGRAM_CHAT_ID")
	}
	if chatIDStr != "" {
		if chatID, err := strconv.ParseInt(chatIDStr, 10, 64); err == nil {
			opts = append(opts, telegram.WithChatID(chatID))
		}
	}

	return opts
}
