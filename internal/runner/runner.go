package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/toolexec/astgrep"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/toolexec/sourcetools"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/session"

	secret_detect "github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spa"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/useragent"
	"github.com/samber/lo"
	"go.uber.org/zap"
)

// maxFeedbackRounds limits re-scanning of newly discovered URLs in the audit phase.
const maxFeedbackRounds = 3

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
	sharedInfra       *SharedInfra         // Optional: pre-built infrastructure for reuse across rescans

	ctx       context.Context       // cancellable context for graceful shutdown
	cancel    context.CancelFunc    // cancels ctx to signal workers to stop
	done      chan struct{}          // closed when RunNativeScan finishes
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
	Name   string
	Client *http.Requester
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

	if settings != nil && settings.Audit.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   opts.ScanUUID,
			Repository: repo,
		}
		if settings != nil {
			scopeCfg := settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(settings.Scope, opts.Targets...)
		}
		jsEngine, jsErr := jsext.NewEngine(&settings.Audit.Extensions, httpRequester, jsEngineOpts)
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
	fmt.Fprintf(os.Stderr, "\n%s %s  %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue(phase), terminal.Muted(detail))
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

	fmt.Fprintf(os.Stderr, "%s%s[%s]\033[0m %s%s\033[0m %s%s\033[0m %s\n",
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

// RunNativeScan orchestrates the 5-phase scan pipeline:
//
//	ExternalHarvest   — harvest URLs from external intelligence sources (opt-in)
//	Spidering         — browser-based crawling (opt-in)
//	Discovery         — ingest all input + deparos content discovery into DB (no modules)
//	SPA               — nuclei + kingfisher batch (opt-in via --spa)
//	Audit             — modules + extensions scan DB records
// printScanConfig prints a human-readable scan configuration summary to stderr.
// This provides the same information the CLI's printScanSummary shows, ensuring
// API-triggered scans also display the effective configuration.
func (r *Runner) printScanConfig() {
	if r.options.Silent || r.options.ScanConfigPrinted {
		return
	}

	opts := r.options
	settings := r.settings

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue("Scan Configuration"))

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
	fmt.Fprintf(os.Stderr, "           %s | %s | %s\n",
		phaseLabel("SPA", "spa", opts.SPAEnabled),
		phaseLabel("Audit", "audit", !opts.SkipAudit),
		phaseLabel("SAST", "sast", opts.SASTEnabled))

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
	extEnabled := settings != nil && settings.Audit.Extensions.Enabled
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
	switch {
	case opts.AuthConfigPath != "":
		printSessionAuth("from " + terminal.ShortenHome(opts.AuthConfigPath))
	case len(opts.SessionFiles) > 0:
		printSessionAuth(fmt.Sprintf("from %d session file(s)", len(opts.SessionFiles)))
	case len(opts.Sessions) > 0:
		printSessionAuth(fmt.Sprintf("from %d inline session(s)", len(opts.Sessions)))
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
		"project_uuid":        opts.ProjectUUID,
		"targets":             opts.Targets,
		"strategy":            strategy,
		"scanning_profile":    opts.ScanningProfile,
		"concurrency":         opts.Concurrency,
		"rate_limit":          rateLimit,
		"max_per_host":        opts.MaxPerHost,
		"heuristics_check":    opts.HeuristicsCheck,
		"scope_origin_mode":   opts.ScopeOriginMode,
		"active_modules":      activeCount,
		"passive_modules":     passiveCount,
		"spidering_enabled":   opts.SpideringEnabled,
		"discovery_enabled":   opts.DiscoverEnabled,
		"spa_enabled":         opts.SPAEnabled,
		"sast_enabled":        opts.SASTEnabled,
		"external_harvest":    opts.ExternalHarvestEnabled,
		"skip_dynamic":        opts.SkipAudit,
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
	if r.repository != nil {
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
		} else {
			// Defer scan completion so the record is updated when RunNativeScan finishes.
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
	}

	// Set up TeeWriter to capture raw stderr output as trace-level scan logs.
	if r.repository != nil {
		origStderr := os.Stderr
		r.teeWriter = newTeeWriter(origStderr, r.scanLogger)
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
			}()
		}
	}

	// Print scan configuration summary
	r.printScanConfig()

	r.scanLogger.Info("", "scan started")

	// Log scan configuration snapshot as structured metadata.
	r.logConfigSnapshot()

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

	// HeuristicsCheck — probe CLI target root pages to decide phase eligibility
	if r.options.HeuristicsCheck != "none" && r.options.HeuristicsCheck != "" {
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
	}

	// ExternalHarvest — harvest from external sources (opt-in)
	if r.options.ExternalHarvestEnabled {
		r.setPhaseTag("harvest")
		r.scanLogger.Info("harvest", "phase started")
		if err := r.runExternalHarvestPhase(ctx, infra); err != nil {
			zap.L().Error("ExternalHarvest phase failed", zap.Error(err))
			r.scanLogger.Error("harvest", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("harvest", "phase completed")
		}
	}

	// Spidering — browser-based crawling (opt-in)
	if r.options.SpideringEnabled {
		r.setPhaseTag("spider")
		r.scanLogger.Info("spidering", "phase started")
		if err := r.runSpideringPhase(ctx, infra); err != nil {
			zap.L().Error("Spidering phase failed", zap.Error(err))
			r.scanLogger.Error("spidering", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("spidering", "phase completed")
		}
	}

	// SAST — ast-grep route extraction from source code (opt-in)
	if r.options.SASTEnabled {
		r.setPhaseTag("sast")
		r.scanLogger.Info("sast", "phase started")
		if err := r.runSASTPhase(ctx, infra); err != nil {
			zap.L().Error("SAST phase failed", zap.Error(err))
			r.scanLogger.Error("sast", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("sast", "phase completed")
		}
	}

	// Discovery — ingest input + deparos discovery (unless skipped)
	if !r.options.SkipIngestion {
		r.setPhaseTag("discovery")
		r.scanLogger.Info("discovery", "phase started")
		if err := r.runDiscoveryPhase(ctx, infra); err != nil {
			r.scanLogger.Error("discovery", "phase failed: "+err.Error())
			return fmt.Errorf("discovery phase failed: %w", err)
		}
		r.scanLogger.Info("discovery", "phase completed")

		// Hard dedup now happens in-memory before DB import (inside DeparosDiscoverySource).
		// Only soft-deduplicate deparos records with similar responses under same path prefix.
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
	} else {
		// Discovery skipped — still seed CLI targets if SPA or DA will run
		needsDBRecords := r.options.SPAEnabled || !r.options.SkipAudit
		if needsDBRecords {
			r.setPhaseTag("seed")
			r.scanLogger.Info("seed", "seeding CLI targets")
			if err := r.seedCLITargets(ctx, infra); err != nil {
				r.scanLogger.Error("seed", "CLI target seeding failed: "+err.Error())
				return fmt.Errorf("CLI target seeding failed: %w", err)
			}
			r.scanLogger.Info("seed", "seeding completed")
		} else {
			zap.L().Info("Discovery skipped, no downstream phases need DB records")
			r.scanLogger.Info("discovery", "skipped, no downstream phases need DB records")
		}
	}

	// SPA — opt-in via --spa or yaml spa.enabled
	if r.options.SPAEnabled {
		r.setPhaseTag("spa")
		r.scanLogger.Info("spa", "phase started")
		if err := r.runSPAPhase(ctx, infra); err != nil {
			zap.L().Error("SPA phase failed", zap.Error(err))
			r.scanLogger.Error("spa", "phase failed: "+err.Error())
		} else {
			r.scanLogger.Info("spa", "phase completed")

			// Deduplicate findings after SPA phase
			r.deduplicateFindings(ctx, "SPA")
		}
	}

	// Audit — runs if modules exist and not skipped by strategy
	if !r.options.SkipAudit {
		r.setPhaseTag("audit")
		activeModules, passiveModules := r.resolveAllModules(infra)
		if len(activeModules) > 0 || len(passiveModules) > 0 {
			r.scanLogger.InfoWithMeta("audit", "phase started", map[string]interface{}{
				"active_modules":  len(activeModules),
				"passive_modules": len(passiveModules),
			})
			if err := r.runAuditPhase(ctx, infra, activeModules, passiveModules); err != nil {
				zap.L().Error("Audit phase failed", zap.Error(err))
				r.scanLogger.Error("audit", "phase failed: "+err.Error())
			} else {
				r.scanLogger.Info("audit", "phase completed")
			}
		} else {
			zap.L().Info("No modules to execute")
			r.scanLogger.Info("audit", "skipped, no modules to execute")
		}
	} else {
		zap.L().Info("Audit skipped by scanning strategy")
		r.scanLogger.Info("audit", "skipped by scanning strategy")
	}

	r.scanLogger.Info("", "scan finished")
	return nil
}

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
func (r *Runner) buildInfrastructure() (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-id
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
			if len(r.options.Sessions) > 0 || r.options.AuthConfigPath != "" || len(r.options.SessionFiles) > 0 {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			zap.L().Warn("Failed to initialize sessions", zap.Error(err))
		}
		return infra, nil
	}

	// Create notifier with backends
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend

		// Telegram backend (from settings or env)
		tgOpts := r.buildTelegramOptions()
		if tg, err := telegram.NewBackend(tgOpts...); err == nil {
			backends = append(backends, tg)
			zap.L().Info("[Notify] Telegram backend enabled")
		}

		// Discord backend (from settings or env)
		webhookURL := r.settings.Notify.Discord.WebhookURL
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

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: r.settings.Notify.Severities,
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
	if r.settings != nil && r.settings.Audit.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   r.options.ScanUUID,
			Repository: r.repository,
		}
		if r.settings != nil {
			scopeCfg := r.settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			jsEngineOpts.ScopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
		}
		jsEngine, err := jsext.NewEngine(&r.settings.Audit.Extensions, httpRequester, jsEngineOpts)
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
		if len(r.options.Sessions) > 0 || r.options.AuthConfigPath != "" || len(r.options.SessionFiles) > 0 {
			return nil, fmt.Errorf("session initialization failed: %w", err)
		}
		zap.L().Warn("Failed to initialize sessions", zap.Error(err))
	}

	return infra, nil
}

// initSessions loads, validates, hydrates sessions and creates compare requesters.
func (r *Runner) initSessions(infra *phaseInfra) error {
	opts := r.options
	sessionCfg := r.settings.ScanningStrategy.Session
	hasSessions := len(opts.Sessions) > 0
	hasAuthConfig := opts.AuthConfigPath != ""
	hasSessionFiles := len(opts.SessionFiles) > 0

	if !hasSessions && !hasAuthConfig && !hasSessionFiles {
		return nil
	}

	var sessions []*session.Session

	switch {
	case hasAuthConfig:
		loaded, err := session.LoadFromConfig(opts.AuthConfigPath)
		if err != nil {
			return err
		}
		sessions = loaded
	case hasSessionFiles:
		loaded, err := session.LoadFromSessionFiles(opts.SessionFiles, sessionCfg.SessionDir)
		if err != nil {
			return err
		}
		sessions = loaded
	case hasSessions:
		loaded, err := session.LoadFromInlineFlags(opts.Sessions)
		if err != nil {
			return err
		}
		sessions = loaded
	}

	mgr, err := session.NewManager(sessions, session.WithSessionDir(sessionCfg.SessionDir))
	if err != nil {
		return err
	}

	// Execute login flows
	if err := mgr.HydrateSessions(); err != nil {
		return fmt.Errorf("session hydration failed: %w", err)
	}

	// Merge primary session headers into the main requester's options.
	// When use_in_discovery is false, primary headers are only applied to the
	// audit phase requester (handled downstream), not the main one used
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
		infra.compareSessions = append(infra.compareSessions, compareSession{
			Name:   cs.Name,
			Client: compareRequester,
		})
	}

	zap.L().Info("Multi-session scanning enabled",
		zap.String("primary", mgr.Primary().Name),
		zap.Int("compare_sessions", len(cmpSessions)))

	return nil
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
func (r *Runner) runDiscoveryPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	// Build the composite input source locally (avoid mutating r.inputSource)
	var sources []source.InputSource
	var discoveryTargets []string // merged deparos targets for verbose printing

	// Add deparos content discovery source if enabled.
	var discoverSrc *source.DeparosDiscoverySource
	if r.options.DiscoverEnabled && len(r.options.Targets) > 0 {
		// Expand deparos targets with hosts from prior phases
		additionalTargets, err := r.getInScopeHostURLs(ctx, infra.scopeMatcher)
		if err != nil {
			zap.L().Warn("Discovery: failed to get DB hosts for deparos expansion", zap.Error(err))
		}

		// When enrich_targets is enabled, also include paths from prior phases
		enrichTargets := false
		if r.settings != nil {
			enrichTargets = r.settings.Discovery.EnrichTargets
		}
		if enrichTargets && r.repository != nil {
			pathTargets, pathErr := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
			if pathErr != nil {
				zap.L().Warn("Discovery: failed to get DB paths for enrichment", zap.Error(pathErr))
			} else if len(pathTargets) > 0 {
				pathURLs := buildDiscoveryTargetsFromPaths(pathTargets)
				additionalTargets = dedupTargets(additionalTargets, pathURLs)
				zap.L().Info("Discovery: enriched targets with paths from prior phases",
					zap.Int("path_targets", len(pathURLs)))
			}
		}

		discoveryTargets = dedupTargets(r.options.Targets, additionalTargets)
		deparosCfg := r.buildDeparosConfig(additionalTargets)
		discoverSrc, err = source.NewDeparosDiscoverySource(deparosCfg)
		if err != nil {
			zap.L().Warn("Failed to initialize deparos discovery", zap.Error(err))
		} else {
			sources = append(sources, discoverSrc)
		}
	} else {
		discoveryTargets = r.options.Targets
	}

	// Always include the original input source
	sources = append(sources, r.inputSource)

	// Build the final composite source
	var compositeSource source.InputSource
	if len(sources) == 1 {
		compositeSource = sources[0]
	} else {
		compositeSource = source.NewMultiSource(sources[0], sources[1])
	}

	r.printPhaseStart("Discovery", "ingest inputs and discover directories, files, and hidden endpoints via Deparos content discovery")
	r.printPhaseDetail(fmt.Sprintf("Sources: deparos-discover=%s",
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled))))

	speedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		discPace := r.settings.ScanningPace.ResolvePhase("discovery")
		if discPace.MaxDuration > 0 {
			speedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(discPace.MaxDuration.String()))
		}
		if discPace.DurationFactor > 0 {
			speedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", discPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(speedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(discoveryTargets)

	enrichTargetsEnabled := false
	if r.settings != nil {
		enrichTargetsEnabled = r.settings.Discovery.EnrichTargets
	}
	if !enrichTargetsEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s enrich discovery targets with discovered paths via %s\n",
			terminal.TipPrefix(),
			terminal.HiCyan("vigolium config discovery.enrich_targets=true"))
	}

	zap.L().Info("Discovery: ingesting input into database")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic: r.makeOnTraffic("discovery"),
		OnResult: func(result *output.ResultEvent) {
			// Discovery phase has no modules, but OnResult still needed for DB storage
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, compositeSource, nil, nil)
	_, err := executor.Execute(ctx)
	if err != nil {
		return err
	}

	// Increment processed_count for discovery phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Discovery: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Discovery", fmt.Sprintf("completed — %s items ingested (deparos=%s) in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())),
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled)),
		terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("Discovery: completed", zap.Int64("processed", executor.Processed()))

	// Print discovery status code stats
	if discoverSrc != nil {
		stats := discoverSrc.Stats()
		if stats.TotalDiscovered > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("discovered %s records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.TotalDiscovered)),
				formatStatusCodeArray(stats.AllCodes)))
		}
		if stats.HardDedupRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("deduplicated %s redundant records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.HardDedupRemoved)),
				formatStatusCodeArray(stats.DedupedCodes)))
		}
	}

	return nil
}

// seedCLITargets ingests CLI targets into the database without running deparos or modules.
// This is used when discovery is skipped but downstream phases (SPA, Audit)
// need DB records to operate on.
func (r *Runner) seedCLITargets(ctx context.Context, infra *phaseInfra) error {
	r.printPhaseStart("Seed", "ingest CLI targets into database (discovery skipped)")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("seed"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, r.inputSource, nil, nil)
	_, err := executor.Execute(ctx)
	if err != nil {
		return err
	}

	// Increment processed_count for seed phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Seed: failed to increment processed count", zap.Error(err))
		}
	}

	zap.L().Info("Seed: CLI targets ingested", zap.Int64("processed", executor.Processed()))
	r.printPhaseComplete("Seed", fmt.Sprintf("completed — %s items ingested",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed()))))
	return nil
}

// runSpideringPhase runs browser-based crawling using spitolas.
// Captured traffic is stored in vigolium's HTTPRecord table via RepositoryWriter.
// Targets are merged from CLI targets and in-scope hosts discovered by prior phases.
func (r *Runner) runSpideringPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil {
		return fmt.Errorf("spidering requires a database repository")
	}

	phaseStart := time.Now()
	r.printPhaseStart("Spidering", "browser-based crawling to discover dynamic content and API endpoints")

	settingsCfg := r.settings.Spidering
	maxDuration := settingsCfg.MaxDurationParsed()
	if r.options.SpideringMaxDuration > 0 {
		maxDuration = r.options.SpideringMaxDuration
	}

	// Merge CLI targets with in-scope hosts from prior phases (ExternalHarvest)
	targets := r.options.Targets
	dbHosts, err := r.getInScopeHostURLs(ctx, infra.scopeMatcher)
	if err != nil {
		zap.L().Warn("Spidering: failed to get DB hosts", zap.Error(err))
	}
	targets = dedupTargets(targets, dbHosts)
	zap.L().Info("Spidering: merged targets",
		zap.Int("cli", len(r.options.Targets)),
		zap.Int("from_db", len(dbHosts)),
		zap.Int("total", len(targets)))

	// Filter targets by heuristics results (only CLI targets are filtered)
	if r.heuristicsResults != nil {
		before := len(targets)
		targets = filterTargetsByHeuristics(targets, r.heuristicsResults, func(hr *HeuristicsResult) bool {
			return hr.SkipSpidering
		})
		if skipped := before - len(targets); skipped > 0 {
			zap.L().Info("Spidering: targets filtered by heuristics",
				zap.Int("skipped", skipped), zap.Int("remaining", len(targets)))
		}
		if len(targets) == 0 {
			r.printPhaseComplete("Spidering", "skipped — all targets excluded by heuristics check")
			return nil
		}
	}

	configDetail := fmt.Sprintf("Config: max-duration=%s, strategy=%s, headless=%s",
		terminal.HiTeal(maxDuration.String()),
		terminal.HiTeal(settingsCfg.Strategy),
		terminal.HiTeal(fmt.Sprintf("%v", settingsCfg.Headless)))
	if r.settings != nil {
		spiderPace := r.settings.ScanningPace.ResolvePhase("spidering")
		if spiderPace.DurationFactor > 0 {
			configDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", spiderPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(configDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(targets)))
	r.printVerboseTargets(targets)

	var totalStates, totalActions, totalRecords int
	for _, target := range targets {
		zap.L().Info("Spidering target", zap.String("target", target))

		cfg := spitolas.SpiderConfig{
			TargetURL:           target,
			MaxDepth:            settingsCfg.MaxDepth,
			MaxStates:           settingsCfg.MaxStates,
			MaxDuration:         maxDuration,
			MaxConsecutiveFails: settingsCfg.MaxConsecutiveFails,
			Headless:            settingsCfg.Headless,
			BrowserCount:        settingsCfg.BrowserCount,
			Strategy:            settingsCfg.Strategy,
			IncludeResponseBody: settingsCfg.IncludeResponseBody,
			IncludeHeaders:      true,
			Silent:              r.options.Silent,
			Verbose:             r.options.Verbose,
			BrowserEngine:       settingsCfg.BrowserEngine,
			NoCDP:               settingsCfg.NoCDP,
			NoForms:             settingsCfg.NoForms,
			ProxyURL:            r.options.ProxyURL,
		}

		// Apply scope filter to skip out-of-scope traffic before saving to DB
		if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
			sm := infra.scopeMatcher
			cfg.ScopeFilter = func(host, path string) bool {
				return sm.InScopeRequest(host, path, "", "")
			}
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, maxDuration)
		result, err := spitolas.RunSpider(timeoutCtx, cfg, r.repository)
		cancel()

		if err != nil {
			zap.L().Error("Spidering failed",
				zap.String("target", target), zap.Error(err))
			continue
		}

		totalStates += result.StatesDiscovered
		totalActions += result.ActionsExecuted
		totalRecords += result.RecordsSaved

		zap.L().Info("Spidering completed for target",
			zap.String("target", target),
			zap.Int("states", result.StatesDiscovered),
			zap.Int("actions", result.ActionsExecuted),
			zap.Int("records_saved", result.RecordsSaved))
	}

	// Increment processed_count for spidering phase
	if r.repository != nil && totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Spidering: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Spidering", fmt.Sprintf("completed — %s records, %s states, %s actions in %s",
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Orange(fmt.Sprintf("%d", totalStates)),
		terminal.Orange(fmt.Sprintf("%d", totalActions)),
		terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// runSPAPhase orchestrates nuclei + kingfisher batch scanning.
func (r *Runner) runSPAPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("SPA", "assess security posture with Nuclei templates and third-party validation checks")
	if r.settings != nil {
		spaPace := r.settings.ScanningPace.ResolvePhase("spa")
		if spaPace.MaxDuration > 0 || spaPace.DurationFactor > 0 {
			detail := "Speed:"
			if spaPace.MaxDuration > 0 {
				detail += fmt.Sprintf(" max-duration=%s", terminal.HiTeal(spaPace.MaxDuration.String()))
			}
			if spaPace.DurationFactor > 0 {
				detail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", spaPace.DurationFactor)))
			}
			r.printPhaseDetail(detail)
		}
	}
	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.SPA.EnrichTargets
	}
	if !enrichTargets && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s enrich SPA targets with discovered paths via %s\n",
			terminal.TipPrefix(),
			terminal.HiCyan("vigolium config spa.enrich_targets=true"))
	}
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	if r.repository != nil && r.options.Verbose {
		paths, _ := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
		if len(paths) > 0 {
			var spaTargets []string
			if enrichTargets {
				spaTargets = buildSPATargetsFromPaths(paths)
			} else {
				spaTargets = buildSPAHostTargets(paths)
			}
			r.printVerboseTargets(spaTargets)
		}
	}
	zap.L().Info("SPA: running security posture assessment")

	// Track findings by severity
	var mu sync.Mutex
	counts := make(map[severity.Severity]int)

	onResult := func(result *output.ResultEvent) {
		mu.Lock()
		counts[result.Info.Severity]++
		mu.Unlock()

		if err := r.output.Write(result); err != nil {
			zap.L().Error("SPA: failed to write result", zap.Error(err))
		}
	}

	// Nuclei scan on distinct hosts
	if err := r.runSPA(ctx, onResult); err != nil {
		zap.L().Error("SPA: Nuclei scan failed", zap.Error(err))
	}

	// Kingfisher batch scan on all response bodies
	if err := r.runKingfisherBatch(ctx, infra, onResult); err != nil {
		zap.L().Error("SPA: Kingfisher batch failed", zap.Error(err))
	}

	// Print summary
	var total int
	for _, c := range counts {
		total += c
	}
	if total > 0 {
		r.printPhaseDetail(formatSPASummary(counts, total))
	}

	// Increment processed_count for SPA phase
	if r.repository != nil && total > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(total)); err != nil {
			zap.L().Warn("SPA: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("SPA", fmt.Sprintf("completed in %s", terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}

// formatSPASummary builds a compact severity breakdown string for SPA findings.
func formatSPASummary(counts map[severity.Severity]int, total int) string {
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

	zap.L().Info("SPA: Kingfisher batch — scanning response bodies for secrets")

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

			result, scanErr := scanner.Scan(ctx, record.ResponseBody)
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
					ModuleID: "spa-kingfisher",
					Info: output.Info{
						Name:        f.RuleName(),
						Description: "Leaked secret detected: " + f.RuleID(),
						Severity:    sev,
						Confidence:  conf,
						Tags:        []string{"secret", "credential", "exposure", "spa"},
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
					FindingSource: database.FindingSourceSPA,
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

	zap.L().Info("SPA: Kingfisher batch completed", zap.Int("findings", totalFindings))
	return nil
}

// runAuditPhase runs all modules on DB records with a feedback loop for newly discovered URLs.
func (r *Runner) runAuditPhase(ctx context.Context, infra *phaseInfra, activeModules []modules.ActiveModule, passiveModules []modules.PassiveModule) error {
	phaseStart := time.Now()

	if r.repository == nil {
		return fmt.Errorf("audit: database repository required")
	}

	r.printPhaseStart("Audit", "execute dynamic security assessments through coordinated active and passive scanning modules")
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
		daPace := r.settings.ScanningPace.ResolvePhase("audit")
		if daPace.MaxDuration > 0 {
			daSpeedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(daPace.MaxDuration.String()))
		}
		if daPace.DurationFactor > 0 {
			daSpeedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", daPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(daSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))

	zap.L().Info("Audit: running modules on database records",
		zap.Int("active", len(activeModules)),
		zap.Int("passive", len(passiveModules)))

	// If SPA was enabled, filter out secret-detect to avoid duplicate kingfisher findings
	if r.options.SPAEnabled {
		passiveModules = filterOutPassiveModule(passiveModules, secret_detect.ModuleID)
	}

	// Wire compare session clients into the authz-compare module
	if len(infra.compareSessions) > 0 {
		clients := make([]*http.Requester, len(infra.compareSessions))
		names := make([]string, len(infra.compareSessions))
		for i, cs := range infra.compareSessions {
			clients[i] = cs.Client
			names[i] = cs.Name
		}
		for _, mod := range activeModules {
			if ac, ok := mod.(*authz_compare.Module); ok {
				ac.SetCompareClients(clients, names)
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

	// Resolve audit concurrency: scanning_pace.audit overrides global when CLI not explicit
	daConcurrency := r.options.Concurrency
	if r.settings != nil && !r.options.ConcurrencyExplicitlySet {
		daPace := r.settings.ScanningPace.ResolvePhase("audit")
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
			zap.L().Warn("Audit: OAST initialization failed, continuing without OAST", zap.Error(err))
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
	var auditMaxDuration time.Duration
	auditParallelPassive := true // default for audit phase
	var auditFeedbackDrain time.Duration
	if r.settings != nil {
		auditPace := r.settings.ScanningPace.ResolvePhase("audit")
		auditMaxDuration = auditPace.MaxDuration
		auditParallelPassive = auditPace.ParallelPassive
		auditFeedbackDrain = auditPace.FeedbackDrainTimeout
	}

	// Feedback loop: re-scan newly discovered URLs
	for round := 0; round < maxFeedbackRounds; round++ {
		roundStart := time.Now()
		dbSource := database.NewOneShotDBInputSource(r.repository.DB(), r.repository, infra.scanUUID).
			WithHostnames(inScopeHostnames)

		// Create batched record writer for throughput
		var recordWriter *database.RecordWriter
		if r.repository != nil {
			recordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		}

		executorCfg := core.ExecutorConfig{
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
			MaxDuration:          auditMaxDuration,
			ParallelPassive:      auditParallelPassive,
			FeedbackDrainTimeout: auditFeedbackDrain,
			IPCache:              ipCache,
			OnTraffic:            r.makeOnTrafficVerbose("audit"),
			OnResult: func(result *output.ResultEvent) {
				if err := r.output.Write(result); err != nil {
					zap.L().Error("Failed to write result", zap.Error(err))
				}
			},
		}
		if oastService != nil {
			executorCfg.OASTProvider = oastService
			executorCfg.OASTService = oastService
		}
		if infra.hookChain != nil {
			executorCfg.Hooks = infra.hookChain
		}

		executor := core.NewExecutor(executorCfg, dbSource, activeModules, passiveModules)
		if oastService != nil {
			oastService.SetRequestUUIDResolver(executor.ResolveRequestUUID)
		}
		_, err := executor.Execute(ctx)

		// Close the batched record writer to flush remaining records
		if recordWriter != nil {
			recordWriter.Close()
		}

		// Log request clustering stats for this round
		if c := infra.httpRequester.Clusterer(); c != nil {
			c.LogStats()
		}

		if err != nil {
			zap.L().Error("Audit: executor error", zap.Error(err), zap.Int("round", round))
			break
		}

		roundElapsed := time.Since(roundStart)
		r.printPhaseComplete("Audit",
			fmt.Sprintf("round %d — %s items in %s", round+1, terminal.Orange(fmt.Sprintf("%d", executor.Processed())), terminal.HiPurple(fmtDuration(roundElapsed))))
		zap.L().Info("Audit: round completed",
			zap.Int("round", round+1),
			zap.Int64("processed", executor.Processed()))

		// Deduplicate findings after each audit round
		r.deduplicateFindings(ctx, "Audit")

		// Check for newly discovered records by reading the current cursor from the scan record.
		if round < maxFeedbackRounds-1 {
			currentScan, scanErr := r.repository.GetScanByUUID(ctx, infra.scanUUID)
			if scanErr != nil {
				break
			}
			newCount, countErr := r.repository.CountRecordsAfterCursor(ctx, currentScan.CursorAt, currentScan.CursorUUID, inScopeHostnames...)
			if countErr != nil || newCount == 0 {
				break
			}
			r.printPhaseFeedback("Audit",
				fmt.Sprintf("%s new records discovered, starting round %d", terminal.Orange(fmt.Sprintf("%d", newCount)), round+2))
			zap.L().Info("Audit: new records discovered, starting next round",
				zap.Int64("new_records", newCount))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Audit", fmt.Sprintf("all rounds completed in %s", terminal.HiPurple(fmtDuration(elapsed))))

	return nil
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
		if activeUsingAll && !isAllModules(r.settings.Audit.EnabledModules.ActiveModules) {
			activeModules = modules.GetActiveModulesByIDs(r.settings.Audit.EnabledModules.ActiveModules)
			zap.L().Info("Active modules filtered by config", zap.Strings("ids", r.settings.Audit.EnabledModules.ActiveModules))
		}

		if passiveUsingAll && !isAllModules(r.settings.Audit.EnabledModules.PassiveModules) {
			passiveModules = modules.GetPassiveModulesByIDs(r.settings.Audit.EnabledModules.PassiveModules)
			zap.L().Info("Passive modules filtered by config", zap.Strings("ids", r.settings.Audit.EnabledModules.PassiveModules))
		}
	}

	// Sort by severity (lowest first)
	if len(activeModules) > 0 {
		sort.Slice(activeModules, func(i, j int) bool {
			return activeModules[i].Severity() < activeModules[j].Severity()
		})
		zap.L().Info("Active modules to execute", zap.Int("count", len(activeModules)))
	}

	if len(passiveModules) > 0 {
		sort.Slice(passiveModules, func(i, j int) bool {
			return passiveModules[i].Severity() < passiveModules[j].Severity()
		})
		zap.L().Info("Passive modules to execute", zap.Int("count", len(passiveModules)))
	}

	return activeModules, passiveModules
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

// buildSPATargetsFromPaths takes distinct path records from the DB and returns
// deduplicated target URLs with path prefixes (last segment stripped).
func buildSPATargetsFromPaths(paths []database.PathTarget) []string {
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

// buildSPAHostTargets returns deduplicated host-level URLs (scheme://host[:port]/)
// without path-prefix expansion. This is faster but provides less granular coverage.
func buildSPAHostTargets(paths []database.PathTarget) []string {
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

// runSPA executes Security Posture Assessment using the nuclei Go library.
func (r *Runner) runSPA(ctx context.Context, onResult func(*output.ResultEvent)) error {
	if r.repository == nil {
		return fmt.Errorf("spa: database repository required")
	}

	// Query distinct paths from DB and build targets
	paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
	if err != nil {
		return fmt.Errorf("spa: failed to query paths: %w", err)
	}
	if len(paths) == 0 {
		zap.L().Info("SPA: no hosts in database, skipping")
		return nil
	}

	enrichTargets := true
	if r.settings != nil {
		enrichTargets = r.settings.SPA.EnrichTargets
	}

	var targets []string
	if enrichTargets {
		targets = buildSPATargetsFromPaths(paths)
	} else {
		targets = buildSPAHostTargets(paths)
	}

	zap.L().Info("SPA: targets from database", zap.Int("count", len(targets)))

	// Build SPA config from settings
	cfg := spa.Config{
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
		spaCfg := &r.settings.SPA
		cfg.Tags = spaCfg.Tags
		cfg.ExcludeTags = spaCfg.ExcludeTags
		cfg.Severities = spaCfg.Severities
		if spaCfg.TemplatesDir != "" {
			cfg.TemplatesDir = config.ExpandPath(spaCfg.TemplatesDir)
		}

		// scanning_pace.spa controls speed
		spaPace := r.settings.ScanningPace.ResolvePhase("spa")
		if !r.options.ConcurrencyExplicitlySet && spaPace.Concurrency > 0 {
			cfg.Concurrency = spaPace.Concurrency
		}
		if spaPace.RateLimit > 0 {
			cfg.RateLimit = spaPace.RateLimit
		}
		if spaPace.MaxDuration > 0 {
			cfg.Timeout = spaPace.MaxDuration
		}
	}

	return spa.Run(ctx, cfg)
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
		RecursionEnabled:   true,
		RecursionDepth:     5,
		SaveResponseBody:   true,
		UseObservedNames:   true,
		UseObservedPaths:   true,
		UseObservedFiles:   true,
		EnableNumericFuzzing: false,
		TestCustom:         true,
		TestObserved:       true,
		TestBackupExtensions:       true,
		TestNoExtension:    true,
		CaseSensitivity:    "auto_detect",
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

		// Malformed path probe
		cfg.EnableMalformedPathProbe = dc.EnableMalformedPathProbe

		// MaxDuration is resolved via scanning_pace (applied to r.options by scan.go)
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

// runSASTPhase runs ast-grep source code analysis to extract routes and parameters.
// Discovered routes are printed to stdout and optionally ingested into the database.
// When opts.SASTAdhoc is set, runs in ad-hoc mode (no DB ingestion).
func (r *Runner) runSASTPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	r.printPhaseStart("SAST", "extract routes and parameters from application source code using ast-grep")

	// Determine whether this is an ad-hoc scan (--sast-adhoc flag, no DB ingestion)
	adHocMode := r.options.SASTAdhoc != ""

	// Collect source repo paths to scan
	var repoPaths []sourceRepoInfo
	if adHocMode {
		repoInfo := sourceRepoInfo{path: r.options.SASTAdhoc}

		// Create a SourceRepo DB record for the ad-hoc repo
		if r.repository != nil {
			absPath := r.options.SASTAdhoc
			if !filepath.IsAbs(absPath) {
				if ap, err := filepath.Abs(absPath); err == nil {
					absPath = ap
				}
			}
			hostname := r.firstTargetHostname()
			sr := &database.SourceRepo{
				ProjectUUID: r.options.ProjectUUID,
				ScanUUID:    infra.scanUUID,
				Hostname:    hostname,
				Name:        filepath.Base(absPath),
				RootPath:    absPath,
				RepoURL:     "",
				RepoType:    "folder",
			}
			if err := r.repository.CreateSourceRepo(ctx, sr); err != nil {
				zap.L().Warn("sast: failed to create source repo record", zap.Error(err))
			} else {
				repoInfo.dbID = sr.ID
				repoInfo.dbRecord = sr
				repoInfo.hostname = hostname
			}
		}

		repoPaths = append(repoPaths, repoInfo)
	} else {
		if globalSourcePath := r.getSourcePath(); globalSourcePath != "" {
			repoPaths = append(repoPaths, sourceRepoInfo{path: globalSourcePath})
		}

		// Look up source repos from DB
		if r.repository != nil {
			for _, t := range r.options.Targets {
				u, parseErr := neturl.Parse(t)
				if parseErr != nil || u.Hostname() == "" {
					continue
				}
				repos, dbErr := r.repository.GetSourceReposByHostname(ctx, r.options.ProjectUUID, u.Hostname())
				if dbErr != nil {
					continue
				}
				for _, sr := range repos {
					repoPaths = append(repoPaths, sourceRepoInfo{
						path:     sr.RootPath,
						hostname: sr.Hostname,
					})
				}
			}
		}
	}

	if len(repoPaths) == 0 {
		r.printPhaseDetail("No source repos found. Use --sast-adhoc <path>, --source <path>, or 'vigolium source add' to link a repo.")
		return nil
	}

	// Ensure ast-grep binary is available
	scannerCfg := astgrep.DefaultConfig()
	if r.settings != nil && r.settings.SourceAware.AstGrep.RulesDir != "" {
		scannerCfg.RulesDir = config.ExpandPath(r.settings.SourceAware.AstGrep.RulesDir)
	}
	scanner, err := astgrep.NewScanner(scannerCfg)
	if err != nil {
		return fmt.Errorf("sast: create scanner: %w", err)
	}
	if err := scanner.EnsureBinary(ctx); err != nil {
		return fmt.Errorf("sast: binary unavailable: %w", err)
	}

	r.printPhaseDetail(fmt.Sprintf("Binary: %s (%s)", terminal.HiTeal(scanner.BinaryPath()), terminal.Gray(scanner.Version())))
	r.printPhaseDetail(fmt.Sprintf("Rules: %s", terminal.HiTeal(scannerCfg.RulesDir)))
	if r.options.SASTRuleFilter != "" {
		r.printPhaseDetail(fmt.Sprintf("Rule filter: %s", terminal.HiTeal(r.options.SASTRuleFilter)))
	}
	if adHocMode {
		r.printPhaseDetail(fmt.Sprintf("Mode: %s", terminal.Orange("ad-hoc")))
	}

	var totalRoutes int
	for _, repo := range repoPaths {
		r.printPhaseDetail(fmt.Sprintf("Scanning %s", terminal.Cyan(repo.path)))

		// Run ast-grep scan with all rules (optionally filtered by --rule)
		result, scanErr := scanner.ScanDirWithRules(ctx, repo.path, r.options.SASTRuleFilter)
		if scanErr != nil {
			zap.L().Error("sast: scan failed", zap.String("repo", repo.path), zap.Error(scanErr))
			continue
		}

		// Convert matches to routes
		routes := astgrep.MatchesToRoutes(result.Matches)
		if len(routes) == 0 {
			r.printPhaseDetail(fmt.Sprintf("  No routes found in %s", terminal.Gray(repo.path)))
			continue
		}

		totalRoutes += len(routes)

		// Log individual routes at DEBUG level
		for _, route := range routes {
			method := route.Method
			if method == "" {
				method = "ANY"
			}
			params := ""
			if len(route.Params) > 0 {
				params = " params=[" + strings.Join(route.Params, ", ") + "]"
			}
			zap.L().Debug("sast: route discovered",
				zap.String("method", method),
				zap.String("path", route.Path),
				zap.String("params", params),
				zap.String("location", fmt.Sprintf("%s:%d", route.File, route.Line)))
		}

		// Print summary stats
		if !r.options.Silent {
			fmt.Fprintf(os.Stderr, "  %s %s routes discovered in %s\n",
				terminal.Green(terminal.SymbolSuccess),
				terminal.Orange(fmt.Sprintf("%d", len(routes))),
				terminal.Cyan(repo.path))
		}

		// Ingest routes into DB only if NOT in ad-hoc mode
		if !adHocMode {
			hostname := repo.hostname
			if hostname == "" {
				hostname = r.firstTargetHostname()
			}

			if r.repository != nil && hostname != "" {
				r.ingestRoutes(ctx, infra, routes, hostname)
			}
		}

		// Store ast-grep matches as findings in the DB
		if r.repository != nil {
			r.ingestAstGrepFindings(ctx, infra.scanUUID, result.Matches, routes, repo.path)
		}

		// Update SourceRepo with extracted endpoints and route params
		if repo.dbRecord != nil && r.repository != nil {
			endpointSet := make(map[string]struct{})
			paramSet := make(map[string]struct{})
			for _, route := range routes {
				if route.Path != "" {
					endpointSet[route.Path] = struct{}{}
				}
				for _, p := range route.Params {
					paramSet[p] = struct{}{}
				}
			}
			sr := repo.dbRecord
			sr.Endpoints = lo.Keys(endpointSet)
			sr.RouteParams = lo.Keys(paramSet)
			// Detect framework from rule set (e.g. "express", "nextjs")
			if rs := result.RuleSet; rs != "" && rs != "all" && !strings.HasPrefix(rs, "filter:") {
				sr.Framework = rs
			}
			sort.Strings(sr.Endpoints)
			sort.Strings(sr.RouteParams)
			if updateErr := r.repository.UpdateSourceRepo(ctx, sr); updateErr != nil {
				zap.L().Warn("sast: failed to update source repo with endpoints", zap.Error(updateErr))
			}
		}

		zap.L().Info("sast: scan completed",
			zap.String("repo", repo.path),
			zap.String("rule_filter", r.options.SASTRuleFilter),
			zap.Int("matches", len(result.Matches)),
			zap.Int("routes", len(routes)))
	}

	// Discover and ingest API spec files (OpenAPI/Swagger, Postman, curl-in-markdown) from source repos
	var totalSpecRoutes int
	var totalSpecFiles int
	if r.repository != nil {
		for _, repo := range repoPaths {
			specs := discoverAPISpecs(repo.path)
			if len(specs) == 0 {
				continue
			}

			hostname := repo.hostname
			if hostname == "" {
				hostname = r.firstTargetHostname()
			}

			if !r.options.Silent {
				fmt.Fprintf(os.Stderr, "  %s Discovered %s API spec file(s) in %s\n",
					terminal.Purple(terminal.SymbolInfo),
					terminal.Orange(fmt.Sprintf("%d", len(specs))),
					terminal.Cyan(repo.path))
			}

			repoSpecRoutes := 0
			for _, spec := range specs {
				totalSpecFiles++

				zap.L().Info("sast: discovered api spec",
					zap.String("type", spec.specType),
					zap.String("file", spec.relPath),
					zap.String("repo", repo.path))

				if !adHocMode && hostname != "" {
					ingested := r.ingestAPISpecRoutes(ctx, infra, spec, hostname)
					totalSpecRoutes += ingested
					repoSpecRoutes += ingested

					if !r.options.Silent {
						fmt.Fprintf(os.Stderr, "    %s %s — %s records ingested\n",
							terminal.Green(terminal.SymbolSuccess),
							terminal.Cyan(fmt.Sprintf("[%s] %s", apiSpecDisplayName(spec.specType), spec.relPath)),
							terminal.Orange(fmt.Sprintf("%d", ingested)))
					}
				} else {
					// Ad-hoc mode or no hostname: just print discovery
					if !r.options.Silent {
						fmt.Fprintf(os.Stderr, "    %s %s\n",
							terminal.Green(terminal.SymbolSuccess),
							terminal.Cyan(fmt.Sprintf("[%s] %s", apiSpecDisplayName(spec.specType), spec.relPath)))
					}
				}
			}

			if !r.options.Silent && repoSpecRoutes > 0 {
				fmt.Fprintf(os.Stderr, "  %s Total: %s records ingested from %s spec file(s)\n",
					terminal.Green(terminal.SymbolSuccess),
					terminal.Orange(fmt.Sprintf("%d", repoSpecRoutes)),
					terminal.Orange(fmt.Sprintf("%d", len(specs))))
			}
		}
	}

	// Run Kingfisher secret detection on source repos
	var totalKingfisherFindings int
	kfScanner, kfErr := kingfisher.NewScanner(nil)
	if kfErr != nil {
		zap.L().Warn("sast: failed to create kingfisher scanner", zap.Error(kfErr))
	} else if kfErr = kfScanner.EnsureBinary(ctx); kfErr != nil {
		zap.L().Warn("sast: kingfisher binary unavailable", zap.Error(kfErr))
	} else {
		r.printPhaseDetail(fmt.Sprintf("Kingfisher: %s (%s)", terminal.HiTeal(kfScanner.BinaryPath()), terminal.Gray(kfScanner.Version())))
		for _, repo := range repoPaths {
			kfResult, scanErr := kfScanner.ScanDir(ctx, repo.path)
			if scanErr != nil {
				zap.L().Warn("sast: kingfisher scan failed", zap.String("repo", repo.path), zap.Error(scanErr))
				continue
			}
			if !kfResult.HasFindings() {
				continue
			}

			if r.repository != nil {
				saved := r.ingestKingfisherSASTFindings(ctx, infra.scanUUID, kfResult.Findings, repo.path)
				totalKingfisherFindings += saved
			}

			if !r.options.Silent {
				fmt.Fprintf(os.Stderr, "  %s %s secrets detected in %s\n",
					terminal.Green(terminal.SymbolSuccess),
					terminal.Orange(fmt.Sprintf("%d", len(kfResult.Findings))),
					terminal.Cyan(repo.path))
			}

			zap.L().Info("sast: kingfisher scan completed",
				zap.String("repo", repo.path),
				zap.Int("findings", len(kfResult.Findings)),
				zap.Duration("duration", kfResult.ScanDuration))
		}
	}

	// Run third-party tools (semgrep, trivy, codeql) if enabled
	var totalThirdPartyFindings int
	tpCfg := r.thirdPartyConfig()
	if tpCfg == nil {
		zap.L().Warn("sast: third-party integration config is nil (settings not loaded?), skipping third-party tools")
	} else if !tpCfg.Enabled {
		zap.L().Info("sast: third-party integration disabled in config")
	} else {
		enabledTools := make([]string, 0)
		for name, tool := range tpCfg.Tools {
			if tool.Enabled {
				enabledTools = append(enabledTools, name)
			}
		}
		zap.L().Info("sast: running third-party tools", zap.Strings("enabled_tools", enabledTools))
	}
	if tpCfg != nil && tpCfg.Enabled {
		stRunner := sourcetools.New(tpCfg, r.repository)
		for _, repo := range repoPaths {
			sr := &database.SourceRepo{
				RootPath:    repo.path,
				Hostname:    repo.hostname,
				ProjectUUID: r.options.ProjectUUID,
			}
			result, err := stRunner.RunAll(ctx, sr)
			if err != nil {
				zap.L().Warn("sast: third-party tools error", zap.String("repo", repo.path), zap.Error(err))
			}
			totalThirdPartyFindings += result.GroupedAt

			for _, f := range result.Findings {
				matched := ""
				if len(f.MatchedAt) > 0 {
					matched = f.MatchedAt[0]
				}
				zap.L().Debug("sast: third-party finding",
					zap.String("module", f.ModuleID),
					zap.String("description", f.Description),
					zap.String("location", matched))

				toolName := "sast"
				if len(f.Tags) >= 2 {
					toolName = f.Tags[1]
				}
				_ = r.output.Write(&output.ResultEvent{
					ModuleID:   f.ModuleID,
					ModuleType: toolName,
					Type:       "sast",
					Info:       output.Info{Name: f.ModuleName, Severity: severityFromString(f.Severity)},
					Matched:    matched,
				})
			}
			if !r.options.Silent && result.GroupedAt > 0 {
				groupMsg := fmt.Sprintf("%s third-party findings in %s",
					terminal.Orange(fmt.Sprintf("%d", result.GroupedAt)),
					terminal.Cyan(repo.path))
				if result.RawCount > result.GroupedAt {
					groupMsg += fmt.Sprintf(" (%s raw findings grouped into %s)",
						terminal.Gray(fmt.Sprintf("%d", result.RawCount)),
						terminal.Orange(fmt.Sprintf("%d", result.GroupedAt)))
				}
				fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Green(terminal.SymbolSuccess), groupMsg)
			}
		}
	}

	elapsed := time.Since(phaseStart)
	summary := fmt.Sprintf("completed — %s routes extracted", terminal.Orange(fmt.Sprintf("%d", totalRoutes)))
	if totalSpecRoutes > 0 {
		summary += fmt.Sprintf(", %s api-spec records from %s file(s)",
			terminal.Orange(fmt.Sprintf("%d", totalSpecRoutes)),
			terminal.Orange(fmt.Sprintf("%d", totalSpecFiles)))
	}
	if totalKingfisherFindings > 0 {
		summary += fmt.Sprintf(", %s secrets detected", terminal.Orange(fmt.Sprintf("%d", totalKingfisherFindings)))
	}
	if totalThirdPartyFindings > 0 {
		summary += fmt.Sprintf(", %s source findings", terminal.Orange(fmt.Sprintf("%d", totalThirdPartyFindings)))
	}
	summary += fmt.Sprintf(" in %s", terminal.HiPurple(fmtDuration(elapsed)))
	r.printPhaseComplete("SAST", summary)

	// Increment processed_count for SAST phase
	sastProcessed := int64(totalRoutes + totalSpecRoutes + totalKingfisherFindings + totalThirdPartyFindings)
	if r.repository != nil && sastProcessed > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, sastProcessed); err != nil {
			zap.L().Warn("SAST: failed to increment processed count", zap.Error(err))
		}
	}

	return nil
}

// runAgentSAST runs AI agent-powered SAST analysis against source repos.
// Returns the total number of findings across all templates and repos.
func (r *Runner) runAgentSAST(ctx context.Context, infra *phaseInfra, repos []sourceRepoInfo) int {
	cfg := r.settings.SourceAware.AgentSAST
	templates := cfg.EffectiveTemplates()

	totalRuns := len(templates) + len(cfg.CustomPrompts)
	r.printPhaseDetail(fmt.Sprintf("Agent SAST: running %d prompt(s) (%d template, %d custom)",
		totalRuns, len(templates), len(cfg.CustomPrompts)))

	engine := agent.NewEngine(r.settings, r.repository)
	defer engine.Close()

	var totalFindings int
	timeout := cfg.TimeoutDuration()

	// Run prompt templates
	for _, tmplID := range templates {
		for _, repo := range repos {
			opts := r.agentSASTOpts(cfg, infra, repo)
			opts.PromptTemplate = tmplID
			totalFindings += r.runSingleAgentSAST(ctx, engine, opts, tmplID, repo.path, timeout)
		}
	}

	// Run custom inline prompts
	for i, prompt := range cfg.CustomPrompts {
		label := fmt.Sprintf("custom-prompt-%d", i+1)
		for _, repo := range repos {
			opts := r.agentSASTOpts(cfg, infra, repo)
			opts.PromptInline = prompt
			opts.Source = label
			totalFindings += r.runSingleAgentSAST(ctx, engine, opts, label, repo.path, timeout)
		}
	}

	return totalFindings
}

// agentSASTOpts builds the common agent.Options for an agent SAST run.
func (r *Runner) agentSASTOpts(cfg config.AgentSASTConfig, infra *phaseInfra, repo sourceRepoInfo) agent.Options {
	hostname := repo.hostname
	if hostname == "" {
		hostname = r.firstTargetHostname()
	}

	var streamWriter io.Writer
	if r.settings.Agent.StreamEnabled() && !r.options.Silent {
		streamWriter = os.Stderr
	}

	opts := agent.Options{
		AgentName:    cfg.Agent,
		SourcePath:   repo.path,
		Hostname:     hostname,
		ScanUUID:     infra.scanUUID,
		ProjectUUID:  r.options.ProjectUUID,
		StreamWriter: streamWriter,
	}
	if len(r.options.Targets) > 0 {
		opts.TargetURL = r.options.Targets[0]
	}
	return opts
}

// runSingleAgentSAST executes one agent run and returns the number of saved findings.
func (r *Runner) runSingleAgentSAST(ctx context.Context, engine *agent.Engine, opts agent.Options, label, repoPath string, timeout time.Duration) int {
	agentCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := engine.Run(agentCtx, opts)
	if err != nil {
		zap.L().Warn("sast: agent run failed",
			zap.String("prompt", label),
			zap.String("repo", repoPath),
			zap.Error(err))
		return 0
	}

	findings := result.SavedCount
	if !r.options.Silent && findings > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s agent findings from %s (%s)\n",
			terminal.Green(terminal.SymbolSuccess),
			terminal.Orange(fmt.Sprintf("%d", findings)),
			terminal.HiTeal(label),
			terminal.Cyan(repoPath))
	}

	zap.L().Info("sast: agent SAST completed",
		zap.String("prompt", label),
		zap.String("repo", repoPath),
		zap.Int("findings", findings),
		zap.Int("skipped", result.SkippedCount))

	return findings
}

// sourceRepoInfo holds source repo metadata for the SAST phase.
type sourceRepoInfo struct {
	path     string
	hostname string
	dbID     int64
	dbRecord *database.SourceRepo // retained after CREATE to avoid re-fetching
}

// firstTargetHostname returns the hostname from the first parseable target URL, or "".
func (r *Runner) firstTargetHostname() string {
	for _, t := range r.options.Targets {
		if u, err := neturl.Parse(t); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return ""
}

// getSourcePath returns the --source path if one was provided.
func (r *Runner) getSourcePath() string {
	return r.options.SourcePath
}

// thirdPartyConfig returns the third-party integration config if available.
func (r *Runner) thirdPartyConfig() *config.ThirdPartyIntegrationConfig {
	if r.settings == nil {
		return nil
	}
	return &r.settings.SourceAware.ThirdPartyIntegration
}

// routeParamPattern matches route parameter placeholders: :paramName, {paramName}, <type:paramName>
var routeParamPattern = regexp.MustCompile(`:(\w+)|\{(\w+)\}|<\w+:(\w+)>`)

// paramNamePatterns maps param name keywords to probe values.
var uuidParamNames = map[string]bool{
	"uuid": true, "guid": true,
}

var emailParamNames = map[string]bool{
	"email": true, "mail": true, "e_mail": true, "email_address": true,
}

var slugParamNames = map[string]bool{
	"slug": true, "handle": true, "username": true, "name": true, "title": true,
}

var pathParamNames = map[string]bool{
	"path": true, "filepath": true, "file_path": true, "filename": true,
}

// probeValueForParam returns a sensible probe value for a parameter name
// based on name heuristics (id→"1", email→"test@example.com", uuid→uuid, etc.).
func probeValueForParam(paramName string) string {
	lower := strings.ToLower(paramName)

	if uuidParamNames[lower] || strings.HasSuffix(lower, "_uuid") || strings.HasSuffix(lower, "uuid") {
		return uuid.New().String()
	}
	if emailParamNames[lower] {
		return "test@example.com"
	}
	if slugParamNames[lower] || pathParamNames[lower] {
		return "test"
	}

	// Default: numeric ID (covers id, userId, pk, etc.)
	return "1"
}

// resolveParameterizedPath substitutes route parameter placeholders with concrete probe values.
func resolveParameterizedPath(path string) string {
	return routeParamPattern.ReplaceAllStringFunc(path, func(match string) string {
		// Extract the parameter name from whichever capture group matched
		subs := routeParamPattern.FindStringSubmatch(match)
		var paramName string
		for _, s := range subs[1:] {
			if s != "" {
				paramName = s
				break
			}
		}
		if paramName == "" {
			return match
		}
		return probeValueForParam(paramName)
	})
}

// probeRoute sends an HTTP request for a whitebox-discovered route and attaches the response.
func (r *Runner) probeRoute(httpRR *httpmsg.HttpRequestResponse, infra *phaseInfra) *httpmsg.HttpRequestResponse {
	respChain, _, err := infra.httpRequester.Execute(httpRR, http.Options{})
	if err != nil {
		zap.L().Debug("whitebox probe failed",
			zap.String("url", httpRR.Target()),
			zap.Error(err))
		return httpRR
	}

	// Copy response bytes before closing (buffer returned to pool on Close)
	fullResp := respChain.FullResponse().Bytes()
	rawCopy := make([]byte, len(fullResp))
	copy(rawCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponse(rawCopy)
	return httpRR.WithResponse(httpResp)
}

// randomProbeToken generates a short random hex token for probe Authorization headers.
func randomProbeToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "vigolium-probe-" + hex.EncodeToString(b)
}

// ingestRoutes converts discovered routes into HTTPRecord entries, probes them
// with live HTTP requests when possible, and saves to DB.
func (r *Runner) ingestRoutes(ctx context.Context, infra *phaseInfra, routes []astgrep.Route, hostname string) {
	// Find a target URL matching the hostname for building full URLs
	var baseURL string
	for _, t := range r.options.Targets {
		u, parseErr := neturl.Parse(t)
		if parseErr != nil || u.Hostname() != hostname {
			continue
		}
		baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		break
	}
	if baseURL == "" {
		baseURL = "https://" + hostname
	}

	canProbe := infra != nil && infra.httpRequester != nil

	// Determine if a session is configured (auth headers already baked into httpRequester)
	hasSession := len(r.options.Sessions) > 0 || r.options.AuthConfigPath != "" || len(r.options.SessionFiles) > 0

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		records []*httpmsg.HttpRequestResponse
	)

	for _, route := range routes {
		if route.Path == "" {
			continue
		}

		method := route.Method
		if method == "" || method == "ANY" || method == "HANDLE" {
			method = "GET"
		}

		resolvedPath := resolveParameterizedPath(route.Path)
		if !strings.HasPrefix(resolvedPath, "/") {
			resolvedPath = "/" + resolvedPath
		}
		fullURL := baseURL + resolvedPath

		httpRR := r.buildRouteRequest(method, fullURL, route)
		if httpRR == nil {
			continue
		}

		if canProbe {
			// If no session is configured, add a random Authorization header
			// to test for auth enforcement gaps
			if !hasSession {
				newReq := httpRR.Request().WithHeader("Authorization", "Bearer "+randomProbeToken())
				httpRR = httpmsg.NewHttpRequestResponse(newReq, httpRR.Response())
			}

			wg.Add(1)
			sem <- struct{}{} // acquire
			go func(rr *httpmsg.HttpRequestResponse) {
				defer wg.Done()
				defer func() { <-sem }() // release

				probed := r.probeRoute(rr, infra)
				mu.Lock()
				records = append(records, probed)
				mu.Unlock()
			}(httpRR)
		} else {
			records = append(records, httpRR)
		}
	}

	wg.Wait()

	if len(records) == 0 {
		return
	}

	if _, err := r.repository.SaveRecordBatch(ctx, records, "ast-grep", r.options.ProjectUUID); err != nil {
		zap.L().Debug("source-aware: failed to save probed routes", zap.Error(err))
	}

	// Deduplicate after probing to remove identical responses
	if _, err := r.repository.DeduplicateRecordsBySource(ctx, r.options.ProjectUUID, "ast-grep"); err != nil {
		zap.L().Debug("source-aware: failed to deduplicate ast-grep records", zap.Error(err))
	}
}

// apiSpecFile holds a discovered API spec file path and its detected type.
type apiSpecFile struct {
	path       string // absolute file path
	specType   string // "openapi", "postman", or "curl-md"
	relPath    string // path relative to repo root (for display)
}

// skipDirs are directories to skip when walking the repo for API spec files.
var apiSpecSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "__pycache__": true, ".venv": true,
	"venv": true, ".tox": true, "target": true, "bin": true, "obj": true,
	".idea": true, ".vscode": true,
}

// discoverAPISpecs walks a repo directory looking for OpenAPI/Swagger specs,
// Postman collections, and Markdown files containing curl commands.
// It validates file contents before returning them (not just filename heuristics).
func discoverAPISpecs(repoPath string) []apiSpecFile {
	var specs []apiSpecFile

	_ = filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if apiSpecSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))

		// Skip files that are too large (>10MB)
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 10*1024*1024 {
			return nil
		}

		// Skip very small files (<20 bytes) — can't contain useful content
		if info.Size() < 20 {
			return nil
		}

		relPath, _ := filepath.Rel(repoPath, path)
		if relPath == "" {
			relPath = filepath.Base(path)
		}

		// Check Markdown files for curl commands
		if ext == ".md" || ext == ".markdown" {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			if markdownHasCurlCommands(string(data)) {
				specs = append(specs, apiSpecFile{path: path, specType: "curl-md", relPath: relPath})
			}
			return nil
		}

		// Only check JSON and YAML for API specs
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		// Check for OpenAPI/Swagger
		if openapi.IsOpenAPISpec(data) {
			specs = append(specs, apiSpecFile{path: path, specType: "openapi", relPath: relPath})
			return nil
		}

		// Check for Postman collection (JSON only)
		if ext == ".json" && isPostmanCollection(data) {
			specs = append(specs, apiSpecFile{path: path, specType: "postman", relPath: relPath})
			return nil
		}

		return nil
	})

	return specs
}

// markdownHasCurlCommands checks if markdown content contains curl commands in fenced code blocks.
func markdownHasCurlCommands(content string) bool {
	inCodeBlock := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock && strings.Contains(trimmed, "curl ") {
			return true
		}
	}
	return false
}

// apiSpecDisplayName returns a human-friendly label for a spec type.
func apiSpecDisplayName(specType string) string {
	switch specType {
	case "openapi":
		return "OpenAPI"
	case "postman":
		return "Postman"
	case "curl-md":
		return "cURL/Markdown"
	default:
		return specType
	}
}

// isPostmanCollection checks if JSON data looks like a Postman Collection v2.x.
func isPostmanCollection(data []byte) bool {
	var probe struct {
		Info *struct {
			Schema string `json:"schema"`
		} `json:"info"`
		Item       json.RawMessage `json:"item"`
		Collection *struct {
			Info *struct {
				Schema string `json:"schema"`
			} `json:"info"`
			Item json.RawMessage `json:"item"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}

	// Check unwrapped format: has "info.schema" containing "collection" and "item" array
	if probe.Info != nil && strings.Contains(probe.Info.Schema, "collection") && len(probe.Item) > 2 {
		return true
	}

	// Check wrapped format: {collection: {info: {schema: ...}, item: [...]}}
	if probe.Collection != nil && probe.Collection.Info != nil &&
		strings.Contains(probe.Collection.Info.Schema, "collection") && len(probe.Collection.Item) > 2 {
		return true
	}

	return false
}

// ingestAPISpecRoutes parses an API spec file and ingests the extracted routes into the DB.
// It uses existing OpenAPI/Postman parsers to generate HttpRequestResponse entries,
// then probes and saves them like ast-grep routes.
func (r *Runner) ingestAPISpecRoutes(ctx context.Context, infra *phaseInfra, spec apiSpecFile, hostname string) int {
	// Determine base URL from targets
	var baseURL string
	for _, t := range r.options.Targets {
		u, parseErr := neturl.Parse(t)
		if parseErr != nil || u.Hostname() != hostname {
			continue
		}
		baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		break
	}
	if baseURL == "" {
		baseURL = "https://" + hostname
	}

	// Collect records from the spec parser
	var parsed []*httpmsg.HttpRequestResponse

	switch spec.specType {
	case "openapi":
		openapiFormat := openapi.New()
		openapiFormat.SetOpenAPIOptions(openapi.Options{
			BaseURL:              baseURL,
			RequiredOnly:         false,
			SkipFormatValidation: true,
		})
		if err := openapiFormat.Parse(spec.path, func(rr *httpmsg.HttpRequestResponse) bool {
			parsed = append(parsed, rr)
			return true
		}); err != nil {
			zap.L().Warn("sast: failed to parse openapi spec",
				zap.String("file", spec.relPath), zap.Error(err))
			return 0
		}

	case "postman":
		postmanFormat := postman.New()
		postmanFormat.SetPostmanOptions(postman.Options{
			BaseURL: baseURL,
		})
		if err := postmanFormat.Parse(spec.path, func(rr *httpmsg.HttpRequestResponse) bool {
			parsed = append(parsed, rr)
			return true
		}); err != nil {
			zap.L().Warn("sast: failed to parse postman collection",
				zap.String("file", spec.relPath), zap.Error(err))
			return 0
		}

	case "curl-md":
		curlFormat := curl.New()
		if err := curlFormat.Parse(spec.path, func(rr *httpmsg.HttpRequestResponse) bool {
			// Filter: only keep requests targeting the scan hostname.
			// Markdown files often contain example curls for localhost or other domains.
			if target := rr.Target(); target != "" {
				u, parseErr := neturl.Parse(target)
				if parseErr == nil && u.Hostname() != "" && u.Hostname() != hostname {
					return true // skip, continue iterating
				}
			}
			parsed = append(parsed, rr)
			return true
		}); err != nil {
			zap.L().Warn("sast: failed to parse curl commands from markdown",
				zap.String("file", spec.relPath), zap.Error(err))
			return 0
		}
	}

	if len(parsed) == 0 {
		return 0
	}

	// Probe routes concurrently (same pattern as ingestRoutes)
	canProbe := infra != nil && infra.httpRequester != nil

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		records []*httpmsg.HttpRequestResponse
	)

	for _, rr := range parsed {
		if canProbe {
			wg.Add(1)
			sem <- struct{}{}
			go func(rr *httpmsg.HttpRequestResponse) {
				defer wg.Done()
				defer func() { <-sem }()

				probed := r.probeRoute(rr, infra)
				mu.Lock()
				records = append(records, probed)
				mu.Unlock()
			}(rr)
		} else {
			records = append(records, rr)
		}
	}

	wg.Wait()

	if len(records) == 0 {
		return 0
	}

	sourceLabel := spec.specType
	if sourceLabel != "curl-md" {
		sourceLabel += "-spec"
	}
	if _, err := r.repository.SaveRecordBatch(ctx, records, sourceLabel, r.options.ProjectUUID); err != nil {
		zap.L().Debug("sast: failed to save api-spec routes",
			zap.String("source", sourceLabel), zap.Error(err))
		return 0
	}

	if _, err := r.repository.DeduplicateRecordsBySource(ctx, r.options.ProjectUUID, sourceLabel); err != nil {
		zap.L().Debug("sast: failed to deduplicate api-spec records",
			zap.String("source", sourceLabel), zap.Error(err))
	}

	return len(records)
}

// ingestAstGrepFindings converts ast-grep matches into Finding records grouped by category.
// Matches are grouped by their rule category (e.g., "express", "security-xss") and each
// category produces a single Finding with a markdown table description of all matches.
func (r *Runner) ingestAstGrepFindings(ctx context.Context, scanUUID string, matches []astgrep.Match, routes []astgrep.Route, repoPath string) {
	// Build a lookup of routes by file:line for enriching finding descriptions
	routesByLocation := make(map[string]astgrep.Route)
	for _, route := range routes {
		key := fmt.Sprintf("%s:%d", route.File, route.Line)
		routesByLocation[key] = route
	}

	// Group matches by category
	type matchEntry struct {
		match    astgrep.Match
		location string
		route    *astgrep.Route
	}
	groups := make(map[string][]matchEntry)

	for _, m := range matches {
		if m.ID == "" {
			m.ID = "ast-grep"
		}
		location := fmt.Sprintf("%s:%d", m.File, m.Range.Start.Line+1)
		cat := astGrepCategory(m.ID)

		entry := matchEntry{match: m, location: location}
		if route, ok := routesByLocation[location]; ok {
			entry.route = &route
		}

		groups[cat] = append(groups[cat], entry)

		zap.L().Debug("sast: ast-grep match",
			zap.String("rule", m.ID),
			zap.String("category", cat),
			zap.String("location", location),
			zap.String("text", m.Text),
		)

		if strings.HasPrefix(cat, "security-") {
			mappedSev := astGrepSeverity(m.Severity)
			_ = r.output.Write(&output.ResultEvent{
				ModuleID:   m.ID,
				ModuleType: "ast-grep",
				Type:       "sast",
				Info:       output.Info{Name: m.ID, Severity: severityFromString(mappedSev)},
				Matched:    location,
			})
		}
	}

	// Create one finding per category
	var saved int
	for cat, entries := range groups {
		isRouteCategory := !strings.HasPrefix(cat, "security-")

		// Collect unique filenames and find highest severity
		fileSet := make(map[string]struct{})
		highestSev := "info"
		for _, e := range entries {
			fileSet[e.match.File] = struct{}{}
			if !isRouteCategory {
				highestSev = higherSeverity(highestSev, astGrepSeverity(e.match.Severity))
			}
		}
		files := make([]string, 0, len(fileSet))
		for f := range fileSet {
			files = append(files, f)
		}
		sort.Strings(files)

		// Build description and evidence
		var desc strings.Builder
		var evidence []string

		if isRouteCategory {
			// Route categories: show routes table, put raw ast-grep JSON in evidence
			fmt.Fprintf(&desc, "## Routes found in %s\n\n", astGrepCategoryName(cat))
			desc.WriteString("| Method | Path | Params | Source |\n")
			desc.WriteString("|--------|------|--------|--------|\n")
			var matches []astgrep.Match
			for _, e := range entries {
				if e.route != nil {
					method := e.route.Method
					if method == "" {
						method = "ANY"
					}
					params := ""
					if len(e.route.Params) > 0 {
						params = strings.Join(e.route.Params, ", ")
					}
					fmt.Fprintf(&desc, "| %s | %s | %s | %s |\n",
						escapeMarkdownTable(method),
						escapeMarkdownTable(e.route.Path),
						escapeMarkdownTable(params),
						escapeMarkdownTable(e.location),
					)
				}
				matches = append(matches, e.match)
			}
			if j, err := json.Marshal(matches); err == nil {
				evidence = append(evidence, string(j))
			}
		} else {
			// Security categories: show findings table, put raw ast-grep JSON in evidence
			fmt.Fprintf(&desc, "## %s\n\n", astGrepCategoryName(cat))
			desc.WriteString("| Rule | Message | Source |\n")
			desc.WriteString("|------|---------|--------|\n")
			var matches []astgrep.Match
			for _, e := range entries {
				fmt.Fprintf(&desc, "| %s | %s | %s |\n",
					escapeMarkdownTable(e.match.ID),
					escapeMarkdownTable(e.match.Message),
					escapeMarkdownTable(e.location),
				)
				matches = append(matches, e.match)
			}
			if j, err := json.Marshal(matches); err == nil {
				evidence = append(evidence, string(j))
			}
		}

		hashInput := fmt.Sprintf("ast-grep-group:%s:%s", cat, repoPath)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

		finding := &database.Finding{
			ProjectUUID:        r.options.ProjectUUID,
			ScanUUID:           scanUUID,
			ModuleID:           cat,
			ModuleName:         astGrepCategoryName(cat),
			ModuleType:         "sast",
			FindingSource:      "ast-grep",
			Description:        desc.String(),
			Severity:           highestSev,
			Confidence:         "firm",
			Tags:               []string{"sast", "ast-grep", cat},
			MatchedAt:          files,
			AdditionalEvidence: evidence,
			HTTPRecordUUIDs:    []string{},
			FindingHash:        hash,
			FoundAt:            time.Now(),
		}

		if err := r.repository.SaveFindingDirect(ctx, finding); err != nil {
			zap.L().Debug("sast: failed to save ast-grep finding", zap.String("category", cat), zap.Error(err))
			continue
		}
		saved++
	}

	zap.L().Info("sast: ast-grep findings ingested",
		zap.Int("categories", saved),
		zap.Int("total_matches", len(matches)),
	)
}


// ingestKingfisherSASTFindings saves kingfisher secret findings from source code into the database.
func (r *Runner) ingestKingfisherSASTFindings(ctx context.Context, scanUUID string, findings []kingfisher.Finding, repoPath string) int {
	var saved int
	for i := range findings {
		f := &findings[i]

		sev := "high"
		conf := "firm"
		if f.IsValidated() {
			sev = "critical"
			conf = "certain"
		}

		location := f.Finding.Path
		if location == "" {
			location = repoPath
		}
		if f.Finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, f.Finding.Line)
		}

		hashInput := fmt.Sprintf("sast-kingfisher:%s:%s:%s:%d", f.RuleID(), repoPath, f.Finding.Path, f.Finding.Line)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))

		finding := &database.Finding{
			ProjectUUID:        r.options.ProjectUUID,
			ScanUUID:           scanUUID,
			ModuleID:           "sast-kingfisher",
			ModuleName:         f.RuleName(),
			ModuleType:         database.ModuleTypeSAST,
			FindingSource:      "kingfisher",
			Description:        fmt.Sprintf("Secret detected in source code: %s (%s)", f.RuleName(), f.RuleID()),
			Severity:           sev,
			Confidence:         conf,
			Tags:               []string{"sast", "kingfisher", "secret", "credential"},
			MatchedAt:          []string{location},
			AdditionalEvidence: []string{f.Snippet()},
			HTTPRecordUUIDs:    []string{},
			FindingHash:        hash,
			FoundAt:            time.Now(),
		}

		if err := r.repository.SaveFindingDirect(ctx, finding); err != nil {
			zap.L().Debug("sast: failed to save kingfisher finding", zap.String("rule", f.RuleID()), zap.Error(err))
			continue
		}
		saved++
	}

	zap.L().Info("sast: kingfisher findings ingested",
		zap.Int("saved", saved),
		zap.Int("total", len(findings)),
	)
	return saved
}
// astGrepCategory extracts the category from a rule ID.
// Security rules (e.g., "security-xss-foo") use the first two segments ("security-xss").
// Framework rules (e.g., "express-route-handler") use the first segment ("express").
func astGrepCategory(ruleID string) string {
	parts := strings.SplitN(ruleID, "-", 3)
	if len(parts) == 0 {
		return "ast-grep"
	}
	if parts[0] == "security" && len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return parts[0]
}

// astGrepCategoryName returns a human-readable display name for an ast-grep category.
func astGrepCategoryName(category string) string {
	names := map[string]string{
		"express":         "Express Routes",
		"flask":           "Flask Routes",
		"gin":             "Gin Routes",
		"django":          "Django Routes",
		"spring":          "Spring Routes",
		"fastapi":         "FastAPI Routes",
		"laravel":         "Laravel Routes",
		"nextjs":          "Next.js Routes",
		"gohttp":          "Go HTTP Routes",
		"php":             "PHP Routes",
		"security-auth":   "Security: Authentication",
		"security-config": "Security: Configuration",
		"security-cors":   "Security: CORS",
		"security-nextjs": "Security: Next.js",
		"security-secrets": "Security: Secrets",
		"security-xss":    "Security: XSS",
	}
	if name, ok := names[category]; ok {
		return name
	}
	// Fallback: title-case the category
	return strings.Title(strings.ReplaceAll(category, "-", " ")) //nolint:staticcheck
}

// escapeMarkdownTable escapes pipe characters and newlines in text for use in markdown table cells.
func escapeMarkdownTable(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// higherSeverity returns the higher of two severity levels.
func higherSeverity(a, b string) string {
	if b == "" {
		return a
	}
	order := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

// astGrepSeverity maps ast-grep native severities to vigolium severities.
func astGrepSeverity(s string) string {
	switch strings.ToLower(s) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "hint":
		return "low"
	default:
		return "info"
	}
}

// severityFromString converts a severity string to a severity.Severity constant.
func severityFromString(s string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "info":
		return severity.Info
	default:
		return severity.Info
	}
}

// buildMinimalRequest creates a minimal HttpRequestResponse for a given method and URL.
func (r *Runner) buildMinimalRequest(method, rawURL string) *httpmsg.HttpRequestResponse {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil
	}

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, u.RequestURI(), u.Host)
	rr, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	return rr
}

// buildRouteRequest creates an HttpRequestResponse enriched with query/body parameters
// from an ast-grep Route. For GET/HEAD/DELETE, params become query string values.
// For POST/PUT/PATCH, body params become a JSON body; remaining params go to query string.
func (r *Runner) buildRouteRequest(method, rawURL string, route astgrep.Route) *httpmsg.HttpRequestResponse {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil
	}

	// Determine which params go to query vs body
	queryParams := route.QueryParams
	bodyParams := route.BodyParams

	// If no typed params available, use generic Params with method-based heuristic
	if len(queryParams) == 0 && len(bodyParams) == 0 && len(route.Params) > 0 {
		switch method {
		case "POST", "PUT", "PATCH":
			bodyParams = route.Params
		default:
			queryParams = route.Params
		}
	}

	// Append query params to URL
	if len(queryParams) > 0 {
		q := u.Query()
		for _, p := range queryParams {
			q.Set(p, probeValueForParam(p))
		}
		u.RawQuery = q.Encode()
	}

	// Build body for POST/PUT/PATCH with body params
	var body string
	var contentType string
	if len(bodyParams) > 0 && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyMap := make(map[string]string, len(bodyParams))
		for _, p := range bodyParams {
			bodyMap[p] = probeValueForParam(p)
		}
		if jsonBytes, jsonErr := json.Marshal(bodyMap); jsonErr == nil {
			body = string(jsonBytes)
			contentType = "application/json"
		}
	}

	// Build raw request
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, u.RequestURI()))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))
	if contentType != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
		sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	rr, err := httpmsg.ParseRawRequest(sb.String())
	if err != nil {
		return nil
	}
	return rr
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
func dedupTargets(base, additional []string) []string {
	seen := make(map[string]struct{}, len(base)+len(additional))
	result := make([]string, 0, len(base)+len(additional))
	for _, t := range base {
		if _, exists := seen[t]; !exists {
			seen[t] = struct{}{}
			result = append(result, t)
		}
	}
	for _, t := range additional {
		if _, exists := seen[t]; !exists {
			seen[t] = struct{}{}
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

