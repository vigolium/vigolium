package runner

import (
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

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

// defaultWordlistDir is where the embedded default wordlists are materialized so
// deparos (which loads wordlists from file paths only) can use them.
// wordlistDirEnv overrides it (absolute or ~-relative).
const (
	defaultWordlistDir = "~/.vigolium/wordlists"
	wordlistDirEnv     = "VIGOLIUM_WORDLIST_DIR"
)

// wordlistDir resolves the directory the embedded default wordlists are written to.
func wordlistDir() string {
	if dir := os.Getenv(wordlistDirEnv); dir != "" {
		return config.ExpandPath(dir)
	}
	return config.ExpandPath(defaultWordlistDir)
}

// resolvedDiscoveryWordlists holds the effective deparos wordlist paths after
// layering: YAML config → CLI --fuzz-wordlist → embedded defaults. The two
// usingX flags drive the header label so it can distinguish operator-supplied
// lists from the bundled fallbacks.
type resolvedDiscoveryWordlists struct {
	shortFile, longFile, shortDir, longDir, fuzz string
	usingEmbedded                                bool // at least one path came from the embedded defaults
	usingConfigured                              bool // at least one path came from YAML / CLI
}

// resolveDiscoveryWordlists computes the wordlist paths feeding deparos. Operator
// config (YAML, then the --fuzz-wordlist CLI override) wins; any gap is filled
// from the embedded defaults — short file/dir lists on every scan, and the heavy
// long lists plus fuzz.txt (which deparos turns into a full /FUZZ brute of the
// root) only at --intensity deep. This is shared by buildDeparosConfig and the
// Discovery phase header so the two never disagree on what is actually running.
func (r *Runner) resolveDiscoveryWordlists() resolvedDiscoveryWordlists {
	var w resolvedDiscoveryWordlists
	expand := func(p string) string {
		if p == "" {
			return ""
		}
		w.usingConfigured = true
		return config.ExpandPath(p)
	}

	if r.settings != nil {
		wl := r.settings.Discovery.Wordlists
		w.shortFile = expand(wl.ShortFilePath)
		w.longFile = expand(wl.LongFilePath)
		w.shortDir = expand(wl.ShortDirPath)
		w.longDir = expand(wl.LongDirPath)
		w.fuzz = expand(wl.FuzzWordlistPath)
	}
	// --fuzz-wordlist is an explicit operator override and wins over YAML.
	if r.options.FuzzWordlistPath != "" {
		w.fuzz = config.ExpandPath(r.options.FuzzWordlistPath)
		w.usingConfigured = true
	}

	deep := strings.EqualFold(r.options.Intensity, "deep")
	fuzzOn, _ := r.discoveryFuzzingState()
	needShortFile := w.shortFile == ""
	needShortDir := w.shortDir == ""
	needLongFile := w.longFile == "" && deep
	needLongDir := w.longDir == "" && deep
	needFuzz := w.fuzz == "" && fuzzOn
	needAny := needShortFile || needShortDir || needLongFile || needLongDir || needFuzz
	if !needAny {
		return w
	}

	paths, err := wordlists.EnsureOnDisk(wordlistDir())
	if err != nil {
		zap.L().Warn("Discovery: failed to materialize embedded wordlists; deparos falls back to observed-only", zap.Error(err))
		return w
	}
	if needShortFile {
		w.shortFile = paths.ShortFile
		w.usingEmbedded = true
	}
	if needShortDir {
		w.shortDir = paths.ShortDir
		w.usingEmbedded = true
	}
	if needLongFile {
		w.longFile = paths.LongFile
		w.usingEmbedded = true
	}
	if needLongDir {
		w.longDir = paths.LongDir
		w.usingEmbedded = true
	}
	if needFuzz {
		w.fuzz = paths.Fuzz
		w.usingEmbedded = true
	}
	return w
}

// discoveryFuzzingState reports whether deparos FUZZ fuzzing is enabled for this
// run, with a short reason for the header. Fuzzing makes deparos auto-append
// /FUZZ and brute-force the (large) fuzz wordlist at each directory, so it is ON
// only when the operator clearly wants it: --fuzz-wordlist supplied, --intensity
// deep, or discovery selected as an explicit phase (e.g. `vigolium run discover`,
// which sets Options.OnlyPhase). It stays OFF on balanced/lite full scans.
func (r *Runner) discoveryFuzzingState() (bool, string) {
	switch {
	case r.options.FuzzWordlistPath != "":
		return true, "via --fuzz-wordlist"
	case strings.EqualFold(r.options.Intensity, "deep"):
		return true, "intensity=deep"
	case r.options.OnlyPhase != "" && OnlyPhaseSet(r.options.OnlyPhase)["discovery"]:
		return true, "discovery-only run"
	case r.autoFuzzDiscovery:
		return true, "auto-enabled (low-yield/SSO target)"
	default:
		return false, "off on balanced/lite full scans (enable via `run discover`, --intensity deep, or --fuzz-wordlist)"
	}
}

// lowYieldSpideringRecords is the spidering record count below which the
// Discovery phase treats the target as "found almost nothing" and auto-enables
// FUZZ fuzzing (the SSO/login-wall case triggers regardless of this count).
const lowYieldSpideringRecords = 10

// shouldAutoFuzzDiscovery decides whether to auto-enable discovery FUZZ fuzzing
// based on the prior Spidering phase outcome. It fires only when fuzzing isn't
// already on, deparos discovery is active with CLI targets, spidering actually
// ran, and spidering came up low-yield — either it bounced off-host to an
// SSO/login wall or returned fewer than lowYieldSpideringRecords records. Gated
// by discovery.auto_fuzz_low_yield (nil/absent = on).
func (r *Runner) shouldAutoFuzzDiscovery() bool {
	if r.settings != nil && r.settings.Discovery.AutoFuzzLowYield != nil && !*r.settings.Discovery.AutoFuzzLowYield {
		return false
	}
	if !r.options.DiscoverEnabled || len(r.options.Targets) == 0 {
		return false
	}
	// Don't override an already-on fuzzing mode (it would just relabel the reason).
	if on, _ := r.discoveryFuzzingState(); on {
		return false
	}
	if !r.spidering.ran {
		return false
	}
	return r.spidering.sawSSO || r.spidering.records < lowYieldSpideringRecords
}

// filterOutHosts drops target URLs whose host matches any host in block
// (case-insensitive). Used to keep off-host SSO/login domains out of the
// discovery/fuzzing scope so auto-fuzz only hits the original target host(s).
func filterOutHosts(targets, block []string) []string {
	if len(block) == 0 || len(targets) == 0 {
		return targets
	}
	blocked := make(map[string]bool, len(block))
	for _, h := range block {
		blocked[strings.ToLower(h)] = true
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		u, err := neturl.Parse(t)
		if err != nil || u.Host == "" || !blocked[strings.ToLower(u.Host)] {
			out = append(out, t)
		}
	}
	return out
}

// boolPtrOr returns *p when p is non-nil, otherwise def. Used to resolve
// optional (pointer-bool) YAML toggles where absent means "use the default".
func boolPtrOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
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
		// Confirmation-gated extension fuzzing: on by default, all sources.
		ConfirmRequired:       true,
		ConfirmViaObserved:    true,
		ConfirmViaFingerprint: true,
		ConfirmViaProbe:       true,
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

		// Wordlist paths are resolved below (outside this block) so the embedded
		// defaults apply even when no YAML config is loaded.
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

		// Confirmation-gated extension fuzzing (pointer-bool: nil = default true)
		cfg.ConfirmRequired = boolPtrOr(dc.Extensions.ConfirmRequired, true)
		cfg.ConfirmViaObserved = boolPtrOr(dc.Extensions.ConfirmViaObserved, true)
		cfg.ConfirmViaFingerprint = boolPtrOr(dc.Extensions.ConfirmViaFingerprint, true)
		cfg.ConfirmViaProbe = boolPtrOr(dc.Extensions.ConfirmViaProbe, true)
		cfg.Candidates = dc.Extensions.Candidates
		cfg.ProbeFilenames = dc.Extensions.ProbeFilenames

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

		// Near-identical response cluster cap. nil = leave 0 so the source applies
		// its default (on, 10); an explicit non-positive value disables it (mapped
		// to -1 since the source treats 0 as "use default").
		if dc.DedupClusterCap != nil {
			if *dc.DedupClusterCap <= 0 {
				cfg.DedupClusterCap = -1
			} else {
				cfg.DedupClusterCap = *dc.DedupClusterCap
			}
		}

		// MaxDuration is resolved via scanning_pace (applied to r.options by scan.go)
	}

	// Resolve wordlist paths: YAML config → CLI --fuzz-wordlist → embedded
	// defaults (short file/dir always; long lists + fuzz.txt only at --intensity
	// deep). Done here, outside the settings block above, so the embedded defaults
	// still apply when no YAML config is loaded.
	wls := r.resolveDiscoveryWordlists()
	cfg.ShortFilePath = wls.shortFile
	cfg.LongFilePath = wls.longFile
	cfg.ShortDirPath = wls.shortDir
	cfg.LongDirPath = wls.longDir
	cfg.FuzzWordlistPath = wls.fuzz

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
