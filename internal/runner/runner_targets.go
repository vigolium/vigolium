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
