package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/bulkhttp"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
)

// DiscoveryConfig holds configuration for deparos content discovery.
type DiscoveryConfig struct {
	Mode                     string                   `yaml:"mode"`
	ScopeMode                string                   `yaml:"scope_mode"`
	Recursion                DiscoveryRecursionConfig `yaml:"recursion"`
	Wordlists                DiscoveryWordlistConfig  `yaml:"wordlists"`
	Extensions               DiscoveryExtensionConfig `yaml:"extensions"`
	Engine                   DiscoveryEngineConfig    `yaml:"engine"`
	JSTangle                 DiscoveryJSTangleConfig  `yaml:"jstangle"`
	Sitemap                  DiscoverySitemapConfig   `yaml:"sitemap"`
	SaveResponseBody         bool                     `yaml:"save_response_body"`
	EnableMalformedPathProbe bool                     `yaml:"enable_malformed_path_probe"`
	DedupClusterCap          *int                     `yaml:"dedup_cluster_cap"`   // cap near-identical discovery responses (same host/status/content-type, size & words within 0.5%) per cluster; nil=default(10), 0=disabled, N=keep at most N
	AutoFuzzLowYield         *bool                    `yaml:"auto_fuzz_low_yield"` // auto-enable FUZZ fuzzing on the original target when spidering came up low-yield or hit an SSO/login wall; nil=default(on)
	EnrichTargets            bool                     `yaml:"enrich_targets"`      // enrich discovery targets with paths from previous phases (spidering, external harvest)
	ExpandSeedParents        bool                     `yaml:"expand_seed_parents"` // expand each seed URL into its parent directories (e.g., /a/b/c -> /, /a/, /a/b/, /a/b/c) and feed them as additional targets to discovery and spidering
	PassiveModuleTags        []string                 `yaml:"passive_module_tags"` // run passive modules matching these tags during discovery (e.g., ["fingerprint"])
	ReSpider                 DiscoveryReSpiderConfig  `yaml:"respider"`            // targeted re-spider of rich/SPA routes found after discovery dedup
	DeparosDedup             DeparosDedupConfig       `yaml:"deparos_dedup"`       // post-discovery status-retention + reflected-URL-robust record dedup
	// ExtractWords harvests words from response bodies into the observed-name
	// wordlist (deparos WordlistExtraction). nil = auto: on at --intensity deep,
	// off otherwise; true/false force it.
	ExtractWords *bool `yaml:"extract_words"`

	// PhaseMaxDuration caps the whole discovery phase ("" = default:
	// --discover-max-time × min(targets, 3); "0" = no phase ceiling). Each
	// target keeps its own --discover-max-time budget inside it; without a
	// phase ceiling 1000 targets at width 3 had no upper bound at all.
	PhaseMaxDuration string `yaml:"phase_max_duration"`

	// TargetConcurrency is how many targets are discovered at once; targets on
	// the same host:port never overlap and the engine threads are split across
	// the targets in flight. 0 = default (min(targets, 3)); 1 = one at a time.
	TargetConcurrency int `yaml:"target_concurrency"`
	// FlushInterval is how often a running target's JS/form/API-spec records are
	// persisted and handed to the scan (also every 500 new nodes). "" = default
	// (15s); "0" = only when the target finishes.
	FlushInterval string `yaml:"flush_interval"`
	// StreamFuzz streams the wordlist/spider (fuzz) class with every flush too,
	// deduplicated keep-first and cluster-capped first-N-wins as it is read.
	// nil = default (true); false keeps it until the target finishes (keep the
	// shorter path, cap shortest-path-first). No effect with flush_interval "0".
	StreamFuzz *bool `yaml:"stream_fuzz"`
}

// PhaseMaxDurationValue resolves discovery.phase_max_duration: the configured
// duration, or perTarget × min(targets, 3) when unset. 0 = no ceiling.
func (c *DiscoveryConfig) PhaseMaxDurationValue(perTarget time.Duration, targets int) time.Duration {
	if strings.TrimSpace(c.PhaseMaxDuration) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(c.PhaseMaxDuration))
		if err != nil || d <= 0 {
			return 0
		}
		return d
	}
	if perTarget <= 0 || targets <= 0 {
		return 0
	}
	return perTarget * time.Duration(min(targets, 3))
}

// StreamsFuzz resolves discovery.stream_fuzz (default true).
func (c *DiscoveryConfig) StreamsFuzz() bool {
	return c.StreamFuzz == nil || *c.StreamFuzz
}

// maxDiscoveryTargetConcurrency bounds discovery.target_concurrency: each
// concurrent target holds its own engine and siteMap in memory.
const maxDiscoveryTargetConcurrency = 32

// FlushIntervalValue resolves discovery.flush_interval for the discovery
// source: 0 means "use the source default", a negative value turns in-crawl
// flushing off. Validate rejects anything unparseable, so a bad value here
// falls back to the default.
func (c *DiscoveryConfig) FlushIntervalValue() time.Duration {
	if c.FlushInterval == "" {
		return 0
	}
	d, err := time.ParseDuration(c.FlushInterval)
	if err != nil {
		return 0
	}
	if d <= 0 {
		return -1
	}
	return d
}

type DiscoveryJSTangleConfig struct {
	Enabled            *bool  `yaml:"enabled"`
	ReplayMode         string `yaml:"replay_mode"`
	ReplaySafety       string `yaml:"replay_safety"`
	SourceMaps         *bool  `yaml:"source_maps"`
	AssetGraph         *bool  `yaml:"asset_graph"`
	ProtocolHandshake  bool   `yaml:"protocol_handshake"`
	WorkerCount        int    `yaml:"worker_count"`
	MemoryBudgetMB     int    `yaml:"memory_budget_mb"`
	CacheMB            int    `yaml:"cache_mb"`
	WorkerMaxJobs      int    `yaml:"worker_max_jobs"`
	WorkerMaxRSSMB     int    `yaml:"worker_max_rss_mb"`
	JobTimeout         string `yaml:"job_timeout"`
	NormalInputMB      int    `yaml:"normal_input_mb"`
	MaxASTInputMB      int    `yaml:"max_ast_input_mb"`
	MaxUnpackInputMB   int    `yaml:"max_unpack_input_mb"`
	HardInputMB        int    `yaml:"hard_input_mb"`
	MaxRequestsPerFile int    `yaml:"max_requests_per_file"`
	MaxASTNodes        int    `yaml:"max_ast_nodes"`
	MaxAssetDepth      int    `yaml:"max_asset_depth"`
	MaxAssetsPerParent int    `yaml:"max_assets_per_parent"`
	MaxAssetsPerHost   int    `yaml:"max_assets_per_host"`
	MaxAssetsTotal     int    `yaml:"max_assets_total"`
	// MaxChunksPerRuntime bounds webpack/Vite chunks rendered from one bundle's
	// loader runtime (replaces max_assets_per_parent for them). 0 = 512.
	MaxChunksPerRuntime int `yaml:"max_chunks_per_runtime"`

	// Persistence of JS-derived request templates that did not become
	// discovery nodes; they are stored as source=jstangle http_records.
	PersistUnreplayed           *bool `yaml:"persist_unreplayed"`              // also store templates never sent (withheld/deduped/unresolved); nil = true
	PersistNotFoundEmitStatuses []int `yaml:"persist_not_found_emit_statuses"` // not-found replay statuses handed to later phases; nil = [400,405,415,422], [] = none
	MaxPersistedJSTemplates     int   `yaml:"max_persisted_js_templates"`      // per-target cap on stored templates; 0 = 2000
}

// DiscoverySitemapConfig controls the sitemap source: discovery fetches the
// sitemaps robots.txt names (or /sitemap.xml and /sitemap_index.xml when it
// names none), feeds every in-scope <loc> path to the observed-path wordlist,
// and spiders a path-shape sample of them.
type DiscoverySitemapConfig struct {
	Enabled     *bool `yaml:"enabled"`      // nil = true
	MaxURLs     int   `yaml:"max_urls"`     // sampled locs spidered per target; 0 = 2000. Hitting it notes the sitemap_cap limit
	PerShape    int   `yaml:"per_shape"`    // sampled locs per host + path shape; 0 = 3
	FollowIndex *bool `yaml:"follow_index"` // fetch <sitemapindex> children (depth <= 2, <= 16 per index); nil = true
}

// IsEnabled reports whether the sitemap source runs; nil defaults to on.
func (c DiscoverySitemapConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// FollowsIndex reports whether sitemap index children are fetched; nil defaults to on.
func (c DiscoverySitemapConfig) FollowsIndex() bool { return c.FollowIndex == nil || *c.FollowIndex }

// IsEnabled reports whether jstangle analysis runs; nil defaults to on, matching
// the sibling *Config.IsEnabled helpers in this file and boolPtrOr on the runner side.
func (c *DiscoveryJSTangleConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// DeparosDedupConfig controls the post-discovery cleanup of stored deparos
// records, running after the discovery phase over the full record set (in
// addition to the in-engine per-target hard dedup and the soft-dedup pass):
//
//   - a status-retention policy that drops 4xx discovery records (a fuzzed path
//     the server rejects with a client error is not a discovered resource),
//     keeping a single representative per host for "auth wall exists" statuses;
//   - reflected-URL-robust dedup that collapses records differing only by an
//     echoed request URL/path or per-request dynamic tokens.
type DeparosDedupConfig struct {
	Enabled          *bool `yaml:"enabled"`            // nil = default (true)
	DropClientErrors *bool `yaml:"drop_client_errors"` // drop 4xx discovery records; nil = default (true)
	// KeepOnePerHost statuses are collapsed to one representative per host instead
	// of dropped. nil = default ([429]: pacing); empty slice = collapse none.
	KeepOnePerHost []int `yaml:"keep_one_per_host"`
	// KeepPerPath statuses preserve every distinct path, capped per host by
	// PerPathCap (AuthWallCap for 401/403). nil = default
	// ([401,403,405,415,422]: authz walls and wrong-method/payload routes are
	// each a target); empty slice = keep none per-path.
	KeepPerPath []int `yaml:"keep_per_path"`
	// PerPathCap bounds distinct KeepPerPath paths kept per (host, status). 0 =
	// default (100); negative = unbounded.
	PerPathCap int `yaml:"per_path_cap"`
	// AuthWallCap bounds distinct 401/403 paths kept per host. 0 = default
	// (25); negative = use per_path_cap.
	AuthWallCap        int   `yaml:"auth_wall_cap"`
	NormalizeReflected *bool `yaml:"normalize_reflected"` // collapse records differing only by a reflected URL/path or dynamic tokens; nil = default (true)
}

// IsEnabled reports whether the post-discovery deparos dedup runs (default on).
func (c *DeparosDedupConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// DropClientErrorsEnabled reports whether 4xx discovery records are dropped
// (default on).
func (c *DeparosDedupConfig) DropClientErrorsEnabled() bool {
	return c.DropClientErrors == nil || *c.DropClientErrors
}

// NormalizeReflectedEnabled reports whether reflected-URL-robust dedup runs
// (default on).
func (c *DeparosDedupConfig) NormalizeReflectedEnabled() bool {
	return c.NormalizeReflected == nil || *c.NormalizeReflected
}

// KeepOneStatuses returns the statuses collapsed to a single record per host
// rather than dropped. nil (absent YAML) defaults to {429} — a pacing signal is
// worth one record per host. An explicit empty slice collapses none.
func (c *DeparosDedupConfig) KeepOneStatuses() []int {
	if c.KeepOnePerHost == nil {
		return []int{429}
	}
	return c.KeepOnePerHost
}

// KeepPerPathStatuses returns the statuses whose distinct paths are preserved.
// nil (absent YAML) defaults to {401,403,405,415,422}: /admin, /backup and
// /.git at 403 are three forbidden-bypass targets, not one (collapsing auth
// walls to one row per host left the bypass module a single record), and
// 405/415/422 are real routes hit with the wrong method/payload. An explicit
// empty slice keeps none per-path.
func (c *DeparosDedupConfig) KeepPerPathStatuses() []int {
	if c.KeepPerPath == nil {
		return []int{401, 403, 405, 415, 422}
	}
	return c.KeepPerPath
}

// AuthWallCapValue returns the per-host cap on distinct 401/403 paths. 0
// (absent YAML) defaults to 25; negative falls back to the per-path cap.
func (c *DeparosDedupConfig) AuthWallCapValue() int {
	if c.AuthWallCap == 0 {
		return 25
	}
	if c.AuthWallCap < 0 {
		return 0
	}
	return c.AuthWallCap
}

// PerPathCapValue returns the per-(host,status) cap on distinct KeepPerPath
// paths. 0 (absent YAML) defaults to 100; negative disables the cap.
func (c *DeparosDedupConfig) PerPathCapValue() int {
	if c.PerPathCap == 0 {
		return 100
	}
	if c.PerPathCap < 0 {
		return 0
	}
	return c.PerPathCap
}

// DiscoveryReSpiderConfig controls the targeted re-spider step that runs after
// discovery dedup. Discovery (fuzzing/jstangle/linkfinder) can surface new routes
// (e.g. /ui/, /console/) after the one-shot browser spidering already ran. When
// such a route's already-fetched response looks like a JS/SPA shell or an
// interactive page (and not a login/SSO wall), this step re-crawls it with a
// real browser on a tight budget so its client-rendered routes enter
// http_records and get dynamic-assessed. Caps keep the browser spend bounded.
type DiscoveryReSpiderConfig struct {
	Enabled            *bool  `yaml:"enabled"`               // nil = default (true)
	MaxSeedsPerHost    int    `yaml:"max_seeds_per_host"`    // per-host seed cap; 0 = default (3)
	MaxSeedsTotal      int    `yaml:"max_seeds_total"`       // overall seed cap; 0 = default (10)
	PerSeedMaxDuration string `yaml:"per_seed_max_duration"` // per-seed crawl budget; "" = default (45s)
	PerSeedMaxStates   int    `yaml:"per_seed_max_states"`   // per-seed state cap; 0 = default (25)
	MaxDepth           int    `yaml:"max_depth"`             // per-seed crawl depth; 0 = default (3)
	StepMaxDuration    string `yaml:"step_max_duration"`     // wall-clock cap for the whole step; "" = default (5m)
}

// IsEnabled reports whether the targeted re-spider step runs (default on).
func (c *DiscoveryReSpiderConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// SeedsPerHost returns the per-host seed cap, applying the default.
func (c *DiscoveryReSpiderConfig) SeedsPerHost() int {
	if c.MaxSeedsPerHost <= 0 {
		return 3
	}
	return c.MaxSeedsPerHost
}

// SeedsTotal returns the overall seed cap, applying the default.
func (c *DiscoveryReSpiderConfig) SeedsTotal() int {
	if c.MaxSeedsTotal <= 0 {
		return 10
	}
	return c.MaxSeedsTotal
}

// PerSeedDuration returns the per-seed crawl budget, applying the default.
func (c *DiscoveryReSpiderConfig) PerSeedDuration() time.Duration {
	if c.PerSeedMaxDuration == "" {
		return 45 * time.Second
	}
	if d, err := time.ParseDuration(c.PerSeedMaxDuration); err == nil && d > 0 {
		return d
	}
	return 45 * time.Second
}

// PerSeedStates returns the per-seed state cap, applying the default.
func (c *DiscoveryReSpiderConfig) PerSeedStates() int {
	if c.PerSeedMaxStates <= 0 {
		return 25
	}
	return c.PerSeedMaxStates
}

// Depth returns the per-seed crawl depth, applying the default.
func (c *DiscoveryReSpiderConfig) Depth() int {
	if c.MaxDepth <= 0 {
		return 3
	}
	return c.MaxDepth
}

// StepDuration returns the wall-clock cap for the whole step, applying the default.
func (c *DiscoveryReSpiderConfig) StepDuration() time.Duration {
	if c.StepMaxDuration == "" {
		return 5 * time.Minute
	}
	if d, err := time.ParseDuration(c.StepMaxDuration); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// DiscoveryRecursionConfig controls directory traversal depth.
type DiscoveryRecursionConfig struct {
	Enabled  bool `yaml:"enabled"`
	MaxDepth int  `yaml:"max_depth"`
}

// Discovery wordlist tiers (discovery.wordlists.tier). The tier picks which
// embedded dir/file lists fill the "long" slot when no path is configured:
// short = none (short lists only), long = dir-long/file-long (~5k),
// large = dir-large/file-large (~9.3k). auto (or empty) derives it from
// --intensity: deep → large, quick and balanced → short.
const (
	WordlistTierAuto  = "auto"
	WordlistTierShort = "short"
	WordlistTierLong  = "long"
	WordlistTierLarge = "large"
)

// DiscoveryWordlistConfig holds paths to wordlist files.
type DiscoveryWordlistConfig struct {
	Tier                 string `yaml:"tier"` // auto|short|long|large; empty = auto
	ShortFilePath        string `yaml:"short_file_path"`
	LongFilePath         string `yaml:"long_file_path"`
	ShortDirPath         string `yaml:"short_dir_path"`
	LongDirPath          string `yaml:"long_dir_path"`
	FuzzWordlistPath     string `yaml:"fuzz_wordlist_path"`
	UseObservedNames     bool   `yaml:"use_observed_names"`
	UseObservedPaths     bool   `yaml:"use_observed_paths"`
	UseObservedFiles     bool   `yaml:"use_observed_files"`
	EnableNumericFuzzing bool   `yaml:"enable_numeric_fuzzing"`
}

// DiscoveryExtensionConfig controls file extension testing.
type DiscoveryExtensionConfig struct {
	TestCustom           bool     `yaml:"test_custom"`
	CustomList           []string `yaml:"custom_list"`
	TestObserved         bool     `yaml:"test_observed"`
	TestBackupExtensions bool     `yaml:"test_backup_extensions"`
	BackupExtensions     []string `yaml:"backup_extensions"`
	TestNoExtension      bool     `yaml:"test_no_extension"`

	// Confirmation-gated server-side extension fuzzing. Pointer-bool semantics:
	// absent YAML (nil) means use the default. When ConfirmRequired is true the
	// engine only sweeps the wordlist for an extension (.php/.aspx/.jsp/.action/
	// .cgi/…) after confirming the app serves it as a valid route — confirmation
	// is driven by what the site reveals (observed URLs + tech fingerprint), not
	// by brute-force guessing (the active probe is off by default).
	ConfirmRequired       *bool    `yaml:"confirm_required"`        // nil = default (true)
	ConfirmViaObserved    *bool    `yaml:"confirm_via_observed"`    // confirm from observed URLs; nil = true
	ConfirmViaFingerprint *bool    `yaml:"confirm_via_fingerprint"` // confirm from response/cookie fingerprint; nil = true
	ConfirmViaProbe       *bool    `yaml:"confirm_via_probe"`       // confirm via active brute-force soft-404 probe; nil = false (FP-prone on catch-all hosts)
	Candidates            []string `yaml:"candidates"`              // candidate extensions (no dot); empty = built-in
	ProbeFilenames        []string `yaml:"probe_filenames"`         // probe base names; empty = built-in

	// SPA-gated JS-bundle name sweep: probe common JS bundle names (main.js,
	// admin.js, config.js, …) on monolith / server-rendered apps and feed hits
	// to jstangle. Skipped on JS-shell SPAs (content-hashed, unguessable bundles).
	JSBundleSweep *bool    `yaml:"js_bundle_sweep"` // nil = default (true)
	JSBundleNames []string `yaml:"js_bundle_names"` // override curated names; empty = built-in
}

// DiscoveryEngineConfig controls discovery execution settings.
type DiscoveryEngineConfig struct {
	CaseSensitivity         string                       `yaml:"case_sensitivity"`
	Timeout                 string                       `yaml:"timeout"`
	CustomHeaders           map[string]string            `yaml:"custom_headers"`
	EnableCookieJar         bool                         `yaml:"enable_cookie_jar"`
	MaxConsecutiveErrors    int                          `yaml:"max_consecutive_errors"`
	MaxConsecutiveWAFBlocks int                          `yaml:"max_consecutive_waf_blocks"`
	ObservedMaxItems        int                          `yaml:"observed_max_items"`
	DisableSecretScan       bool                         `yaml:"disable_secret_scan"`
	PrefixBreaker           DiscoveryPrefixBreakerConfig `yaml:"prefix_breaker"`
	// Protocol is the wire protocol for discovery traffic: "auto" (default:
	// HTTP/3 where the origin proves it, else HTTP/2 where ALPN selects it,
	// else HTTP/1.1, pinned per origin), "http1", "http2" or "http3".
	Protocol string `yaml:"protocol"`
	// BruteForceConcurrency is each target's worker count for wordlist and
	// FUZZ-template requests; the rest of discovery (spider, observed-word
	// variants, JS) keeps the phase concurrency. 0 = default: the per-host
	// slot cap (scanning_pace.max_per_host), or the phase concurrency when
	// -c was given explicitly.
	BruteForceConcurrency int `yaml:"brute_force_concurrency"`
}

// DiscoveryPrefixBreakerConfig tunes the per-prefix circuit breaker that stops
// discovery from recursing into trap directories (uniform 4xx / soft-200 sinks).
// Pointer-bool semantics aren't used; absent YAML means use defaults from
// pkg/deparos/config/defaults.go.
type DiscoveryPrefixBreakerConfig struct {
	Enabled        *bool   `yaml:"enabled"`         // nil = use deparos default (true)
	MinSamples     int     `yaml:"min_samples"`     // 0 = use deparos default
	TripRatio      float64 `yaml:"trip_ratio"`      // 0 = use deparos default
	PrefixSegments int     `yaml:"prefix_segments"` // 0 = use deparos default
	LengthBucket   int64   `yaml:"length_bucket"`   // 0 = use deparos default
}

// DefaultDiscoveryConfig returns default discovery configuration.
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		Mode:      "files_and_dirs",
		ScopeMode: "subdomain",
		Recursion: DiscoveryRecursionConfig{
			Enabled:  true,
			MaxDepth: 5,
		},
		Wordlists: DiscoveryWordlistConfig{
			UseObservedNames:     true,
			UseObservedPaths:     true,
			UseObservedFiles:     true,
			EnableNumericFuzzing: false,
		},
		Extensions: DiscoveryExtensionConfig{
			TestCustom:           true,
			TestObserved:         true,
			TestBackupExtensions: true,
			TestNoExtension:      true,
		},
		Engine: DiscoveryEngineConfig{
			CaseSensitivity:  "auto_detect",
			Timeout:          "10s",
			ObservedMaxItems: 4000,
		},
		JSTangle: DiscoveryJSTangleConfig{
			// WorkerCount/MemoryBudgetMB 0 = derived from CPUs and RAM. MaxUnpackInputMB
			// 0 follows HardInputMB, so a config written before the unpack tier existed
			// (hard_input_mb: 10, no max_unpack_input_mb) still validates.
			ReplayMode: "exact", ReplaySafety: "read-only", WorkerCount: 0, MemoryBudgetMB: 0, CacheMB: 128,
			WorkerMaxJobs: 100, WorkerMaxRSSMB: 1024, JobTimeout: "60s",
			NormalInputMB: 1, MaxASTInputMB: 4, MaxUnpackInputMB: 0, HardInputMB: 16, MaxRequestsPerFile: 500,
			MaxASTNodes:   500_000,
			MaxAssetDepth: 4, MaxAssetsPerParent: 64, MaxAssetsPerHost: 512, MaxAssetsTotal: 2048,
			MaxChunksPerRuntime:     512,
			MaxPersistedJSTemplates: 2000,
		},
		Sitemap: DiscoverySitemapConfig{
			MaxURLs: deparosconfig.DefaultSitemapMaxURLs, PerShape: deparosconfig.DefaultSitemapPerShape,
		},
		SaveResponseBody: true,
	}
}

// EngineTimeoutParsed returns the parsed engine timeout. Falls back to 10s on error.
func (c *DiscoveryConfig) EngineTimeoutParsed() time.Duration {
	if c.Engine.Timeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(c.Engine.Timeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// Validate checks discovery configuration for errors.
func (c *DiscoveryConfig) Validate() error {
	switch c.Mode {
	case "", "files_and_dirs", "files_only", "dirs_only":
		// valid
	default:
		return fmt.Errorf("discovery.mode: must be files_and_dirs, files_only, or dirs_only, got %q", c.Mode)
	}

	switch c.ScopeMode {
	case "", "any", "subdomain", "exact":
		// valid
	default:
		return fmt.Errorf("discovery.scope_mode: must be any, subdomain, or exact, got %q", c.ScopeMode)
	}

	switch strings.ToLower(strings.TrimSpace(c.Wordlists.Tier)) {
	case "", WordlistTierAuto, WordlistTierShort, WordlistTierLong, WordlistTierLarge:
		// valid
	default:
		return fmt.Errorf("discovery.wordlists.tier: must be auto, short, long, or large, got %q", c.Wordlists.Tier)
	}

	if c.Recursion.Enabled && c.Recursion.MaxDepth < 1 {
		return fmt.Errorf("discovery.recursion.max_depth must be >= 1 when enabled")
	}

	if c.Engine.Timeout != "" {
		d, err := time.ParseDuration(c.Engine.Timeout)
		if err != nil {
			return fmt.Errorf("discovery.engine.timeout: invalid duration %q: %w", c.Engine.Timeout, err)
		}
		if d < 1*time.Second || d > 300*time.Second {
			return fmt.Errorf("discovery.engine.timeout must be 1s-300s, got %v", d)
		}
	}

	if _, err := bulkhttp.ParseMode(c.Engine.Protocol); err != nil {
		return fmt.Errorf("discovery.engine.protocol: %w", err)
	}
	if n := c.Engine.BruteForceConcurrency; n < 0 || n > deparosconfig.MaxBruteForceThreads {
		return fmt.Errorf("discovery.engine.brute_force_concurrency must be 0-%d, got %d", deparosconfig.MaxBruteForceThreads, n)
	}

	switch c.Engine.CaseSensitivity {
	case "", "auto_detect", "sensitive", "insensitive":
		// valid
	default:
		return fmt.Errorf("discovery.engine.case_sensitivity: must be auto_detect, sensitive, or insensitive, got %q", c.Engine.CaseSensitivity)
	}
	switch c.JSTangle.ReplayMode {
	case "", "exact", "conservative", "off":
	default:
		return fmt.Errorf("discovery.jstangle.replay_mode must be exact, conservative, or off")
	}
	switch c.JSTangle.ReplaySafety {
	case "", "metadata-only", "read-only", "safe-baseline", "state-changing":
	default:
		return fmt.Errorf("discovery.jstangle.replay_safety must be metadata-only, read-only, safe-baseline, or state-changing")
	}
	if c.JSTangle.JobTimeout != "" {
		if duration, err := time.ParseDuration(c.JSTangle.JobTimeout); err != nil || duration < time.Second || duration > 5*time.Minute {
			return fmt.Errorf("discovery.jstangle.job_timeout must be a duration between 1s and 5m")
		}
	}
	if c.JSTangle.WorkerCount < 0 || c.JSTangle.WorkerCount > 16 || c.JSTangle.CacheMB < 0 {
		return fmt.Errorf("discovery.jstangle worker/cache budgets are invalid")
	}
	// The deparos engine rejects an ENABLED jstangle whose memory budget is below
	// the floor and then fails to construct, which silently aborts the whole
	// Discovery phase. Mirror deparos's own floor here (shared constant) so an
	// invalid budget surfaces as a clear config error at scan start instead. Gated
	// on IsEnabled to match deparos, which skips all checks when jstangle is off.
	if c.JSTangle.IsEnabled() && !deparosconfig.ValidJSTangleMemoryBudgetMB(c.JSTangle.MemoryBudgetMB) {
		return fmt.Errorf("discovery.jstangle.memory_budget_mb must be 0 (auto) or >= %d when jstangle is enabled, got %d",
			deparosconfig.MinJSTangleMemoryBudgetMB, c.JSTangle.MemoryBudgetMB)
	}
	// Same tier rule deparos enforces at engine construction, checked here so an
	// unpack ceiling above the hard limit is a config error, not a silent clamp.
	if c.JSTangle.IsEnabled() {
		if err := deparosconfig.ValidateJSTangleInputTiers(c.JSTangle.NormalInputMB, c.JSTangle.MaxASTInputMB,
			c.JSTangle.MaxUnpackInputMB, c.JSTangle.HardInputMB); err != nil {
			return fmt.Errorf("discovery.jstangle: %w", err)
		}
	}
	if c.JSTangle.MaxASTNodes != 0 && (c.JSTangle.MaxASTNodes < 1_000 || c.JSTangle.MaxASTNodes > 5_000_000) {
		return fmt.Errorf("discovery.jstangle.max_ast_nodes must be 1000-5000000")
	}
	if c.JSTangle.MaxPersistedJSTemplates < 0 {
		return fmt.Errorf("discovery.jstangle.max_persisted_js_templates must be >= 0, got %d", c.JSTangle.MaxPersistedJSTemplates)
	}
	if c.Sitemap.MaxURLs < 0 {
		return fmt.Errorf("discovery.sitemap.max_urls must be >= 0, got %d", c.Sitemap.MaxURLs)
	}
	if c.Sitemap.PerShape < 0 {
		return fmt.Errorf("discovery.sitemap.per_shape must be >= 0, got %d", c.Sitemap.PerShape)
	}
	for _, status := range c.JSTangle.PersistNotFoundEmitStatuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("discovery.jstangle.persist_not_found_emit_statuses: %d is not an HTTP status", status)
		}
	}

	if c.TargetConcurrency < 0 || c.TargetConcurrency > maxDiscoveryTargetConcurrency {
		return fmt.Errorf("discovery.target_concurrency must be 0 (auto) to %d, got %d", maxDiscoveryTargetConcurrency, c.TargetConcurrency)
	}
	if c.FlushInterval != "" {
		d, err := time.ParseDuration(c.FlushInterval)
		if err != nil {
			return fmt.Errorf("discovery.flush_interval: invalid duration %q: %w", c.FlushInterval, err)
		}
		if d > 0 && d < time.Second {
			return fmt.Errorf("discovery.flush_interval must be 0 (off) or >= 1s, got %v", d)
		}
	}

	if c.ReSpider.PerSeedMaxDuration != "" {
		if _, err := time.ParseDuration(c.ReSpider.PerSeedMaxDuration); err != nil {
			return fmt.Errorf("discovery.respider.per_seed_max_duration: invalid duration %q: %w", c.ReSpider.PerSeedMaxDuration, err)
		}
	}
	if c.ReSpider.StepMaxDuration != "" {
		if _, err := time.ParseDuration(c.ReSpider.StepMaxDuration); err != nil {
			return fmt.Errorf("discovery.respider.step_max_duration: invalid duration %q: %w", c.ReSpider.StepMaxDuration, err)
		}
	}

	return nil
}
