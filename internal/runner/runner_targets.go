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
	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/bulkhttp"
	"github.com/vigolium/vigolium/pkg/database"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// getInScopeDBHosts returns the in-scope (scheme, hostname, port) origins from the
// database according to the CLI targets and origin mode. When no targets are configured,
// returns nil (meaning no origin filter — all records are included).
func (r *Runner) getInScopeDBHosts(ctx context.Context) []database.HostTarget {
	if r.repository == nil || r.settings == nil {
		return nil
	}
	return r.repository.InScopeHosts(ctx, r.settings.Scope, r.options.Targets, r.options.ProjectUUID, r.options.ScanUUID)
}

// resolvedScopeOriginMode is the origin-scope mode this run actually applies —
// the value getInScopeDBHosts above is filtering by. The single accessor every
// reporter uses, so the banner, the run summary, the config snapshot and the
// scans row cannot disagree with the matcher or with each other.
func (r *Runner) resolvedScopeOriginMode() string {
	if r.settings == nil {
		return config.DefaultCLIOriginMode
	}
	return config.ResolveCLIOriginMode(r.settings.Scope.CLIOriginMode)
}

// persistScopeOriginMode stamps the resolved mode on the scan row. Run
// unconditionally rather than only for rows this runner did not create: the
// alternative is a guard that encodes WHO created the row, and the flags
// available to ask that (ScanOnReceive, ManagedScanRecord) do not cover every
// externally-created row — `POST /api/scan-records`, `POST /api/scan-all-records`
// and `vigolium ingest`'s scan row set neither, so a guarded stamp silently
// skipped them. The write is idempotent and once per scan, which is cheaper than
// keeping that list correct.
//
// Best-effort: failing to annotate a scan must not abort it.
func (r *Runner) persistScopeOriginMode(ctx context.Context, scanUUID string) {
	if r.repository == nil {
		return
	}
	if err := r.repository.UpdateScanPartial(ctx, &database.Scan{
		UUID:            scanUUID,
		ScopeOriginMode: r.resolvedScopeOriginMode(),
	}); err != nil {
		zap.L().Warn("Failed to record scope origin mode on scan", zap.Error(err))
	}
}

// normalizeTargetSchemes gives every target in options an explicit scheme.
//
// Both constructors call it because this is the one seam every entry point
// passes: the CLI merges its targets in mergePositionalTargets, but the REST
// handlers, both agent-swarm paths, `scan-url` and launch.Params all assign
// options.Targets directly, and a schemeless target reaching the browser phase
// or targetHostnames below is dropped rather than scanned. Idempotent, so the
// CLI normalizing first (it needs to, to dedup on the normalized spelling)
// costs nothing here.
func normalizeTargetSchemes(options *types.Options) {
	if options == nil {
		return
	}
	for i, t := range options.Targets {
		normalized, assumed := httpmsg.EnsureURLSchemeTracked(t, httpmsg.DefaultTargetScheme)
		options.Targets[i] = normalized
		if !assumed {
			continue
		}
		// Recorded, never cleared: the CLI has usually normalized already (it
		// must, to dedup on the normalized spelling) and marked these itself,
		// so this loop only adds the entries the direct-assignment entry points
		// would otherwise lose. See Options.TargetsSchemeAssumed.
		options.MarkSchemeAssumed(map[string]struct{}{normalized: {}})
	}
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

// buildOriginURL renders an origin as scheme://host[:port], omitting the port when it is
// the scheme default (https→443, http→80).
func buildOriginURL(scheme, host string, port int) string {
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		return fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// buildKnownIssueScanTargetsFromPaths takes distinct path records from the DB and returns
// deduplicated target URLs with path prefixes (last segment stripped).
func buildKnownIssueScanTargetsFromPaths(paths []database.PathTarget) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, p := range paths {
		// Build host base URL
		base := buildOriginURL(p.Scheme, p.Hostname, p.Port)

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
		target := buildOriginURL(p.Scheme, p.Hostname, p.Port)
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
		base := buildOriginURL(p.Scheme, p.Hostname, p.Port)

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
	return paths.StateDir("wordlists", config.ExpandPath(defaultWordlistDir))
}

// resolvedDiscoveryWordlists holds the effective deparos wordlist paths after
// layering: YAML config → CLI --discovery-wordlist → embedded defaults. The two
// usingX flags drive the header label so it can distinguish operator-supplied
// lists from the bundled fallbacks.
type resolvedDiscoveryWordlists struct {
	shortFile, longFile, shortDir, longDir string
	fuzz                                   []string // streamed in order, deduplicated across files
	tier                                   string   // effective discovery.wordlists.tier (never "auto")
	usingEmbedded                          bool     // at least one path came from the embedded defaults
	usingConfigured                        bool     // at least one path came from YAML / CLI
}

// autoWordlistTier maps --intensity to the embedded dir/file wordlist tier
// used when discovery.wordlists.tier is auto (or unset). quick and balanced
// keep the short lists only, which is what they always ran; deep, which used
// to add the ~5k long lists, gets the larger tier.
func autoWordlistTier(intensity string) string {
	if strings.EqualFold(strings.TrimSpace(intensity), "deep") {
		return config.WordlistTierLarge
	}
	return config.WordlistTierShort
}

// discoveryWordlistTier resolves discovery.wordlists.tier, applying the
// intensity mapping for auto/empty (and for an unknown value, which config
// validation rejects before a scan starts).
func (r *Runner) discoveryWordlistTier() string {
	tier := ""
	if r.settings != nil {
		tier = strings.ToLower(strings.TrimSpace(r.settings.Discovery.Wordlists.Tier))
	}
	switch tier {
	case config.WordlistTierShort, config.WordlistTierLong, config.WordlistTierLarge:
		return tier
	default:
		return autoWordlistTier(r.options.Intensity)
	}
}

// Discovery wordlist slots, as the plan names them.
const (
	wordlistSlotShortFile = "short_file"
	wordlistSlotLongFile  = "long_file"
	wordlistSlotShortDir  = "short_dir"
	wordlistSlotLongDir   = "long_dir"
	wordlistSlotFuzz      = "fuzz"
)

// wordlistRef is one list feeding deparos, before anything is written to
// disk: either a configured path or the logical name of an embedded list.
type wordlistRef struct {
	slot     string
	path     string // configured path (expanded); "" for an embedded list
	embedded string // embedded logical name; "" for a configured path
}

// discoveryWordlistRefs is the pure half of resolveDiscoveryWordlists: which
// list fills each slot and whether it is configured or embedded. Operator
// config (YAML, then the --discovery-wordlist CLI override) wins; any gap is
// filled from the embedded defaults — short file/dir lists on every scan, the
// long slot from the wordlist tier (discovery.wordlists.tier; auto = large at
// --intensity deep, none otherwise), and fuzz.txt (which deparos turns into a
// full /FUZZ brute of the root) whenever fuzzing is on. Nothing is read from or
// written to disk, so the scan plan sizes discovery from the same answer the
// phase runs with.
func (r *Runner) discoveryWordlistRefs() (refs []wordlistRef, tier string) {
	var shortFile, longFile, shortDir, longDir string
	var fuzz []string
	if r.settings != nil {
		wl := r.settings.Discovery.Wordlists
		shortFile = config.ExpandPath(wl.ShortFilePath)
		longFile = config.ExpandPath(wl.LongFilePath)
		shortDir = config.ExpandPath(wl.ShortDirPath)
		longDir = config.ExpandPath(wl.LongDirPath)
		if wl.FuzzWordlistPath != "" {
			fuzz = []string{config.ExpandPath(wl.FuzzWordlistPath)}
		}
	}
	// --discovery-wordlist is an explicit operator override and wins over YAML.
	if len(r.options.FuzzWordlistPaths) > 0 {
		fuzz = nil
		for _, p := range r.options.FuzzWordlistPaths {
			if p != "" {
				fuzz = append(fuzz, config.ExpandPath(p))
			}
		}
	}

	tier = r.discoveryWordlistTier()
	wantLong := tier != config.WordlistTierShort
	fuzzOn, _ := r.discoveryFuzzingState()
	// A resolved fuzz path IS the switch as far as deparos is concerned
	// (buildDeparosConfig copies it to cfg.FuzzWordlistPaths, and the engine
	// creates its FuzzTask whenever HasFuzzWordlist()). So fuzzing-off has to
	// clear the path, not merely decline to materialize the embedded default —
	// otherwise a discovery.wordlists.fuzz_wordlist_path in the config file
	// reaches the engine anyway and --no-discovery-fuzz brute-forces the host
	// while the phase header reports fuzzing as disabled.
	if !fuzzOn {
		fuzz = nil
	}
	longFileName, longDirName := wordlists.NameLongFile, wordlists.NameLongDir
	if tier == config.WordlistTierLarge {
		longFileName, longDirName = wordlists.NameLargeFile, wordlists.NameLargeDir
	}
	slot := func(name, path, embedded string, want bool) {
		switch {
		case path != "":
			refs = append(refs, wordlistRef{slot: name, path: path})
		case want:
			refs = append(refs, wordlistRef{slot: name, embedded: embedded})
		}
	}
	slot(wordlistSlotShortFile, shortFile, wordlists.NameShortFile, true)
	slot(wordlistSlotLongFile, longFile, longFileName, wantLong)
	slot(wordlistSlotShortDir, shortDir, wordlists.NameShortDir, true)
	slot(wordlistSlotLongDir, longDir, longDirName, wantLong)
	for _, p := range fuzz {
		refs = append(refs, wordlistRef{slot: wordlistSlotFuzz, path: p})
	}
	if len(fuzz) == 0 && fuzzOn {
		refs = append(refs, wordlistRef{slot: wordlistSlotFuzz, embedded: wordlists.NameFuzz})
	}
	return refs, tier
}

// resolveDiscoveryWordlists computes the wordlist paths feeding deparos:
// discoveryWordlistRefs, with the embedded lists materialized to disk (deparos
// loads wordlists from file paths only). This is shared by buildDeparosConfig
// and the Discovery phase header so the two never disagree on what is
// actually running; the Discovery phase resolves it once and hands the result
// to both.
func (r *Runner) resolveDiscoveryWordlists() resolvedDiscoveryWordlists {
	refs, tier := r.discoveryWordlistRefs()
	w := resolvedDiscoveryWordlists{tier: tier}
	needEmbedded := false
	for _, ref := range refs {
		if ref.embedded != "" {
			needEmbedded = true
		} else {
			w.usingConfigured = true
		}
	}
	var paths wordlists.DefaultPaths
	if needEmbedded {
		var err error
		paths, err = wordlists.EnsureOnDisk(wordlistDir())
		if err != nil {
			zap.L().Warn("Discovery: failed to materialize embedded wordlists; deparos falls back to observed-only", zap.Error(err))
		}
	}
	for _, ref := range refs {
		path := ref.path
		if ref.embedded != "" {
			path = paths.ByName(ref.embedded)
			if path == "" {
				continue
			}
			w.usingEmbedded = true
		}
		switch ref.slot {
		case wordlistSlotShortFile:
			w.shortFile = path
		case wordlistSlotLongFile:
			w.longFile = path
		case wordlistSlotShortDir:
			w.shortDir = path
		case wordlistSlotLongDir:
			w.longDir = path
		case wordlistSlotFuzz:
			w.fuzz = append(w.fuzz, path)
		}
	}
	return w
}

// discoveryExtractWords resolves discovery.extract_words: an explicit value
// wins; unset means on at --intensity deep and off otherwise. Response-word
// harvesting feeds every response body's tokens into the observed-name
// wordlist, so it multiplies brute-force work and is kept for deep scans.
func (r *Runner) discoveryExtractWords() bool {
	if r.settings != nil && r.settings.Discovery.ExtractWords != nil {
		return *r.settings.Discovery.ExtractWords
	}
	return r.options != nil && strings.EqualFold(strings.TrimSpace(r.options.Intensity), "deep")
}

// discoveryFuzzingState reports whether deparos FUZZ fuzzing is enabled for this
// run, with a short reason for the header. Fuzzing makes deparos auto-append
// /FUZZ and brute-force the (large) fuzz wordlist at each directory, so it is ON
// only when the operator clearly wants it: --discovery-wordlist supplied, --intensity
// deep, or discovery selected as an explicit phase (e.g. `vigolium run discover`,
// which sets Options.OnlyPhase). It stays OFF on balanced/lite full scans.
func (r *Runner) discoveryFuzzingState() (bool, string) {
	switch {
	// --no-discovery-fuzz is checked FIRST and wins outright. Every other arm
	// here is a heuristic switching fuzzing ON; this one is the operator
	// switching it off, and a heuristic that can overrule an explicit off is a
	// knob that does nothing on exactly the runs where it was typed on purpose.
	// It is the reason resolution lives in one function rather than at each of
	// the four sites that consume the answer.
	case r.options.NoDiscoveryFuzz:
		return false, "via --no-discovery-fuzz"
	case len(r.options.FuzzWordlistPaths) > 0:
		return true, "via --discovery-wordlist"
	case strings.EqualFold(r.options.Intensity, "deep"):
		return true, "intensity=deep"
	case r.options.OnlyPhase != "" && OnlyPhaseSet(r.options.OnlyPhase)["discovery"]:
		return true, "discovery-only run"
	case r.autoFuzzDiscovery:
		return true, "auto-enabled (low-yield/SSO target)"
	default:
		return false, "off on balanced/lite full scans (enable via `run discover`, --intensity deep, or --discovery-wordlist)"
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
// by discovery.auto_fuzz_low_yield (nil/absent = on), and refused outright under
// --no-discovery-fuzz.
func (r *Runner) shouldAutoFuzzDiscovery() bool {
	// Checked here as well as in discoveryFuzzingState, not only there. The
	// "already on" guard below reads the state as OFF under --no-discovery-fuzz
	// and would therefore fall straight through to the auto-enable — setting
	// r.autoFuzzDiscovery, which drives the "Fuzzing auto-enabled" banner and the
	// SSO-host scope filtering even though no fuzzing will happen.
	if r.options.NoDiscoveryFuzz {
		return false
	}
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
	// Records the capture lost still count as found: a crawl that reached plenty
	// and failed to persist it is not a low-yield target.
	return r.spidering.sawSSO || r.spidering.records+r.spidering.lost < lowYieldSpideringRecords
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
		blocked[normalizeSSOHost(h)] = true
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		u, err := neturl.Parse(t)
		if err != nil || u.Host == "" || !blocked[strings.ToLower(u.Hostname())] {
			out = append(out, t)
		}
	}
	return out
}

// normalizeSSOHost reduces a host to the one spelling the SSO block list uses:
// a lowercase bare hostname, port stripped.
//
// Every producer of that list has to agree on a spelling or the list silently
// stops matching. They did not: the landing-URL sites contributed host:port
// while the crawler's wall-host set contributed bare hostnames, so the block
// list held two spellings of the same host and lookups against it hit or missed
// depending on which producer got there first.
func normalizeSSOHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i+1:], "]") {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

// ssoHostsFromSpider returns the login/SSO wall hosts a spider result implies:
// every host the crawler denied, plus the landing host it came to rest on.
//
// Shared by all three phases that feed the block list so the "whole chain, not
// just the landing" rule lands in one place. An OAuth bounce routinely crosses
// an authorize endpoint on one host before reaching the login form on another,
// and taking only the landing left the first host a fuzz target.
func ssoHostsFromSpider(wallHosts []string, landingURL string) []string {
	out := make([]string, 0, len(wallHosts)+1)
	seen := make(map[string]bool, len(wallHosts)+1)
	add := func(h string) {
		if h = normalizeSSOHost(h); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range wallHosts {
		add(h)
	}
	if lu, err := neturl.Parse(landingURL); err == nil {
		add(lu.Hostname())
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

// discoveryRateLimit is the requests-per-second ceiling the discovery engine will
// enforce (0 = unpaced), resolved by config so the banner, the scan.started pace
// table and the engine all read one answer. See ScanningPaceConfig.DiscoveryRateLimit.
func (r *Runner) discoveryRateLimit() int {
	var pace *config.ScanningPaceConfig
	if r.settings != nil {
		pace = &r.settings.ScanningPace
	}
	return pace.DiscoveryRateLimit(r.options)
}

// phaseConcurrency is the worker count a phase will run with:
// scanning_pace.<phase>.concurrency when set and the CLI did not type a global
// one, otherwise the global value.
//
// One function for every phase because the rule is one rule, and the phases
// that resolved it inline each printed the global value on their own "Speed:"
// line while running on the section's.
func (r *Runner) phaseConcurrency(phase string) int {
	concurrency := r.options.Concurrency
	if r.settings != nil && !r.options.ConcurrencyExplicitlySet {
		if pace := r.settings.ScanningPace.ResolvePhase(phase); pace.Concurrency > 0 {
			concurrency = pace.Concurrency
		}
	}
	return concurrency
}

// discoveryBruteForceConcurrency is the default per-target worker count for
// discovery's wordlist and FUZZ-template requests: the scan's per-host slot
// cap, so wordlist fuzzing runs as wide as the scan already allows one host to
// be hit (the gate's host slots bound it either way), and never below the
// phase concurrency. An explicit -c is the operator choosing a pace, so it
// sets this too.
func (r *Runner) discoveryBruteForceConcurrency(concurrency int) int {
	if r.options.ConcurrencyExplicitlySet {
		return concurrency
	}
	perHost := 0
	if r.options.MaxPerHostExplicitlySet {
		perHost = r.options.MaxPerHost
	} else if r.settings != nil {
		perHost = r.settings.ScanningPace.MaxPerHost
	}
	if perHost <= 0 {
		perHost = types.DefaultMaxPerHost
	}
	return min(max(concurrency, perHost), deparosconfig.MaxBruteForceThreads)
}

// discoveryWirePace is discovery's brute-force worker count per target and its
// wire protocol mode: discovery.engine.brute_force_concurrency and .protocol
// when set, else discoveryBruteForceConcurrency and auto (HTTP/3, then
// HTTP/2, then HTTP/1.1, pinned per origin). One answer for the engine config
// and the phase's Speed line; the protocol comes back canonical.
func (r *Runner) discoveryWirePace(concurrency int) (bruteForce int, protocol string) {
	bruteForce, mode := r.discoveryBruteForceConcurrency(concurrency), bulkhttp.ModeAuto
	if r.settings != nil {
		eng := r.settings.Discovery.Engine
		if eng.BruteForceConcurrency > 0 {
			bruteForce = eng.BruteForceConcurrency
		}
		// Validated at load, so a parse error only means "keep auto".
		if m, err := bulkhttp.ParseMode(eng.Protocol); err == nil {
			mode = m
		}
	}
	return bruteForce, string(mode)
}

// discoveryConcurrency is the engine thread count the Discovery phase will run
// with. Shared by buildDeparosConfig and the phase's own "Speed:" line.
func (r *Runner) discoveryConcurrency() int { return r.phaseConcurrency("discovery") }

// buildDeparosConfig maps YAML DiscoveryConfig + CLI flags into a DeparosDiscoveryConfig.
// additionalTargets are merged (deduplicated) with CLI targets to expand the discovery scope.
// wls is the phase's resolveDiscoveryWordlists answer, resolved once by the
// caller so the config and the phase header share one materialization.
func (r *Runner) buildDeparosConfig(additionalTargets []string, wls resolvedDiscoveryWordlists) source.DeparosDiscoveryConfig {
	// Resolve discovery concurrency: scanning_pace.discovery overrides global when CLI not explicit
	discoveryConcurrency := r.discoveryConcurrency()

	// Merge CLI targets with additional targets (deduplicated)
	targets := dedupTargets(r.options.Targets, additionalTargets)

	cfg := source.DeparosDiscoveryConfig{
		Targets:       targets,
		Concurrency:   discoveryConcurrency,
		RateLimit:     r.discoveryRateLimit(),
		MaxDuration:   r.options.DiscoverMaxDuration,
		EnableModules: r.options.Modules,
		// Browser-harvested sessions from the spidering phase, so content
		// discovery crawls each host with its WAF/bot-cleared session.
		BrowserSessions: r.browserSessions,
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
		// Confirmation-gated extension fuzzing: on by default. Confirm from what
		// the site reveals (observed URLs + tech fingerprint); the brute-force
		// active probe is off by default (see ConfirmViaProbe — it confirms off
		// guessed filenames and false-positives on catch-all hosts).
		ConfirmRequired:       true,
		ConfirmViaObserved:    true,
		ConfirmViaFingerprint: true,
		ConfirmViaProbe:       false,
	}
	cfg.BruteForceConcurrency, cfg.Protocol = r.discoveryWirePace(discoveryConcurrency)
	cfg.ExtractWords = r.discoveryExtractWords()

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
		cfg.ConfirmViaProbe = boolPtrOr(dc.Extensions.ConfirmViaProbe, false)
		cfg.Candidates = dc.Extensions.Candidates
		cfg.ProbeFilenames = dc.Extensions.ProbeFilenames

		// SPA-gated JS-bundle name sweep (pointer-bool: nil = default true)
		cfg.JSBundleSweep = boolPtrOr(dc.Extensions.JSBundleSweep, true)
		cfg.JSBundleNames = dc.Extensions.JSBundleNames

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
		// Note: the crawl's inline secret scan is unconditionally disabled by the
		// deparos source adapter (its matches are never promoted; the main pipeline
		// re-scans), so dc.Engine.DisableSecretScan is not plumbed here.

		jobTimeout := 60 * time.Second
		if dc.JSTangle.JobTimeout != "" {
			if parsed, err := time.ParseDuration(dc.JSTangle.JobTimeout); err == nil {
				jobTimeout = parsed
			}
		}
		cfg.JSTangle = &deparosconfig.JSTangleConfig{
			Enabled: boolPtrOr(dc.JSTangle.Enabled, true), ReplayMode: dc.JSTangle.ReplayMode,
			ReplaySafety: dc.JSTangle.ReplaySafety,
			SourceMaps:   boolPtrOr(dc.JSTangle.SourceMaps, true), AssetGraph: boolPtrOr(dc.JSTangle.AssetGraph, true),
			ProtocolHandshake: dc.JSTangle.ProtocolHandshake,
			WorkerCount:       dc.JSTangle.WorkerCount, MemoryBudgetMB: dc.JSTangle.MemoryBudgetMB, CacheMB: dc.JSTangle.CacheMB,
			WorkerMaxJobs: dc.JSTangle.WorkerMaxJobs, WorkerMaxRSSMB: dc.JSTangle.WorkerMaxRSSMB, JobTimeout: jobTimeout,
			NormalInputMB: dc.JSTangle.NormalInputMB, MaxASTInputMB: dc.JSTangle.MaxASTInputMB,
			MaxUnpackInputMB: dc.JSTangle.MaxUnpackInputMB, HardInputMB: dc.JSTangle.HardInputMB,
			MaxRequestsPerFile: dc.JSTangle.MaxRequestsPerFile,
			MaxASTNodes:        dc.JSTangle.MaxASTNodes,
			MaxAssetDepth:      dc.JSTangle.MaxAssetDepth, MaxAssetsPerParent: dc.JSTangle.MaxAssetsPerParent,
			MaxAssetsPerHost: dc.JSTangle.MaxAssetsPerHost, MaxAssetsTotal: dc.JSTangle.MaxAssetsTotal,
			MaxChunksPerRuntime: dc.JSTangle.MaxChunksPerRuntime,
		}
		cfg.JSTemplatePersist = source.JSTemplatePersistConfig{
			SkipUnreplayed: !boolPtrOr(dc.JSTangle.PersistUnreplayed, true),
			EmitStatuses:   dc.JSTangle.PersistNotFoundEmitStatuses,
			MaxPerTarget:   dc.JSTangle.MaxPersistedJSTemplates,
		}
		cfg.Sitemap = &deparosconfig.SitemapConfig{
			Enabled: dc.Sitemap.IsEnabled(), MaxURLs: dc.Sitemap.MaxURLs,
			PerShape: dc.Sitemap.PerShape, FollowIndex: dc.Sitemap.FollowsIndex(),
		}
		cfg.TargetConcurrency = dc.TargetConcurrency
		cfg.FlushInterval = dc.FlushIntervalValue()
		cfg.FuzzAtEnd = !dc.StreamsFuzz()

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

	// Wordlist paths: YAML config → CLI --discovery-wordlist → embedded
	// defaults (short file/dir always; the long slot per discovery.wordlists.tier;
	// fuzz.txt when fuzzing is on). Applied here, outside the settings block above,
	// so the embedded defaults still apply when no YAML config is loaded.
	cfg.ShortFilePath = wls.shortFile
	cfg.LongFilePath = wls.longFile
	cfg.ShortDirPath = wls.shortDir
	cfg.LongDirPath = wls.longDir
	cfg.FuzzWordlistPaths = wls.fuzz

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

	sources := harvester.BuildSources(cfg.Sources, harvester.SourceKeys{
		URLScan:    cfg.APIKeys.URLScan,
		VirusTotal: cfg.APIKeys.VirusTotal,
	}, proxyURL)

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

	h := harvester.New(sources, timeout).WithOptions(cfg.HarvesterOptions())

	zap.L().Info("ExternalHarvester initialized",
		zap.Int("sources", len(sources)),
		zap.Strings("domains", domains),
		zap.Duration("timeout", timeout))

	return source.NewExternalHarvesterInputSource(h, domains, r.options.Modules)
}

// getInScopeHostURLs returns deduplicated host URLs (e.g. "https://example.com") for the
// in-scope origins (scheme/host/port) of the CLI targets — the same scoping
// dynamic-assessment and known-issue-scan use — so DB hosts on a different port left in
// the project by a prior scan (e.g. localhost:3000 while targeting localhost:3005) are not
// re-crawled or re-discovered.
func (r *Runner) getInScopeHostURLs(ctx context.Context) []string {
	return hostURLsFromHostTargets(r.getInScopeDBHosts(ctx))
}

// hostURLsFromHostTargets renders origin tuples as host URLs, omitting the port when it is
// the scheme default (https→443, http→80).
func hostURLsFromHostTargets(hosts []database.HostTarget) []string {
	if len(hosts) == 0 {
		return nil
	}
	urls := make([]string, 0, len(hosts))
	for _, h := range hosts {
		urls = append(urls, buildOriginURL(h.Scheme, h.Hostname, h.Port))
	}
	return urls
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
