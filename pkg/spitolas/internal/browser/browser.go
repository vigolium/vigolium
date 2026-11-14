package browser

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	chromium "github.com/vigolium/vigolium/internal/resources/spitolas"
	"github.com/vigolium/vigolium/pkg/browserprobe"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/internal/scratch"
	"go.uber.org/zap"
)

// Browser wraps rod.Browser with additional functionality.
type Browser struct {
	rodBrowser  *rod.Browser
	config      *config.Config
	launcher    *launcher.Launcher
	profileDir  string // Chromium user-data directory owned by this browser; removed by Close
	currentPage *Page  // Persistent page for session state preservation

	// uaOverride is the realistic User-Agent applied to every page (the real
	// browser UA with "HeadlessChrome" stripped). Computed once per browser
	// (uaOnce) so NewPage doesn't re-query the browser version per page/tab.
	uaOnce     sync.Once
	uaOverride string
	// uaMetadata is the client-hint metadata sent with uaOverride when stealth
	// is on (see stealthUserAgentMetadata); nil otherwise.
	uaMetadata *proto.EmulationUserAgentMetadata

	// crawlCtx, when set, is bound onto every page created by NewPage so that
	// the crawl's deadline/cancellation propagates into every rod operation
	// (navigation, WaitStable, clicks, element lookups, form fills) — not just
	// the Go-level loop checks. rod's Page.Timeout(d) derives from the page's
	// context, so a bound page caps each op at min(d, remaining-deadline) and
	// aborts in-flight CDP calls the moment the crawl context is cancelled.
	// Without this the spider can run far past max-duration: the deadline is
	// only polled between actions while individual browser operations block on
	// their own fixed rod timeouts (PageLoadTimeout=30s, ElementTimeout=5s).
	// The browser connection itself stays on the background context so capture
	// flushing and shutdown still work after the deadline fires.
	crawlCtx context.Context

	// killer and killProfileDir are the process handles Kill uses, snapshotted at
	// a successful launch and NEVER mutated afterwards.
	//
	// They duplicate launcher/profileDir deliberately. Kill exists for the case
	// where Close is wedged — and a wedged Close is holding b.mu, so Kill cannot
	// take the lock to read those fields. Write-once-at-launch fields are safe to
	// read without it.
	killer         processKiller
	killProfileDir string

	// killOnce makes Kill idempotent: the watchdog path can fire it while a
	// racing Close is also escalating to it.
	killOnce sync.Once

	// closeRod overrides the bounded rod-browser close in tests. nil means the
	// real one. It is a seam rather than an interface because the production path
	// needs rod's own Timeout clone, and the branch worth testing — "a close that
	// errored means the process may still be running, so escalate to Kill" — is
	// otherwise only reachable with a genuinely wedged browser.
	closeRod func() error

	mu    sync.Mutex
	pages []*Page
}

// processKiller is the launcher capability Kill needs. An interface so the kill
// path is testable without launching a real browser — *launcher.Launcher
// satisfies it.
type processKiller interface {
	Kill()
}

// New creates a new browser instance. Provisioning is not cancellable; use
// NewWithContext when a caller context should be able to stop it.
func New(cfg *config.Config) (*Browser, error) {
	return NewWithContext(context.Background(), cfg)
}

// NewWithContext creates a new browser instance whose provisioning — choosing
// a candidate binary and, as a last resort, downloading Chrome for Testing —
// stops when ctx ends. ctx bounds only the launch: the running browser stays
// on the background context so capture flushing and shutdown keep working
// after a crawl deadline (bind the crawl context to pages with
// SetCrawlContext).
func NewWithContext(ctx context.Context, cfg *config.Config) (*Browser, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}
	b := &Browser{
		config: cfg,
		pages:  make([]*Page, 0),
	}

	if err := b.launch(ctx); err != nil {
		return nil, err
	}

	return b, nil
}

// launch starts the browser process, trying each candidate binary in priority
// order and falling through to the next whenever one fails to actually launch.
//
// Order: explicit browser_path → embedded engine binary → system Google Chrome
// → system Chromium → Chrome for Testing (cached, then downloaded) → rod's own
// auto-download. A binary that merely prints a version but crashes on real
// headless startup (e.g. some distro Chromium builds on a KVM guest) is
// therefore auto-recovered from — the scan falls back to a working browser (in
// practice Chrome for Testing) instead of failing outright. Only when every
// candidate fails does this return an aggregated error. A cancelled ctx stops
// the walk before the next candidate (and inside the CfT download).
func (b *Browser) launch(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}
	return b.launchFrom(ctx, b.browserCandidates(ctx))
}

// browserLaunchTimeout bounds a single `launcher.Launch()` call.
//
// Launch is not otherwise bounded by the caller's context — rod kills the browser
// process when the launcher's context ends, and the running browser must outlive
// the provisioning context so capture can keep flushing after a crawl deadline
// (see NewWithContext). So the per-ATTEMPT bound is its own deadline: a binary
// that starts but never prints its DevTools URL would otherwise hold the launch
// walk open indefinitely, and the next candidate — in practice a working one —
// would never be tried. A variable so tests can shrink it.
var browserLaunchTimeout = 60 * time.Second

// launchFrom walks candidates in order. Split out of launch so the candidate list
// is injectable: the failure paths below are the whole point of this function and
// a test must be able to drive them without a real browser on the host.
func (b *Browser) launchFrom(ctx context.Context, candidates []browserCandidate) error {
	var attempts []string
	sandboxRetried := false
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("failed to launch browser: %w", err)
		}
		binPath, err := c.resolve()
		if err != nil {
			zap.L().Debug("browser candidate unavailable, skipping",
				zap.String("candidate", c.label), zap.Error(err))
			continue
		}

		compat := b.config.BrowserCompat
		compat.NoSandbox = effectiveNoSandbox(compat)
		l := b.newLauncher(binPath, compat)
		u, err := launchBounded(l)
		// A Linux host that cannot give this binary a sandbox fails the launch
		// outright (Ubuntu 23.10+'s AppArmor user-namespace restriction is the
		// common case and is not detectable up front for every binary). Retry
		// once without it rather than fail the crawl; a success is remembered so
		// the rest of the run launches unsandboxed directly, with one warning.
		if err != nil && !compat.NoSandbox && runtime.GOOS == "linux" && !sandboxRetried {
			sandboxRetried = true
			reason := sandboxRetryReason(currentSandboxHost(), browserprobe.FirstLine(err.Error()))
			compat.NoSandbox = true
			// The sandboxed attempt's profile is abandoned here: the retry builds
			// its own launcher with its own directory.
			discardLauncherProfile(l)
			l = b.newLauncher(binPath, compat)
			if u2, err2 := launchBounded(l); err2 == nil {
				recordSandboxFallback(reason)
				u, err = u2, nil
			} else {
				zap.L().Debug("unsandboxed retry also failed; not a sandbox problem",
					zap.String("candidate", c.label), zap.Error(err2))
			}
		}
		if err != nil {
			// No l.Kill() here: launcher.Launch already kills the process on the
			// getURL/timeout failure path, and a failed cmd.Start leaves none —
			// a second Kill would just burn its built-in ~1s sleep for nothing.
			// The PROFILE still has to go: newLauncher allocated a scratch
			// directory for this attempt, and a host where several candidates fail
			// before one works left one stranded per failure, every launch.
			discardLauncherProfile(l)
			short := browserprobe.FirstLine(err.Error())
			zap.L().Warn("browser candidate failed to launch, falling back to next",
				zap.String("candidate", c.label),
				zap.String("bin", binPathOrAuto(binPath)),
				zap.String("error", short))
			attempts = append(attempts, fmt.Sprintf("%s [%s]: %s", c.label, binPathOrAuto(binPath), short))
			continue
		}

		browser := rod.New().ControlURL(u)
		if err := browser.Connect(); err != nil {
			l.Kill()
			// Killed, so nothing is writing into the profile any more.
			discardLauncherProfile(l)
			zap.L().Warn("browser candidate connected but handshake failed, falling back to next",
				zap.String("candidate", c.label), zap.Error(err))
			attempts = append(attempts, fmt.Sprintf("%s [%s]: connect: %v", c.label, binPathOrAuto(binPath), err))
			continue
		}

		b.launcher = l
		b.profileDir = l.Get(flags.UserDataDir)
		b.rodBrowser = browser
		// Snapshotted for Kill, which cannot take b.mu — see the field comments.
		// Written here, before the browser is handed to any caller, and never again.
		b.killer = l
		b.killProfileDir = b.profileDir
		b.applyDownloadPolicy()
		zap.L().Debug("browser launched",
			zap.String("candidate", c.label), zap.String("bin", binPathOrAuto(binPath)))
		return nil
	}

	if len(attempts) == 0 {
		hint := ""
		if isLinuxARM64For(runtime.GOOS, runtime.GOARCH) {
			hint = " — install one with: sudo apt-get install -y chromium"
		}
		return fmt.Errorf("failed to launch browser: no browser binary found%s", hint)
	}
	return fmt.Errorf("failed to launch browser: all %d candidate(s) failed: %s",
		len(attempts), strings.Join(attempts, "; "))
}

// launchBounded runs one launcher.Launch under browserLaunchTimeout.
//
// l.Context(ctx) is how the bound is applied, and rod kills the process when that
// context ends — which is exactly right HERE and only here: the context is
// discarded the moment Launch returns a URL, because launcher.Launch has already
// finished with it by then. It must never be the caller's long-lived context (see
// browserLaunchTimeout).
func launchBounded(l *launcher.Launcher) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), browserLaunchTimeout)
	defer cancel()
	return l.Context(ctx).Launch()
}

// removeProfileDir removes a Chromium profile directory this package allocated,
// logging a failure rather than reporting it: the caller is always on a teardown
// path whose outcome a stranded directory must not change. An empty dir is a
// no-op, so every caller can hand over whichever field it holds. why names the
// teardown in the log line.
//
// Profile ownership is the same rule everywhere, which is why this is one
// function: newLauncher is the only thing that ever sets UserDataDir — a fresh
// scratch directory per attempt, or rod's own per-launch temp path when scratch
// allocation failed — so the directory is always that attempt's and nobody
// else's. The abandoned-launch, Kill and Close paths all rely on exactly that.
// Call it only once the attempt's process is gone.
func removeProfileDir(dir, why string) {
	if dir == "" {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		zap.L().Debug("could not remove the browser profile directory",
			zap.String("dir", dir), zap.String("teardown", why), zap.Error(err))
	}
}

// discardLauncherProfile removes the Chromium profile directory a launch attempt
// that will not be used had allocated.
func discardLauncherProfile(l *launcher.Launcher) {
	if l == nil {
		return
	}
	removeProfileDir(l.Get(flags.UserDataDir), "abandoned launch attempt")
}

// Kill terminates the browser process and removes its profile, WITHOUT taking
// b.mu.
//
// That is the whole reason it exists. Close holds b.mu for its bounded shutdown,
// so when that shutdown wedges — the case where a browser process is actually
// leaked — nothing that needs the lock can reach the process. The watchdog paths
// that abandon a crawl call this instead, and so does Close when its own bounded
// close fails.
//
// Safe to call concurrently with Close, more than once, and on a browser that
// never launched. It reads only the write-once-at-launch handles.
func (b *Browser) Kill() {
	if b == nil {
		return
	}
	b.killOnce.Do(func() {
		if b.killer != nil {
			b.killer.Kill()
		}
		removeProfileDir(b.killProfileDir, "kill")
	})
}

// browserCandidate is one binary to attempt, in priority order. resolve is lazy
// so expensive providers (the Chrome for Testing download) only run once every
// cheaper candidate has already failed.
type browserCandidate struct {
	label   string
	resolve func() (string, error) // returns bin path; "" means "let rod auto-download"
}

// browserCandidates builds the ordered candidate list for the current host. It
// resolves the platform-varying inputs (system browser binaries, GOOS/GOARCH)
// and hands them to buildBrowserCandidates, which owns the ordering.
func (b *Browser) browserCandidates(ctx context.Context) []browserCandidate {
	systemBins := systemBrowserBins(browserPreferenceOrderFor(runtime.GOOS), lookPathFound, validateBrowserBin)
	return buildBrowserCandidates(ctx, runtime.GOOS, runtime.GOARCH, b.config.BrowserPath, systemBins, b.getEmbeddedBrowserPath)
}

// ensureCfTBrowser downloads (or reuses) Chrome for Testing. A variable so
// tests can observe the call without a network fetch.
//
// Reaching it mid-crawl is the fallback: the scan runner pre-provisions the
// browser before the spidering phase's deadline starts (see NeedsDownload), so
// this rung only downloads when every resolved browser failed to launch. Its
// progress is the text rendering on stderr.
var ensureCfTBrowser = func(ctx context.Context) (string, error) {
	return cftbrowser.EnsureBrowser(ctx, nil)
}

// NeedsDownload reports whether launching a browser for cfg would have to fall
// through to the Chrome for Testing download: no configured browser_path, no
// embedded engine binary, no working system browser and no cached CfT copy, on
// a platform CfT supports. No network. The scan runner asks before the
// spidering phase so it can download (with progress) outside the phase budget.
func NeedsDownload(cfg *config.Config) bool {
	if cfg == nil || cfg.BrowserPath != "" {
		return false
	}
	if !cftbrowser.IsSupported() {
		return false // nothing to download; launch reports the install hint
	}
	if _, err := (&Browser{config: cfg}).getEmbeddedBrowserPath(); err == nil {
		return false
	}
	for _, name := range browserPreferenceOrderFor(runtime.GOOS) {
		if p, ok := lookPathFound(name); ok && validateBrowserBin(p) {
			return false
		}
	}
	if _, err := cftbrowser.FindCachedBrowser(); err == nil {
		return false
	}
	return true
}

// buildBrowserCandidates assembles the ordered candidate list from already-
// resolved inputs. Platform (goos/goarch), the configured path, the resolved
// system browser bins, and the embedded-binary resolver are all injected, so the
// ordering — and the platform-specific tail (the linux/arm64 rod-auto-download
// skip) — is unit-testable on any host. See launch() for the order rationale.
// ctx reaches the Chrome for Testing download, the only candidate that blocks
// on the network.
func buildBrowserCandidates(ctx context.Context, goos, goarch, configPath string, systemBins []string, embedded func() (string, error)) []browserCandidate {
	var cands []browserCandidate
	add := func(label string, resolve func() (string, error)) {
		cands = append(cands, browserCandidate{label: label, resolve: resolve})
	}

	// 1. Explicit configured path — highest priority (e.g. spidering.browser_path).
	if configPath != "" {
		add("configured browser_path", func() (string, error) { return configPath, nil })
	}

	// 2. Embedded engine binary — only resolves for the ungoogled/fingerprint
	//    engines (or an embed_chromium build); a no-op for the default engine.
	add("embedded browser", embedded)

	// 3. System browsers, real Chrome first then Chromium. All resolvable
	//    binaries are enumerated (not just the first match) so a crash-on-launch
	//    Chromium can fall through to a working Chrome/Chromium, then to CfT.
	for _, p := range systemBins {
		add("system browser "+p, func() (string, error) { return p, nil })
	}

	// cftCandidate wraps a Chrome-for-Testing resolver with the shared
	// "is there a build for this platform?" guard so the two CfT rungs below
	// can't drift in how they gate (no build for e.g. linux/arm64).
	cftCandidate := func(fn func() (string, error)) func() (string, error) {
		return func() (string, error) {
			if !cftbrowser.IsSupported() {
				return "", fmt.Errorf("chrome for testing unsupported on %s/%s", goos, goarch)
			}
			return fn()
		}
	}

	// 4. Chrome for Testing — a previously cached copy (no network).
	add("Chrome for Testing (cached)", cftCandidate(cftbrowser.FindCachedBrowser))

	// --offline (SAFE-11): no download rungs at all — a missing browser fails
	// with the install hint instead of fetching one.
	if offlineMode.Load() {
		return cands
	}

	// 5. Chrome for Testing — download on the fly (network, last real resort).
	//    This is what recovers a host whose only system browser is broken.
	add("Chrome for Testing (download)", cftCandidate(func() (string, error) {
		zap.L().Info("No working system browser — downloading Chrome for Testing")
		return ensureCfTBrowser(ctx)
	}))

	// 6. rod's built-in auto-download (a browser rod fetches itself). Dropped
	//    ONLY on linux/arm64, where rod's download URLs are broken and would
	//    hang on a multi-minute fetch race. This does NOT make arm64 a
	//    second-class platform: an apt-installed system Chromium (candidate 3)
	//    — or the embedded ungoogled arm64 engine (candidate 2) — is the
	//    supported path there, exactly like everywhere else. What arm64 lacks is
	//    only the *automatic download* rungs (both CfT and rod publish no
	//    linux/arm64 build), so if no browser is installed launch() returns an
	//    "install chromium" hint instead of hanging.
	if !isLinuxARM64For(goos, goarch) {
		add("rod auto-download", func() (string, error) { return "", nil })
	}

	return cands
}

// isLinuxARM64For reports whether goos/goarch is linux/arm64. Only the automatic
// browser *download* fallbacks are unavailable there (neither rod nor Chrome for
// Testing ship a linux/arm64 binary); a system-installed Chromium is used
// normally. Parameterized by GOOS/GOARCH so it's testable on any host.
func isLinuxARM64For(goos, goarch string) bool {
	return goos == "linux" && goarch == "arm64"
}

// newLauncher builds a fresh, fully-configured launcher for a single launch
// attempt. A launcher.Launcher may only be Launch()ed once, so every candidate
// gets its own. An empty binPath leaves the binary unset so rod resolves or
// auto-downloads one. compat is the effective exception set for this attempt
// (the sandbox decision already resolved by the caller).
func (b *Browser) newLauncher(binPath string, compat config.BrowserCompat) *launcher.Launcher {
	l := launcher.New()
	if binPath != "" {
		l = l.Bin(binPath)
	}

	// Pin the Chromium profile under this run's scratch instead of letting rod
	// pick $TMPDIR/rod/user-data/<random>, which it only ever removes through
	// launcher.Cleanup() - a call Close never made, so every launch stranded a
	// profile permanently (see the internal/scratch package doc for the scale).
	//
	// Cleanup() is not the fix: it blocks until the browser process exits, so a
	// wedged browser - exactly the case that leaks - would hang teardown. Owning
	// the path lets Close remove it directly, with scratch.Release as the
	// backstop for a run that never reaches Close at all.
	if dir, err := scratch.MkdirTemp("rod-profile-*"); err == nil {
		l = l.UserDataDir(dir)
	} else {
		zap.L().Debug("could not allocate a scratch browser profile; rod will use its own temp directory",
			zap.Error(err))
	}

	l.Set("disable-ipc-flooding-protection").
		Set("disable-xss-auditor").
		Set("disable-bundled-ppapi-flash").
		Set("disable-plugins-discovery").
		Set("disable-default-apps").
		Set("disable-prerender-local-predictor").
		Set("disable-breakpad").
		Set("disable-crash-reporter").
		Set("disk-cache-size", "0").
		Set("disable-settings-window").
		Set("disable-notifications").
		Set("disable-speech-api").
		Set("disable-file-system").
		Set("disable-presentation-api").
		Set("disable-permissions-api").
		Set("disable-new-zip-unpacker").
		Set("disable-media-session-api").
		Set("disable-audio-output").
		Set("disable-dev-shm-usage").
		Set("no-experiments").
		Set("no-first-run").
		Set("no-default-browser-check").
		Set("no-pings").
		Set("no-service-autorun").
		Set("media-cache-size", "0").
		Set("use-fake-device-for-media-stream").
		Set("dbus-stub").
		Set("lang", "en-US").
		Set("disable-background-networking")

	// Appended, not Set: rod's own disable-features (site-per-process,
	// TranslateUI) must survive. The HTTPS-upgrade features are off so Chrome
	// does not auto-upgrade HTTP to HTTPS, which times out against a target with
	// no HTTPS server.
	l = appendDisableFeatures(l,
		"ChromeWhatsNewUI", "HttpsUpgrades", "HttpsFirstModeV2", "HttpsFirstBalancedMode",
		"HttpsFirstModeForAdvancedProtectionUsers", "ImageServiceObserveSyncDownloadStatus",
		"TrackingProtection3pcd", "LensOverlay")

	if b.config.StealthEnabled() {
		l = applyStealthFlags(l)
	}

	// Security boundaries are configured, not hard-coded: the sandbox, TLS
	// verification, mixed-content blocking and the same-origin policy each
	// relax only when compat asks (or, for the sandbox, when the host cannot
	// provide one). The flags above are hygiene and stay unconditional.
	l = applySecurityFlags(l, compat)

	// Add fingerprint flags for Ungoogled-Chromium
	if b.config.BrowserEngine == "ungoogled" || b.config.BrowserEngine == "fingerprint" {
		fingerprint := strconv.Itoa(rand.Intn(10000000) + 1)
		l = l.Set("fingerprint", fingerprint).
			Set("fingerprint-platform", "windows").
			// Set("timezone", "America/Los_Angeles").
			Set("fingerprint-brand", "Chrome")
		zap.L().Debug("Using Ungoogled-Chromium fingerprint",
			zap.String("fingerprint", fingerprint),
			zap.String("fingerprint-brand", "Chrome"))
	}

	l = l.Headless(b.config.Headless)

	// Set proxy if configured. Force HTTP/1.1 alongside it: intercepting proxies
	// (Burp, ZAP) routinely mishandle HTTP/2 frame translation, which Chrome
	// surfaces as net::ERR_HTTP2_PROTOCOL_ERROR and which fails navigation
	// outright rather than degrading gracefully.
	if b.config.ProxyURL != "" {
		l = applyProxy(l, b.config.ProxyURL)
		if b.config.ProxyAllowLoopback {
			// Chrome bypasses the proxy for localhost/127.0.0.1 by default;
			// <-loopback> drops that implicit rule so an intercepting proxy
			// (Burp) also captures traffic to a loopback target.
			l = l.Set("proxy-bypass-list", "<-loopback>")
		}
		zap.L().Debug("Proxy configured — forcing HTTP/1.1 (disable-http2, disable-quic)",
			zap.String("proxy", b.config.ProxyURL))
	}

	return l
}

// binPathOrAuto renders an empty bin path (rod auto-download) as "auto" for logs.
func binPathOrAuto(binPath string) string {
	if binPath == "" {
		return "auto-download"
	}
	return binPath
}

// applyProxy points the launcher at proxyURL and forces HTTP/1.1 over it.
// disable-http2 stops Chrome from negotiating HTTP/2 with the proxy (the source
// of net::ERR_HTTP2_PROTOCOL_ERROR through Burp/ZAP), and disable-quic stops it
// from routing around the proxy over QUIC/HTTP3, which an HTTP proxy can't
// intercept. No-op when proxyURL is empty so non-proxied scans keep HTTP/2.
func applyProxy(l *launcher.Launcher, proxyURL string) *launcher.Launcher {
	if proxyURL == "" {
		return l
	}
	return l.Proxy(proxyURL).
		Set("disable-http2").
		Set("disable-quic")
}

// SetCrawlContext binds ctx onto every page subsequently created by NewPage so
// the crawl deadline propagates into rod's per-operation timeouts. Call it once
// before the crawl starts creating pages. A nil ctx clears the binding. See the
// crawlCtx field doc for why this is required to honor max-duration.
func (b *Browser) SetCrawlContext(ctx context.Context) {
	b.mu.Lock()
	b.crawlCtx = ctx
	b.mu.Unlock()
}

// browserOpTimeout bounds a one-shot browser-level CDP op (page/tab create,
// list, close, version). Unlike page ops, these run on the browser's background
// context — NOT the crawl context bound onto pages — so without an explicit cap
// a wedged or unresponsive browser would hang them forever, including at
// teardown. Do NOT use the capped clone for long-lived loops (EachEvent).
const browserOpTimeout = 30 * time.Second

// boundedBrowser returns the rod browser capped at browserOpTimeout for a
// one-shot browser-level CDP call.
func (b *Browser) boundedBrowser() *rod.Browser {
	return b.rodBrowser.Timeout(browserOpTimeout)
}

// tabCreateTimeout bounds creating a tab (target create + attach) on a wedged
// or unresponsive browser. A variable so tests can shrink it.
var tabCreateTimeout = browserOpTimeout

// createRodPage opens a tab, bounded by tabCreateTimeout and by crawlCtx.
//
// Not a Timeout-bounded clone: rod sets the new page's .browser to whatever
// browser handle created it and derives the page's own context from that
// handle's, so a Timeout clone would expire the long-lived crawl page
// browserOpTimeout after creation. Instead the handle gets a cancel-only
// context whose watchdog (the timeout, or the crawl context ending) is
// disarmed as soon as the tab exists, leaving it live for the page's lifetime.
// The returned release ends that context; call it once the page is closed.
func (b *Browser) createRodPage(crawlCtx context.Context, browserContext proto.BrowserBrowserContextID, newWindow bool) (*rod.Page, context.CancelFunc, error) {
	handle, release := b.rodBrowser.WithCancel()
	// Empty is the default context; rod's Page creates the target in the
	// handle's context.
	handle.BrowserContextID = browserContext
	timer := time.AfterFunc(tabCreateTimeout, release)
	stopCrawlWatch := func() bool { return true }
	if crawlCtx != nil {
		stopCrawlWatch = context.AfterFunc(crawlCtx, release)
	}
	rodPage, err := handle.Page(proto.TargetCreateTarget{URL: "about:blank", NewWindow: newWindow})
	timer.Stop()
	stopCrawlWatch()
	if err == nil && handle.GetContext().Err() != nil {
		// The watchdog fired just as creation finished: the handle the page
		// holds is already dead, so the page is unusable.
		err = handle.GetContext().Err()
		_ = closePageWithTimeout(rodPage.Context(context.Background()), browserOpTimeout, 1)
	}
	if err != nil {
		release()
		if crawlCtx != nil && crawlCtx.Err() != nil {
			err = fmt.Errorf("%w (crawl context: %w)", err, crawlCtx.Err())
		}
		return nil, nil, err
	}
	return rodPage, release, nil
}

// NewPage creates a new page (tab).
func (b *Browser) NewPage() (*Page, error) {
	return b.newPage("", false)
}

// NewWindowPage creates a page in a window of its own. Use it for a page that
// is driven at the same time as another: Chrome stops rendering a tab hidden
// behind another tab of its window, so requestAnimationFrame never fires there
// and every rod action that waits for a repaint (a click's scroll-into-view)
// blocks for good. A page alone in its window stays visible.
func (b *Browser) NewWindowPage() (*Page, error) {
	return b.newPage("", true)
}

// NewIsolatedPage creates a tab in a browser context of its own (CDP
// Target.createBrowserContext, the same thing rod's Incognito does): it shares
// no cookies, storage or cache with the default context or any other isolated
// tab. Closing the page disposes the context. The browser-level traffic
// capture still sees it, since every page enables Network on its own session.
// Like NewWindowPage, the tab gets a window of its own.
func (b *Browser) NewIsolatedPage() (*Page, error) {
	res, err := proto.TargetCreateBrowserContext{}.Call(b.boundedBrowser())
	if err != nil {
		return nil, fmt.Errorf("failed to create browser context: %w", err)
	}
	dispose := func() {
		_ = proto.TargetDisposeBrowserContext{BrowserContextID: res.BrowserContextID}.Call(b.boundedBrowser())
	}
	page, err := b.newPage(res.BrowserContextID, true)
	if err != nil {
		dispose()
		return nil, err
	}
	release := page.release
	page.release = func() {
		if release != nil {
			release()
		}
		dispose()
	}
	return page, nil
}

// newPage creates a tab in browserContext ("" = the default context), in a
// window of its own when newWindow is set.
func (b *Browser) newPage(browserContext proto.BrowserBrowserContextID, newWindow bool) (*Page, error) {
	b.mu.Lock()
	crawlCtx := b.crawlCtx
	b.mu.Unlock()

	rodPage, release, err := b.createRodPage(crawlCtx, browserContext, newWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}

	// Bind the crawl context (if set) so every rod operation on this page — and
	// every element derived from it — inherits the crawl's deadline and
	// cancellation. rod returns a clone from Context(), so use the clone.
	if crawlCtx != nil {
		rodPage = rodPage.Context(crawlCtx)
	}

	// Enable Network domain on this page for traffic capture.
	// Browser.EachEvent only enables domains at browser level, but Network events
	// are only emitted from pages that have the Network domain explicitly enabled.
	_ = proto.NetworkEnable{}.Call(rodPage)

	// Present as a normal browser, not HeadlessChrome. Many SPAs gate their
	// content/locale routing (and some anti-bot layers gate rendering) on a real
	// User-Agent + Accept-Language; the default headless UA both advertises
	// automation and can trigger a degraded experience where the app never renders
	// its real content. Strip "Headless" from the actual UA (keeping the accurate
	// Chrome version) and pin Accept-Language to en-US. The UA is resolved once per
	// browser; the override itself is a page-level CDP call, so it's applied here.
	//
	// With stealth on, the override also carries client-hint metadata for the
	// same version, so navigator.userAgentData and Sec-CH-UA stop naming
	// HeadlessChrome either.
	stealth := b.config.StealthEnabled()
	b.uaOnce.Do(func() {
		if ver, verr := (proto.BrowserGetVersion{}).Call(b.boundedBrowser()); verr == nil {
			b.uaOverride = strings.ReplaceAll(ver.UserAgent, "HeadlessChrome", "Chrome")
			if stealth {
				b.uaMetadata = stealthUserAgentMetadata(ver.Product, runtime.GOOS, runtime.GOARCH)
			}
		}
	})
	if b.uaOverride != "" {
		_ = proto.NetworkSetUserAgentOverride{
			UserAgent:         b.uaOverride,
			AcceptLanguage:    defaultAcceptLanguage,
			UserAgentMetadata: b.uaMetadata,
		}.Call(rodPage)
	}

	page := &Page{
		rodPage: rodPage,
		config:  b.config,
		browser: b,
		release: release,
	}

	// Registered before the first navigation so it runs ahead of page scripts
	// in every document this tab loads.
	if stealth {
		page.installStealth(stealthOptionsFor(b.config.Headless, runtime.GOOS, runtime.GOARCH))
	}

	// This runs in background and answers JS dialogs per the dialog policy.
	page.setupAutoDialogHandler()

	// A policy that denies form submission also blocks it inside the page.
	if needsSubmitGuard(b.config) {
		page.installSubmitGuard()
	}

	b.mu.Lock()
	b.pages = append(b.pages, page)
	b.mu.Unlock()

	return page, nil
}

// Pages returns all open pages.
func (b *Browser) Pages() []*Page {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]*Page, len(b.pages))
	copy(result, b.pages)
	return result
}

// forget drops page from the tracked set (it was closed on its own).
func (b *Browser) forget(page *Page) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, p := range b.pages {
		if p == page {
			b.pages = append(b.pages[:i], b.pages[i+1:]...)
			return
		}
	}
}

// CurrentPage returns the current persistent page, or nil if none exists.
// CRITICAL FIX: This allows page reuse across actions to preserve session state.
func (b *Browser) CurrentPage() *Page {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.currentPage
}

// SetCurrentPage sets the current persistent page.
func (b *Browser) SetCurrentPage(page *Page) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentPage = page
}

// RodBrowser returns the underlying rod.Browser instance.
// Used for browser-level operations like traffic capture.
func (b *Browser) RodBrowser() *rod.Browser {
	return b.rodBrowser
}

// UserAgent returns the User-Agent the browser presents to sites — the real
// Chrome UA with "HeadlessChrome" rewritten to "Chrome" (see NewPage). Empty
// until the first page is created. Callers harvest this after a crawl so
// downstream phases can pin the exact UA the WAF issued its clearance cookie to.
func (b *Browser) UserAgent() string {
	return b.uaOverride
}

// HarvestCookies returns the browser's current cookie jar as net/http cookies.
// Called at the end of a crawl to carry the session (including any WAF/bot
// clearance cookies the real browser earned) forward into later scan phases.
// Uses the timeout-bounded browser handle so a wedged browser can't hang the
// harvest.
func (b *Browser) HarvestCookies() ([]*http.Cookie, error) {
	if b.rodBrowser == nil {
		return nil, fmt.Errorf("no browser available")
	}
	raw, err := b.boundedBrowser().GetCookies()
	if err != nil {
		return nil, err
	}
	cookies := make([]*http.Cookie, 0, len(raw))
	for _, c := range raw {
		if converted := cdpCookieToHTTP(c); converted != nil {
			cookies = append(cookies, converted)
		}
	}
	return cookies, nil
}

// cdpCookieToHTTP converts one CDP cookie to a net/http cookie, or nil for a
// nil or nameless one. Pure, so the conversion is testable without a browser.
//
// Domain is passed through EXACTLY as CDP reports it, leading dot and all: that
// dot is the only record of whether the cookie is host-only (bare domain) or
// domain-wide (".example.com"), and stripping it here would silently widen every
// host-only cookie to the whole domain downstream.
//
// Expires is carried for persistent cookies so a downstream consumer can drop a
// cookie that has since expired. A session cookie (Session true, or a
// non-positive epoch, which is CDP's "no expiry") keeps the zero time, which
// every consumer reads as "lives as long as the session does".
func cdpCookieToHTTP(c *proto.NetworkCookie) *http.Cookie {
	if c == nil || c.Name == "" {
		return nil
	}
	out := &http.Cookie{
		Name:     c.Name,
		Value:    c.Value,
		Domain:   c.Domain,
		Path:     c.Path,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
	}
	if !c.Session && c.Expires > 0 {
		out.Expires = c.Expires.Time()
	}
	return out
}

// closePageWithTimeout attempts to close a page with timeout and retry logic.
// Returns error only if ALL retries fail.
func closePageWithTimeout(rodPage *rod.Page, timeout time.Duration, maxRetries int) error {
	targetID := rodPage.TargetID

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create channel for close result
		resultChan := make(chan error, 1)

		// Run Close() in goroutine with timeout protection
		go func() {
			resultChan <- rodPage.Close()
		}()

		// Wait for either completion or timeout
		select {
		case err := <-resultChan:
			if err == nil {
				if attempt > 1 {
					zap.L().Debug("Page closed successfully after retry",
						zap.String("target_id", string(targetID)),
						zap.Int("attempt", attempt))
				}
				return nil
			}
			zap.L().Warn("Page close failed, will retry",
				zap.String("target_id", string(targetID)),
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries))

		case <-time.After(timeout):
			zap.L().Warn("Page close timed out, will retry",
				zap.String("target_id", string(targetID)),
				zap.Duration("timeout", timeout),
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries))
		}

		// Exponential backoff before retry (50ms, 100ms, 150ms)
		if attempt < maxRetries {
			backoff := time.Duration(50*attempt) * time.Millisecond
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("failed to close page %s after %d attempts", targetID, maxRetries)
}

// CloseOtherWindows closes all pages except the current one and keep, with
// timeout protection. It queries the browser to get ALL actual windows
// (including those opened by target="_blank" or window.open()). keep names the
// crawl's other tabs, which must survive one tab's popup cleanup.
//
// CRITICAL: Uses timeout + retry to prevent deadlocks when pages are slow to close.
// This is essential for target="_blank" links which may open pages faster than we can track them.
func (b *Browser) CloseOtherWindows(keep ...*Page) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.currentPage == nil {
		zap.L().Debug("CloseOtherWindows: no current page set, nothing to close")
		return nil
	}

	currentTargetID := b.currentPage.rodPage.TargetID
	kept := []*Page{b.currentPage}
	keepIDs := map[proto.TargetTargetID]bool{currentTargetID: true}
	for _, p := range keep {
		if p == nil || p.rodPage == nil || keepIDs[p.rodPage.TargetID] {
			continue
		}
		keepIDs[p.rodPage.TargetID] = true
		kept = append(kept, p)
	}

	// Query all browser pages including those opened by target="_blank" or window.open()
	allPages, err := b.boundedBrowser().Pages()
	if err != nil {
		zap.L().Error("Failed to query browser pages", zap.Error(err))
		return fmt.Errorf("failed to query browser pages: %w", err)
	}

	zap.L().Debug("CloseOtherWindows: closing extra pages",
		zap.Int("total_pages", len(allPages)),
		zap.String("current_target", string(currentTargetID)))

	// Close pages not matching current target with timeout protection
	closedCount := 0
	failedCount := 0

	for _, rodPage := range allPages {
		if keepIDs[rodPage.TargetID] {
			continue
		}

		// Attempt to close with timeout (5s per attempt, 3 retries)
		err := closePageWithTimeout(rodPage, 5*time.Second, 3)
		if err != nil {
			zap.L().Warn("Failed to close page, continuing anyway",
				zap.String("target_id", string(rodPage.TargetID)),
				zap.Error(err))
			failedCount++
		} else {
			closedCount++
		}
	}

	zap.L().Debug("CloseOtherWindows: completed",
		zap.Int("closed", closedCount),
		zap.Int("failed", failedCount))

	// Reset internal tracking to only the kept pages
	b.pages = kept

	// Return error if ALL pages failed to close (indicates serious problem)
	if failedCount > 0 && closedCount == 0 && len(allPages) > len(kept) {
		return fmt.Errorf("failed to close any of %d extra pages", len(allPages)-len(kept))
	}

	return nil
}

// Close closes the browser.
func (b *Browser) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close all pages
	for _, page := range b.pages {
		_ = page.Close()
	}
	b.pages = nil

	// Close browser. Cap it so a wedged browser can't hang teardown forever
	// (the deferred pool.Close at the end of a crawl runs through here).
	var closeErr error
	switch {
	case b.closeRod != nil:
		closeErr = b.closeRod()
	case b.rodBrowser != nil:
		closeErr = b.boundedBrowser().Close()
	}

	// A bounded close that FAILED means the browser did not acknowledge shutdown
	// within browserOpTimeout — the process may well still be running, and
	// Close() returning was previously the last anyone looked at it. Escalate to
	// the launcher's own kill, which is what actually owns the process.
	//
	// Kill also removes the profile, and it is idempotent, so the removal below
	// is not duplicated work on this path — just whichever of the two runs first.
	//
	// An acknowledged close is not an exited process: Chromium answers
	// Browser.close and then spends a moment shutting down, flushing its profile
	// (Default/Cache, Network Persistent State...) as it goes. Removing the
	// profile in that window lets the exiting process re-create it, which
	// stranded one profile directory per closed browser. So a clean close waits
	// for the exit too, and a process that does not exit gets the same kill.
	if closeErr != nil || !b.awaitProcessExit(browserExitTimeout) {
		b.Kill()
	}

	// Remove the Chromium profile whether or not the browser closed cleanly: a
	// browser that failed to shut down is exactly the case that used to strand
	// its profile. Done after the close above so the process is no longer
	// writing into it.
	removeProfileDir(b.profileDir, "close")
	b.profileDir = ""

	return closeErr
}

// browserExitTimeout bounds how long Close waits for the browser process to exit
// after an acknowledged close before escalating to Kill. Chromium normally exits
// well within it. A variable so tests can shrink it.
var browserExitTimeout = 5 * time.Second

// awaitProcessExit reports whether the launched browser process exited within
// timeout, and true when there is no process to wait for. rod's Cleanup is what
// observes the exit (it also removes the profile once the process is gone); on a
// timeout it keeps waiting in the background, so the Kill that follows still
// ends with the profile removed after the process is really dead.
func (b *Browser) awaitProcessExit(timeout time.Duration) bool {
	l := b.launcher
	if l == nil || l.PID() == 0 {
		return true
	}
	exited := make(chan struct{})
	go func() {
		l.Cleanup()
		close(exited)
	}()
	select {
	case <-exited:
		return true
	case <-time.After(timeout):
		zap.L().Debug("browser process did not exit after close, killing it",
			zap.Int("pid", l.PID()), zap.Duration("waited", timeout))
		return false
	}
}

// IsConnected returns true if browser is connected.
func (b *Browser) IsConnected() bool {
	return b.rodBrowser != nil
}

// browserPreferenceOrderFor is the OS-specific list of system browser binaries
// to try, in priority order: real Google Chrome first, then Chromium. (Chrome
// for Testing is handled separately by browserCandidates, always after these.)
// Both bare names — resolved via PATH — and absolute fallbacks are listed; the
// absolute paths cover the apt layout where the real binary lives under
// /usr/lib/chromium and the snap stub sits in /usr/bin. Duplicates that resolve
// to the same path are collapsed by systemBrowserBins. Parameterized by GOOS so
// the ordering can be unit-tested on any host.
func browserPreferenceOrderFor(goos string) []string {
	return browserPreferenceOrderForEnv(goos, os.Getenv)
}

// browserPreferenceOrderForEnv is browserPreferenceOrderFor with the environment
// lookup injected. The Windows list is built from LOCALAPPDATA/ProgramFiles, so
// without this seam it could only be exercised on a Windows host — the same
// reason systemBrowserBins takes its lookPath as a parameter.
func browserPreferenceOrderForEnv(goos string, getenv func(string) string) []string {
	switch goos {
	case "linux":
		return []string{
			// Google Chrome (real).
			"google-chrome-stable", "google-chrome", "chrome",
			"/usr/bin/google-chrome-stable", "/usr/bin/google-chrome",
			// Chromium.
			"chromium", "chromium-browser",
			"/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/lib/chromium/chromium",
			"/usr/lib/chromium-browser/chromium-browser",
		}
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"google-chrome", "chrome",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"chromium",
		}
	case "windows":
		// Chrome is essentially never on PATH on Windows, so the absolute
		// install locations carry this list; the bare names stay first so a
		// user who *did* put one on PATH keeps that choice. Per-user installs
		// (LOCALAPPDATA) are listed before machine-wide ones because when both
		// exist the per-user one is what that user actually launches.
		paths := []string{"chrome"}
		local := getenv("LOCALAPPDATA")
		progFiles := envOr(getenv, "ProgramFiles", `C:\Program Files`)
		progFiles86 := envOr(getenv, "ProgramFiles(x86)", `C:\Program Files (x86)`)
		if local != "" {
			paths = append(paths, winPath(local, `Google\Chrome\Application\chrome.exe`))
		}
		paths = append(paths,
			winPath(progFiles, `Google\Chrome\Application\chrome.exe`),
			winPath(progFiles86, `Google\Chrome\Application\chrome.exe`),
		)
		if local != "" {
			// Canary, after stable Chrome and before Chromium (mirrors darwin).
			paths = append(paths, winPath(local, `Google\Chrome SxS\Application\chrome.exe`))
		}
		paths = append(paths, "chromium")
		if local != "" {
			paths = append(paths, winPath(local, `Chromium\Application\chrome.exe`))
		}
		return append(paths, winPath(progFiles, `Chromium\Application\chrome.exe`))
	default:
		return []string{"chrome", "chromium"}
	}
}

// envOr returns the named environment variable, or fallback when it is unset.
// The literal fallbacks matter on a stripped environment (a service account, a
// CI shell) where ProgramFiles may be absent but the standard location is still
// correct.
func envOr(getenv func(string) string, name, fallback string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return fallback
}

// winPath joins a Windows base directory and a relative Windows path with a
// literal backslash. filepath.Join is deliberately not used: it joins with the
// *host's* separator, so building these on a linux/darwin machine (which the
// unit tests do) would emit "C:\Program Files/Google\Chrome\...".
func winPath(base, rel string) string {
	return strings.TrimRight(base, `\`) + `\` + rel
}

// lookPathFound resolves name via exec.LookPath, returning the absolute path and
// whether it was found. Split out so systemBrowserBins can be unit-tested with a
// stubbed lookup.
func lookPathFound(name string) (string, bool) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

// systemBrowserBins returns the resolvable, validated system browser binaries in
// the given preference order, deduplicated by resolved path. Real Chrome sorts
// ahead of Chromium so a working Chrome is preferred, while still enumerating
// every binary so launch() can fall through a crash-on-launch one. lookPath and
// validate are injected for testing (production: lookPathFound + validateBrowserBin).
func systemBrowserBins(order []string, lookPath func(string) (string, bool), validate func(string) bool) []string {
	var out []string
	seen := make(map[string]bool)
	for _, name := range order {
		p, ok := lookPath(name)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true // mark before validate so a shared path is validated once
		if !validate(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// validateBrowserBin checks if a browser binary is a real browser executable
// (not a snap stub or broken wrapper). On Ubuntu, apt install chromium-browser
// installs a shell script at /usr/bin/chromium-browser that just prints
// "Please install it with: snap install chromium" and exits.
func validateBrowserBin(binPath string) bool {
	// Chrome on Windows is a GUI-subsystem binary: `chrome.exe --version` has
	// no console to write to, so it exits without printing anything. Probing by
	// output would therefore reject every real Chrome on Windows. Fall back to
	// "the file is there and is a file" — the candidate paths this validates
	// are specific install locations, not guesses, and a genuinely broken
	// binary surfaces when the launch itself fails rather than silently.
	if runtime.GOOS == "windows" {
		info, err := os.Stat(binPath)
		return err == nil && info.Mode().IsRegular()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	output := string(out)
	// Snap stubs print "requires the chromium snap to be installed"
	if strings.Contains(output, "snap") {
		return false
	}
	// A real browser prints a version line like "Chromium 124.0.6367.60"
	return strings.Contains(output, "Chromium") ||
		strings.Contains(output, "Chrome") ||
		strings.Contains(output, "Microsoft Edge")
}

// getEmbeddedBrowserPath returns the path to the embedded browser binary based on config.
func (b *Browser) getEmbeddedBrowserPath() (string, error) {
	engine := b.config.BrowserEngine
	if engine == "" {
		engine = "chromium" // Default
	}

	// Map engine name to chromium.BrowserEngine
	var browserEngine chromium.BrowserEngine
	switch engine {
	case "chromium":
		browserEngine = chromium.EngineChromium
	case "ungoogled":
		browserEngine = chromium.EngineUngoogled
	case "fingerprint":
		browserEngine = chromium.EngineFingerprint
	default:
		return "", fmt.Errorf("unknown browser engine: %s", engine)
	}

	return chromium.GetBrowserPath(browserEngine, "")
}

// Pool manages a pool of browsers.
type Pool struct {
	config   *config.Config
	browsers []*Browser
	mu       sync.Mutex
}

// NewPool creates a new browser pool. Provisioning is not cancellable; see
// NewPoolWithContext.
func NewPool(cfg *config.Config) (*Pool, error) {
	return NewPoolWithContext(context.Background(), cfg)
}

// NewPoolWithContext creates a new browser pool whose provisioning stops when
// ctx ends (see NewWithContext).
func NewPoolWithContext(ctx context.Context, cfg *config.Config) (*Pool, error) {
	pool := &Pool{
		config:   cfg,
		browsers: make([]*Browser, 0),
	}

	// Create initial browsers
	for i := 0; i < cfg.BrowserCount; i++ {
		browser, err := NewWithContext(ctx, cfg)
		if err != nil {
			_ = pool.Close()
			return nil, fmt.Errorf("failed to create browser %d: %w", i, err)
		}
		pool.browsers = append(pool.browsers, browser)
	}

	return pool, nil
}

// SetCrawlContext binds ctx onto every browser in the pool so pages they create
// inherit the crawl deadline/cancellation. Call before the crawl starts.
func (p *Pool) SetCrawlContext(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, browser := range p.browsers {
		browser.SetCrawlContext(ctx)
	}
}

// Get returns a browser from the pool.
func (p *Pool) Get() *Browser {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.browsers) == 0 {
		return nil
	}

	// Round-robin selection
	browser := p.browsers[0]
	p.browsers = append(p.browsers[1:], browser)
	return browser
}

// Close closes all browsers in the pool.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for _, browser := range p.browsers {
		if err := browser.Close(); err != nil {
			lastErr = err
		}
	}
	p.browsers = nil

	return lastErr
}

// Size returns the number of browsers in the pool.
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.browsers)
}

// WaitContext creates a context with timeout.
func WaitContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}

// offlineMode drops the browser download rungs (SAFE-11, --offline).
var offlineMode atomic.Bool

// SetOffline turns the browser download fallbacks off (true) or on.
func SetOffline(v bool) { offlineMode.Store(v) }

// Offline reports whether browser downloads are disabled.
func Offline() bool { return offlineMode.Load() }

// PopupURLs lists the URLs of page targets opened by p (window.open /
// target=_blank) and still open, after giving each up to wait to load so its
// traffic is captured before CloseOtherWindows closes it (MISS-29a). Popups
// used to be closed ~200ms after the click, their traffic lost.
func (b *Browser) PopupURLs(p *Page, wait time.Duration) []string {
	if b == nil || p == nil || p.rodPage == nil {
		return nil
	}
	res, err := proto.TargetGetTargets{}.Call(b.boundedBrowser())
	if err != nil {
		return nil
	}
	var out []string
	for _, info := range res.TargetInfos {
		if info == nil || info.Type != proto.TargetTargetInfoTypePage || info.OpenerID != p.rodPage.TargetID {
			continue
		}
		if wait > 0 {
			if pg, perr := b.boundedBrowser().PageFromTarget(info.TargetID); perr == nil {
				_ = pg.Timeout(wait).WaitLoad()
				if u, uerr := pg.Info(); uerr == nil && u != nil && u.URL != "" {
					info.URL = u.URL
				}
			}
		}
		if info.URL != "" && info.URL != "about:blank" {
			out = append(out, info.URL)
		}
	}
	return out
}
