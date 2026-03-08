package browser

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	chromium "github.com/vigolium/vigolium/internal/resources/spitolas"
	"github.com/vigolium/vigolium/pkg/spitolas/extension"
	_ "github.com/vigolium/vigolium/pkg/spitolas/extension/ublock" // Auto-register uBlock

	"github.com/vigolium/vigolium/pkg/spitolas/rod"
	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/launcher"
	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/proto"
	"go.uber.org/zap"
)

// Browser wraps rod.Browser with additional functionality.
type Browser struct {
	rodBrowser  *rod.Browser
	config      *config.Config
	launcher    *launcher.Launcher
	currentPage *Page // Persistent page for session state preservation

	mu    sync.Mutex
	pages []*Page
}

// New creates a new browser instance.
func New(cfg *config.Config) (*Browser, error) {
	b := &Browser{
		config: cfg,
		pages:  make([]*Page, 0),
	}

	if err := b.launch(); err != nil {
		return nil, err
	}

	return b, nil
}

// launch starts the browser process.
func (b *Browser) launch() error {
	l := launcher.New()

	// Try to use embedded browser binary
	binPath, err := b.getEmbeddedBrowserPath()
	if err != nil {
		zap.L().Warn("Failed to get embedded browser, using auto-download fallback",
			zap.Error(err))
	} else {
		l = l.Bin(binPath)
		zap.L().Debug("Using embedded browser", zap.String("path", binPath))
	}

	l.NoSandbox(true)
	l.Set("disable-web-security").
		Set("allow-running-insecure-content").
		Set("reduce-security-for-testing").
		Set("disable-ipc-flooding-protection").
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
		Set("disable-background-networking").
		// Disable HTTPS upgrade features to prevent Chrome from auto-upgrading HTTP to HTTPS
		// which causes timeout when target doesn't have HTTPS server
		Set("disable-features", "ChromeWhatsNewUI,HttpsUpgrades,HttpsFirstModeV2,HttpsFirstBalancedMode,HttpsFirstModeForAdvancedProtectionUsers,ImageServiceObserveSyncDownloadStatus,TrackingProtection3pcd,LensOverlay,AutomationControlled").
		Set("ignore-certificate-errors")

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

	// Get all extension paths
	extPaths, err := extension.GetExtensionPaths()
	if err != nil {
		return fmt.Errorf("failed to get extensions: %w", err)
	}

	if len(extPaths) > 0 {
		zap.L().Debug("Extensions loaded", zap.Int("count", len(extPaths)))
		for _, p := range extPaths {
			zap.L().Debug("Extension path", zap.String("path", p))
		}

		// Use headless=new for extensions (supports extensions unlike old headless)
		if b.config.Headless {
			l = l.HeadlessNew(true)
		} else {
			l = l.Headless(false)
		}

		// Load all extensions
		l = l.Set("load-extension", strings.Join(extPaths, ","))
		l = l.Set("disable-extensions-except", strings.Join(extPaths, ","))
	} else {
		// No extensions - use standard headless
		if b.config.Headless {
			l = l.Headless(true)
		} else {
			l = l.Headless(false)
		}
	}

	// Set proxy if configured
	if b.config.ProxyURL != "" {
		l = l.Proxy(b.config.ProxyURL)
	}

	// Launch the browser
	u, err := l.Launch()
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}

	b.launcher = l

	// Connect to browser
	browser := rod.New().ControlURL(u)
	if err := browser.Connect(); err != nil {
		return fmt.Errorf("failed to connect to browser: %w", err)
	}

	b.rodBrowser = browser

	// Wait for extensions to initialize
	if len(extPaths) > 0 {
		time.Sleep(2 * time.Second)
		zap.L().Debug("Extensions initialized")
	}

	return nil
}

// NewPage creates a new page (tab).
func (b *Browser) NewPage() (*Page, error) {
	rodPage, err := b.rodBrowser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}

	// Enable Network domain on this page for traffic capture.
	// Browser.EachEvent only enables domains at browser level, but Network events
	// are only emitted from pages that have the Network domain explicitly enabled.
	_ = proto.NetworkEnable{}.Call(rodPage)

	page := &Page{
		rodPage: rodPage,
		config:  b.config,
		browser: b,
	}

	// CRAWLJAX PARITY: Setup auto-accept dialog handler for alert/confirm/prompt
	// This runs in background and automatically accepts all JS dialogs.
	// Matches Java Crawljax handlePopups() behavior.
	page.setupAutoDialogHandler()

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

// CloseOtherWindows closes all pages except the current one with timeout protection.
// This matches Java Crawljax's closeOtherWindows() which uses WebDriver.getWindowHandles()
// to get ALL actual browser windows (including those opened by target="_blank" or window.open()).
//
// CRITICAL: Uses timeout + retry to prevent deadlocks when pages are slow to close.
// This is essential for target="_blank" links which may open pages faster than we can track them.
//
// CRAWLJAX PARITY: WebDriverBackedEmbeddedBrowser.java:587-603
func (b *Browser) CloseOtherWindows() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.currentPage == nil {
		zap.L().Debug("CloseOtherWindows: no current page set, nothing to close")
		return nil
	}

	currentTargetID := b.currentPage.rodPage.TargetID

	// Query actual browser pages (matches Crawljax WebDriver.getWindowHandles())
	// This gets ALL pages including those opened by target="_blank" or window.open()
	allPages, err := b.rodBrowser.Pages()
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
		if rodPage.TargetID == currentTargetID {
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

	// Reset internal tracking to only current page
	b.pages = []*Page{b.currentPage}

	// Return error if ALL pages failed to close (indicates serious problem)
	if failedCount > 0 && closedCount == 0 && len(allPages) > 1 {
		return fmt.Errorf("failed to close any of %d extra pages", len(allPages)-1)
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

	// Close browser
	if b.rodBrowser != nil {
		if err := b.rodBrowser.Close(); err != nil {
			return err
		}
	}

	return nil
}

// IsConnected returns true if browser is connected.
func (b *Browser) IsConnected() bool {
	return b.rodBrowser != nil
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

// NewPool creates a new browser pool.
func NewPool(cfg *config.Config) (*Pool, error) {
	pool := &Pool{
		config:   cfg,
		browsers: make([]*Browser, 0),
	}

	// Create initial browsers
	for i := 0; i < cfg.BrowserCount; i++ {
		browser, err := New(cfg)
		if err != nil {
			_ = pool.Close()
			return nil, fmt.Errorf("failed to create browser %d: %w", i, err)
		}
		pool.browsers = append(pool.browsers, browser)
	}

	return pool, nil
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
