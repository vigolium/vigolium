package crawler

import (
	"context"
	"errors"
	"fmt"
	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// Authentication states (Stats.AuthState). There is deliberately no
// "verified": applying credentials says nothing about whether the application
// accepted them, and an identity check needs an operator-declared success
// condition this crawler does not have.
const (
	AuthNotRequested = "not-requested" // no cookies or headers were configured
	AuthConfigured   = "configured"    // configured, not yet applied to a page
	AuthApplied      = "applied"       // installed on the start page (and later pages)
	AuthFailed       = "failed"        // configured but not (fully) applied
	AuthLost         = "lost"          // the crawl was logged out and re-applying did not restore it
	AuthRestored     = "restored"      // logged out once and restored by re-applying credentials
)

// pageAuthOps are the two page calls that install credentials. Nil fields use
// the page's own methods; tests substitute them so the credential rules run
// without a browser.
type pageAuthOps struct {
	setCookies func(page *browser.Page, cookies []*http.Cookie) error
	setHeaders func(page *browser.Page, headers map[string]string) error
}

var errNoPage = errors.New("no page")

func (o pageAuthOps) cookies(page *browser.Page, cookies []*http.Cookie) error {
	if o.setCookies != nil {
		return o.setCookies(page, cookies)
	}
	if page == nil {
		return errNoPage
	}
	return page.SetCookies(cookies)
}

// installHeaders puts the operator's credential headers on page. By default
// that is the per-request credential router: headers ride only on
// requests the credential scope admits, never on third-party subresources,
// and the scan's method policy blocks disallowed XHR/fetch methods.
// Network.setExtraHTTPHeaders, which put them on every request, is not used.
func (c *Crawler) installHeaders(page *browser.Page, headers map[string]string) error {
	if c.authOps.setHeaders != nil {
		return c.authOps.setHeaders(page, headers)
	}
	if page == nil {
		return errNoPage
	}
	return page.InstallCredentialRouter(headers, c.credentialRouteAllowed, c.config.MethodAllowed, c.credentialPatterns())
}

// credentialRouteAllowed is the router's per-request credential decision:
// inside the credential scope, and not withdrawn for leaving it.
func (c *Crawler) credentialRouteAllowed(rawURL string) bool {
	c.mu.Lock()
	withdrawn := c.credentialHeadersWithdrawn
	c.mu.Unlock()
	return !withdrawn && c.credentialOriginAllowed(rawURL)
}

// credentialPatterns narrows which requests the router pauses: the target
// host and its subdomains under the default host scope, every request ("*")
// under an explicit crawl scope (judged by credentialOriginAllowed).
func (c *Crawler) credentialPatterns() []string {
	if c.config.CrawlScope != nil || c.config.URL == nil {
		return nil
	}
	return browser.CredentialHostPatterns(c.config.URL.Hostname())
}

// initialAuthState is the state before any page exists.
func (c *Crawler) initialAuthState() string {
	if len(c.config.InitialCookies) == 0 && len(c.config.ExtraHeaders) == 0 {
		return AuthNotRequested
	}
	return AuthConfigured
}

// credentialOriginAllowed reports whether operator credential headers may ride
// on a page at rawURL: anywhere the operator's scope admits, or — under the
// default host scope — the target host and its subdomains. An adopted
// relocation host is not included: the credentials were given for the target.
func (c *Crawler) credentialOriginAllowed(rawURL string) bool {
	if c.config.CrawlScope != nil {
		return c.config.CrawlScope(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return sameOrSubdomain(strings.ToLower(u.Hostname()), strings.ToLower(c.config.URL.Hostname()))
}

// applyPageAuth seeds operator-supplied authentication onto a freshly created
// page before navigation: initial cookies (written into the browser's cookie
// jar, which scopes them by their own domain/path) and extra HTTP headers such
// as Authorization / X-Api-Key. Extra headers are page-wide in CDP — they ride
// on every request the page makes — so they are installed only when the
// target is inside the operator scope, and never again once the crawl has
// withdrawn them for leaving it (withdrawCredentialHeaders).
//
// The outcome is recorded in Stats.AuthState; a failure is sticky, so a run
// whose start page went out unauthenticated says so even if a later page got
// the credentials. The error is returned for RequireAuth to act on.
func (c *Crawler) applyPageAuth(page *browser.Page) error {
	// Fonts, media and third-party images carry no crawlable surface and cost
	// time on every page. Installed here because this runs for every
	// fresh page.
	if c.config.BlockResources && page != nil && c.authOps.setHeaders == nil {
		if err := page.SetResourceBlocking(c.firstPartyResource); err != nil {
			zap.L().Debug("Spidering: could not install resource blocking", zap.Error(err))
		}
	}
	// A method policy with no credential headers still needs the router: it
	// is what blocks a read-only crawl's XHR/fetch writes.
	if c.config.MethodAllowed != nil && len(c.config.ExtraHeaders) == 0 && page != nil && c.authOps.setHeaders == nil {
		if err := page.InstallCredentialRouter(nil, nil, c.config.MethodAllowed, nil); err != nil {
			zap.L().Debug("Spidering: could not install the method-policy router", zap.Error(err))
		}
	}
	if len(c.config.InitialCookies) == 0 && len(c.config.ExtraHeaders) == 0 {
		return nil
	}
	var errs []error
	if len(c.config.InitialCookies) > 0 {
		zap.L().Debug("Setting initial cookies", zap.Int("count", len(c.config.InitialCookies)))
		if err := c.authOps.cookies(page, c.config.InitialCookies); err != nil {
			errs = append(errs, fmt.Errorf("set cookies: %w", err))
		}
	}
	if len(c.config.ExtraHeaders) > 0 {
		c.mu.Lock()
		withdrawn := c.credentialHeadersWithdrawn
		c.mu.Unlock()
		target := c.config.URL.String()
		switch {
		case withdrawn:
			// Withdrawn when the crawl left the credential scope; a fresh page
			// (reset) does not bring them back.
		case !c.credentialOriginAllowed(target):
			c.denyCredentialHost(c.config.URL.Hostname())
			errs = append(errs, fmt.Errorf("extra headers withheld: the target %s is outside the operator scope", c.config.URL.Hostname()))
		default:
			zap.L().Debug("Setting extra headers", zap.Int("count", len(c.config.ExtraHeaders)))
			if err := c.installHeaders(page, c.config.ExtraHeaders); err != nil {
				errs = append(errs, fmt.Errorf("set extra headers: %w", err))
			}
		}
	}
	err := errors.Join(errs...)
	c.mu.Lock()
	switch {
	case err != nil:
		c.stats.AuthState = AuthFailed
	case c.stats.AuthState != AuthFailed:
		c.stats.AuthState = AuthApplied
	}
	c.mu.Unlock()
	if err != nil {
		zap.L().Warn("Spidering: configured authentication could not be applied", zap.Error(err))
	}
	return err
}

// seedPageAuth applies configured authentication to the start page. The error
// is non-nil only when RequireAuth turns a failed application into a failed
// crawl; otherwise the crawl proceeds and Stats.AuthState says "failed".
func (c *Crawler) seedPageAuth(page *browser.Page) error {
	if err := c.applyPageAuth(page); err != nil && c.config.RequireAuth {
		return fmt.Errorf("authentication required but not applied: %w", err)
	}
	return nil
}

// withdrawCredentialHeaders stops sending the operator's extra headers once
// the crawl's page lands on a host the credential scope does not admit (an
// off-host start redirect: a relocated app being adopted, or a login wall).
// The headers are cleared on page and not installed on later pages; the host
// is recorded (never the header values). Cookies are untouched — the browser's
// jar already scopes them by domain. Without CDP request interception a
// header has necessarily ridden on the redirect hop that got here; this stops
// every request after it.
func (c *Crawler) withdrawCredentialHeaders(page *browser.Page, landingURL, host string) {
	if len(c.config.ExtraHeaders) == 0 || c.credentialOriginAllowed(landingURL) {
		return
	}
	c.mu.Lock()
	already := c.credentialHeadersWithdrawn
	c.credentialHeadersWithdrawn = true
	c.mu.Unlock()
	c.denyCredentialHost(host)
	if already {
		return
	}
	if err := c.installHeaders(page, map[string]string{}); err != nil {
		zap.L().Warn("Spidering: could not clear credential headers after leaving the credential scope",
			zap.String("host", host), zap.Error(err))
		return
	}
	zap.L().Warn("Spidering: stopped sending configured credential headers — the crawl left the operator scope",
		zap.String("host", host))
}

// denyCredentialHost records a host credential headers were kept from.
func (c *Crawler) denyCredentialHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host == "" || slices.Contains(c.stats.CredentialHostsDenied, host) {
		return
	}
	c.stats.CredentialOriginsDenied++
	c.stats.CredentialHostsDenied = append(c.stats.CredentialHostsDenied, host)
}

// firstPartyResource reports whether a resource URL belongs to the target
// (its host or a subdomain, or anything the operator scope admits), so its
// images are never blocked.
func (c *Crawler) firstPartyResource(rawURL string) bool {
	if c.config.CrawlScope != nil && c.config.CrawlScope(rawURL) {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || c.config.URL == nil {
		return true
	}
	return sameOrSubdomain(strings.ToLower(u.Hostname()), strings.ToLower(c.config.URL.Hostname()))
}

// authConfigured reports whether this crawl carries credentials.
func (c *Crawler) authConfigured() bool {
	return len(c.config.InitialCookies) > 0 || len(c.config.ExtraHeaders) > 0 || c.config.AuthMonitor != nil
}

// refreshAuthIfChanged re-applies the live session's credentials when their
// generation moved (a re-login happened elsewhere in the scan).
func (c *Crawler) refreshAuthIfChanged(page *browser.Page) {
	mon := c.config.AuthMonitor
	if mon == nil || (page == nil && c.authOps.setHeaders == nil) {
		return
	}
	gen, headers, cookies := mon.Credentials()
	dirty := c.authDirty.Swap(false)
	c.mu.Lock()
	changed := gen != 0 && (gen != c.authGen || dirty)
	if changed {
		c.authGen = gen
	}
	c.mu.Unlock()
	if !changed {
		return
	}
	c.reapplyCredentials(page, headers, cookies)
}

// reapplyCredentials installs headers (through the credential router) and
// cookies on page.
func (c *Crawler) reapplyCredentials(page *browser.Page, headers map[string]string, cookies []*http.Cookie) {
	if len(headers) > 0 {
		if err := c.installHeaders(page, headers); err != nil {
			zap.L().Debug("Spidering: re-applying session headers failed", zap.Error(err))
		}
	}
	if len(cookies) > 0 {
		if err := c.authOps.cookies(page, cookies); err != nil {
			zap.L().Debug("Spidering: re-applying session cookies failed", zap.Error(err))
		}
	}
}

// checkLoggedOut detects a crawl that lost its session: after an
// authenticated start, a page landing on a login form/URL. It re-applies the
// credentials once and reloads; if the page is still a login page the crawl
// is marked AuthLost (and keeps going anonymously, now honestly reported),
// else AuthRestored. Returns true when the page was a login page.
func (c *Crawler) checkLoggedOut(ctx context.Context, page *browser.Page) bool {
	if !c.authConfigured() || page == nil {
		return false
	}
	c.mu.Lock()
	state := c.stats.AuthState
	c.mu.Unlock()
	if state != AuthApplied && state != AuthRestored {
		return false
	}
	if !c.pageLooksLoggedOut(page) {
		return false
	}
	headers := c.config.ExtraHeaders
	var cookies []*http.Cookie
	if mon := c.config.AuthMonitor; mon != nil {
		var gen uint64
		gen, headers, cookies = mon.Credentials()
		c.mu.Lock()
		c.authGen = gen
		c.mu.Unlock()
	} else {
		cookies = c.config.InitialCookies
	}
	c.reapplyCredentials(page, headers, cookies)
	if err := page.ReloadCtx(ctx); err == nil {
		_ = page.WaitStable(c.config.DOMStableTime)
	}
	next := AuthRestored
	if c.pageLooksLoggedOut(page) {
		next = AuthLost
	}
	c.mu.Lock()
	c.stats.AuthState = next
	c.mu.Unlock()
	zap.L().Warn("Spidering: the crawl landed on a login page after an authenticated start",
		zap.String("outcome", next))
	return true
}

// pageLooksLoggedOut reports whether page is a login page: a login/SSO URL
// or a document that reads as a login form.
func (c *Crawler) pageLooksLoggedOut(page *browser.Page) bool {
	raw, err := page.URL()
	if err == nil {
		if u, perr := url.Parse(raw); perr == nil && authsig.LooksLikeLoginURL(u) {
			return true
		}
	}
	html, err := page.HTML()
	return err == nil && authsig.BodyLooksLikeLogin([]byte(html))
}

// observeAuthResponse feeds one captured response to the live session's
// logged-out detector.
func (c *Crawler) observeAuthResponse(e *network.TrafficEntry) {
	mon := c.config.AuthMonitor
	if mon == nil || e == nil || e.Response == nil {
		return
	}
	c.mu.Lock()
	gen := c.authGen
	c.mu.Unlock()
	h := make(http.Header, len(e.Response.Headers))
	for k, v := range e.Response.Headers {
		h.Set(k, v)
	}
	mon.Observe(gen, e.Response.Status, h, e.Response.Body)
}

// watchAuthChanges marks the crawl auth-dirty whenever the monitor signals a
// re-login, until ctx ends.
func (c *Crawler) watchAuthChanges(ctx context.Context, mon config.AuthMonitor) {
	ch := mon.Changed()
	if ch == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
				c.authDirty.Store(true)
			}
		}
	}()
}
