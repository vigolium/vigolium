package cache_auth_misconfiguration

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// cacheIndicatorHeaders are response headers proving a shared HTTP cache (CDN or
// reverse proxy) is actually in the request path. Origin "Cache-Control: public"
// alone does NOT prove a cache stores and replays the response — and virtually
// all CDNs strip Set-Cookie from cached responses by default — so we require at
// least one of these before flagging.
var cacheIndicatorHeaders = map[string]bool{
	"age": true, "x-cache": true, "x-cache-status": true,
	"x-cache-hits": true, "cf-cache-status": true, "x-varnish": true,
	"x-proxy-cache": true, "akamai-cache-status": true, "x-cacheable": true,
	"x-cdn-cache": true, "fastly-cache": true,
}

// nonSensitiveCookieExact is the set of well-known cookie names that do not
// carry user-identifying data — load-balancer affinity, analytics/marketing,
// and consent cookies. Leaking these cross-user is not a session compromise, so
// their presence alone must not raise a finding.
var nonSensitiveCookieExact = map[string]bool{
	// Load-balancer / affinity / WAF
	"awsalb": true, "awsalbcors": true, "lb": true, "route": true,
	"srv_id": true, "server_id": true, "__cfduid": true, "__cf_bm": true,
	"cf_clearance": true, "__cflb": true, "datadome": true,
	// Analytics / marketing
	"_ga": true, "_gid": true, "_gat": true, "_fbp": true, "_fbc": true,
	"_gcl_au": true, "_clck": true, "_clsk": true,
	// Consent
	"cookieconsent": true, "cookie_consent": true, "cookie-agreed": true,
	"euconsent": true, "euconsent-v2": true, "gdpr": true, "consent": true,
	"usercentrics": true, "cookielawinfoconsent": true,
}

// nonSensitiveCookiePrefixes covers families of non-sensitive cookies whose
// names carry a per-property suffix (e.g. BIGipServerpool_x, _ga_AB12, incap_ses_1).
var nonSensitiveCookiePrefixes = []string{
	"bigipserver", "bigip", "incap_ses_", "visid_incap_", "nlbi_",
	"_ga_", "_gac_", "__utm", "_gat_", "ajs_", "mp_", "_pk_", "_hjsession",
	"amplitude_", "mixpanel", "intercom-", "optimizely", "nr_", "_uetsid",
	"_uetvid", "cookielawinfo-", "cookieconsent", "cookie_consent", "cookie-agreed",
}

// Module implements the cache-auth misconfiguration passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Cache-Auth Misconfiguration module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("cache_auth_misconfiguration"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks for cacheable responses missing Vary headers.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Skip static assets — by file extension and by path segment.
	if modkit.IsStaticAssetPath(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Parse response headers
	var cacheControl, vary, cacheIndicator string
	var setCookies []string
	for _, hdr := range ctx.Response().Headers() {
		nameLower := strings.ToLower(hdr.Name)
		switch nameLower {
		case "cache-control":
			cacheControl = strings.ToLower(hdr.Value)
		case "vary":
			vary = strings.ToLower(hdr.Value)
		case "set-cookie":
			setCookies = append(setCookies, hdr.Value)
		}
		if cacheIndicator == "" && cacheIndicatorHeaders[nameLower] {
			cacheIndicator = hdr.Name
		}
	}

	// Check if response is cacheable
	if !isCacheable(cacheControl) {
		return nil, nil
	}

	// Require evidence that a shared cache is actually in the path. Without it,
	// the public Cache-Control comes from the origin only and there is no cache
	// to leak one user's response to another.
	if cacheIndicator == "" {
		return nil, nil
	}

	// Only Set-Cookies that look user-specific matter. LB-affinity, analytics
	// and consent cookies are not a cross-user leak even when cached.
	sensitiveCookie := firstSensitiveCookie(setCookies)

	// Check for Authorization in request
	hasAuthReq := ctx.Request().Header("Authorization") != ""

	// No user-specific indicators
	if sensitiveCookie == "" && !hasAuthReq {
		return nil, nil
	}

	// Check for missing Vary headers
	var issues []string
	if sensitiveCookie != "" && !strings.Contains(vary, "cookie") {
		issues = append(issues, fmt.Sprintf("Set-Cookie %q present but missing Vary: Cookie", sensitiveCookie))
	}
	if hasAuthReq && !strings.Contains(vary, "authorization") {
		issues = append(issues, "Authorization in request but missing Vary: Authorization")
	}

	if len(issues) == 0 {
		return nil, nil
	}

	extracted := append(issues,
		fmt.Sprintf("Cache-Control: %s", cacheControl),
		fmt.Sprintf("Shared cache present: %s", cacheIndicator),
	)
	if vary != "" {
		extracted = append(extracted, fmt.Sprintf("Vary: %s", vary))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Cache-Auth Misconfiguration",
				Description: fmt.Sprintf("Cacheable response at %s (served via shared cache: %s) has user-specific data without proper Vary headers: %s", urlx.Path, cacheIndicator, strings.Join(issues, "; ")),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"cache", "authentication", "vary", "misconfiguration"},
				Reference:   []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"},
			},
		},
	}, nil
}

// firstSensitiveCookie returns the name of the first Set-Cookie that looks
// user-specific, or "" if every cookie is a known non-sensitive (LB / analytics
// / consent) cookie. The name is used as finding evidence.
func firstSensitiveCookie(setCookies []string) string {
	for _, sc := range setCookies {
		name := cookieName(sc)
		if name != "" && !isNonSensitiveCookie(name) {
			return name
		}
	}
	return ""
}

// cookieName extracts the cookie name from a Set-Cookie header value
// ("NAME=value; Path=/; ..." -> "NAME").
func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i >= 0 {
		return strings.TrimSpace(setCookie[:i])
	}
	return ""
}

// isNonSensitiveCookie reports whether a cookie name belongs to a well-known
// load-balancer, analytics, or consent family that carries no user secret.
func isNonSensitiveCookie(name string) bool {
	lower := strings.ToLower(name)
	if nonSensitiveCookieExact[lower] {
		return true
	}
	for _, p := range nonSensitiveCookiePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// isCacheable checks if the Cache-Control header indicates the response is publicly cacheable.
func isCacheable(cc string) bool {
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	return strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage")
}
