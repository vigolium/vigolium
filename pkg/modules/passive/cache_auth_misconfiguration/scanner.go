package cache_auth_misconfiguration

import (
	"fmt"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
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

	// Parse response headers and require an actual cache HIT. A CDN/MISS header
	// proves only that a cache layer exists, not that this user-specific response
	// was stored or replayed.
	var cacheControl, vary string
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
	}

	// Check if response is cacheable
	if !isCacheable(cacheControl) {
		return nil, nil
	}

	cacheInfo := infra.CacheStateFromHeaders(ctx.Response().Headers())
	if !cacheInfo.Hit {
		return nil, nil
	}

	// Only Set-Cookies that look user-specific matter. LB-affinity, analytics
	// and consent cookies are not a cross-user leak even when cached.
	sensitiveSetCookie := firstSensitiveCookie(setCookies)
	sensitiveRequestCookie := firstSensitiveRequestCookie(ctx.Request().Header("Cookie"))

	// Check for Authorization in request
	hasAuthReq := credentialLooksReal(ctx.Request().Header("Authorization"))

	// No user-specific indicators
	if sensitiveSetCookie == "" && sensitiveRequestCookie == "" && !hasAuthReq {
		return nil, nil
	}

	// Check for missing Vary headers
	var issues []string
	if sensitiveSetCookie != "" && !varyContains(vary, "cookie") {
		issues = append(issues, fmt.Sprintf("live Set-Cookie %q present without Vary: Cookie", sensitiveSetCookie))
	}
	if sensitiveRequestCookie != "" && !varyContains(vary, "cookie") {
		issues = append(issues, fmt.Sprintf("request cookie %q present without Vary: Cookie", sensitiveRequestCookie))
	}
	if hasAuthReq && !varyContains(vary, "authorization") {
		issues = append(issues, "Authorization in request but missing Vary: Authorization")
	}

	if len(issues) == 0 {
		return nil, nil
	}

	extracted := append(issues,
		fmt.Sprintf("Cache-Control: %s", cacheControl),
		fmt.Sprintf("Cache hit: %s", cacheInfo.Evidence),
	)
	if vary != "" {
		extracted = append(extracted, fmt.Sprintf("Vary: %s", vary))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindCandidate,
			EvidenceGrade:    output.EvidenceGradeCandidate,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Authenticated Cache-Keying Candidate",
				Description: fmt.Sprintf("A cache HIT at %s was explicitly publicly cacheable and involved a credential/session indicator without a matching HTTP Vary token: %s. This does not prove the cache lacks an equivalent internal key or that another user receives the response.", urlx.Path, strings.Join(issues, "; ")),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"cache", "authentication", "vary", "misconfiguration"},
				Reference:   []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"},
			},
			Metadata: map[string]any{
				"cache_hit_evidence": cacheInfo.Evidence,
				"cross_user_replay":  false,
				"body_personalized":  false,
				"internal_cache_key": "unknown",
			},
		},
	}, nil
}

// firstSensitiveCookie returns the name of the first Set-Cookie that looks
// user-specific, or "" if every cookie is a known non-sensitive (LB / analytics
// / consent) cookie. The name is used as finding evidence.
func firstSensitiveCookie(setCookies []string) string {
	for _, sc := range setCookies {
		cookie, err := stdhttp.ParseSetCookie(sc)
		if err != nil || cookie == nil || cookie.Name == "" || isNonSensitiveCookie(cookie.Name) {
			continue
		}
		if cookie.Value == "" || cookie.MaxAge < 0 || cookie.MaxAge == 0 && strings.Contains(strings.ToLower(sc), "max-age=0") ||
			!cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			continue
		}
		return cookie.Name
	}
	return ""
}

func firstSensitiveRequestCookie(raw string) string {
	cookies, err := stdhttp.ParseCookie(raw)
	if err != nil {
		return ""
	}
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name != "" && cookie.Value != "" && !isNonSensitiveCookie(cookie.Name) && !modkit.IsPlaceholderValue(cookie.Value) {
			return cookie.Name
		}
	}
	return ""
}

func credentialLooksReal(raw string) bool {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return false
	}
	value := parts[len(parts)-1]
	return len(value) >= 8 && !modkit.IsPlaceholderValue(value)
}

func varyContains(vary, wanted string) bool {
	for _, token := range strings.Split(vary, ",") {
		if strings.EqualFold(strings.TrimSpace(token), wanted) {
			return true
		}
	}
	return false
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
