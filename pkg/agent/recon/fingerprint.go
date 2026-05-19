package recon

import (
	"net/http"
	"regexp"
	"strings"
)

// stackRule is a single inline tech-stack detection rule. Match runs
// against a probeResponse and, when it fires, returns a StackDetection.
// Multiple rules may fire for one response; the orchestrator dedupes by
// detection Name and merges evidence.
type stackRule struct {
	Match func(*probeResponse) (matched bool, version string, evidence string)
	Name  string
	Cat   string
	Tag   string
	Conf  Confidence
}

// headerContainsRule builds a stackRule that fires when the given header
// (case-insensitive) contains needle. The version is extracted from the
// header by skipping past versionPrefix. Used for the many server /
// language detections that all follow the same shape (Server, X-Powered-By,
// X-AspNet-Version, …).
func headerContainsRule(name, cat, tag string, conf Confidence, header, needle, versionPrefix string) stackRule {
	return stackRule{
		Name: name, Cat: cat, Tag: tag, Conf: conf,
		Match: func(r *probeResponse) (bool, string, string) {
			v := r.Header(header)
			if v == "" || !strings.Contains(strings.ToLower(v), needle) {
				return false, "", ""
			}
			version := ""
			if versionPrefix != "" {
				version = extractVersionAfter(v, versionPrefix)
			}
			return true, version, header + ": " + v
		},
	}
}

// headerPresentRule fires when the given header is present (non-empty).
// Evidence is "<header>: <value>".
func headerPresentRule(name, cat, tag string, conf Confidence, header string) stackRule {
	return stackRule{
		Name: name, Cat: cat, Tag: tag, Conf: conf,
		Match: func(r *probeResponse) (bool, string, string) {
			v := r.Header(header)
			if v == "" {
				return false, "", ""
			}
			return true, "", header + ": " + v
		},
	}
}

var (
	wpGeneratorRe       = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)`)
	drupalGeneratorRe   = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']Drupal\s+(\d+)`)
	joomlaGeneratorRe   = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']Joomla!\s+-\s+Open Source Content Management\s+-\s+Version\s+([\d.]+)`)
	nextDataRe          = regexp.MustCompile(`<script\s+id=["']__NEXT_DATA__["']`)
	nuxtRe              = regexp.MustCompile(`window\.__NUXT__`)
	drupalSettingsRe    = regexp.MustCompile(`(?:jQuery\.extend\(Drupal\.settings|drupalSettings\s*=)`)
	railsCsrfRe         = regexp.MustCompile(`<meta\s+name=["']csrf-token["']`)
	laravelXsrfCookieRe = regexp.MustCompile(`(?i)XSRF-TOKEN=`)
	djangoCsrfCookieRe  = regexp.MustCompile(`(?i)csrftoken=`)
	railsSessionCookie  = regexp.MustCompile(`(?i)_(?:[a-z0-9_]+)_session=`)
)

// stackRules is the inline fingerprint catalog applied to every fetched
// response (base URL, well-known paths, OPTIONS responses, etc.). Order
// is not significant — multiple rules may match the same response.
var stackRules = []stackRule{
	// --- Server / language signals (from Server, X-Powered-By) ---
	headerContainsRule("nginx", "server", "nginx", ConfidenceHigh, "Server", "nginx", "nginx/"),
	headerContainsRule("apache", "server", "apache", ConfidenceHigh, "Server", "apache", "Apache/"),
	headerContainsRule("iis", "server", "iis", ConfidenceHigh, "Server", "iis", "IIS/"),
	headerContainsRule("php", "language", "php", ConfidenceHigh, "X-Powered-By", "php", "PHP/"),
	headerContainsRule("express", "framework", "express", ConfidenceHigh, "X-Powered-By", "express", ""),
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if s := r.Header("X-AspNet-Version"); s != "" {
				return true, s, "X-AspNet-Version: " + s
			}
			if xpb := r.Header("X-Powered-By"); strings.Contains(strings.ToLower(xpb), "asp.net") {
				return true, "", "X-Powered-By: " + xpb
			}
			return false, "", ""
		},
		Name: "asp.net", Cat: "framework", Tag: "aspnet", Conf: ConfidenceHigh,
	},

	// --- CMS signals (body + cookies) ---
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if m := wpGeneratorRe.FindStringSubmatch(r.Body); len(m) > 1 {
				return true, m[1], "WordPress generator meta tag"
			}
			if strings.Contains(r.Body, "/wp-content/") || strings.Contains(r.Body, "/wp-includes/") {
				return true, "", "/wp-content/ or /wp-includes/ asset reference in body"
			}
			if strings.Contains(strings.ToLower(r.Header("Link")), "wp-json") {
				return true, "", "Link header references wp-json"
			}
			if r.Header("X-Pingback") != "" {
				return true, "", "X-Pingback: " + r.Header("X-Pingback")
			}
			return false, "", ""
		},
		Name: "wordpress", Cat: "cms", Tag: "wordpress", Conf: ConfidenceHigh,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if m := drupalGeneratorRe.FindStringSubmatch(r.Body); len(m) > 1 {
				return true, m[1], "Drupal generator meta tag"
			}
			if drupalSettingsRe.MatchString(r.Body) {
				return true, "", "Drupal.settings JS object found"
			}
			if strings.Contains(strings.ToLower(r.Header("X-Generator")), "drupal") {
				return true, "", "X-Generator: " + r.Header("X-Generator")
			}
			return false, "", ""
		},
		Name: "drupal", Cat: "cms", Tag: "drupal", Conf: ConfidenceHigh,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if m := joomlaGeneratorRe.FindStringSubmatch(r.Body); len(m) > 1 {
				return true, m[1], "Joomla generator meta tag"
			}
			return false, "", ""
		},
		Name: "joomla", Cat: "cms", Tag: "joomla", Conf: ConfidenceHigh,
	},

	// --- Framework signals (cookies, body) ---
	{
		Match: func(r *probeResponse) (bool, string, string) {
			setCookie := strings.Join(r.HeaderValues("Set-Cookie"), "; ")
			if laravelXsrfCookieRe.MatchString(setCookie) || strings.Contains(strings.ToLower(setCookie), "laravel_session") {
				return true, "", "XSRF-TOKEN or laravel_session cookie present"
			}
			return false, "", ""
		},
		Name: "laravel", Cat: "framework", Tag: "laravel", Conf: ConfidenceHigh,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			setCookie := strings.Join(r.HeaderValues("Set-Cookie"), "; ")
			if djangoCsrfCookieRe.MatchString(setCookie) || strings.Contains(strings.ToLower(setCookie), "sessionid=") {
				return true, "", "csrftoken or sessionid cookie present"
			}
			if strings.Contains(r.Body, "csrfmiddlewaretoken") {
				return true, "", "csrfmiddlewaretoken found in body"
			}
			return false, "", ""
		},
		Name: "django", Cat: "framework", Tag: "django", Conf: ConfidenceHigh,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			setCookie := strings.Join(r.HeaderValues("Set-Cookie"), "; ")
			if railsSessionCookie.MatchString(setCookie) {
				if railsCsrfRe.MatchString(r.Body) {
					return true, "", "_<app>_session cookie + csrf-token meta tag"
				}
				return true, "", "_<app>_session cookie present"
			}
			if r.Header("X-Request-Id") != "" && railsCsrfRe.MatchString(r.Body) {
				return true, "", "csrf-token meta tag + X-Request-Id header (typical Rails)"
			}
			return false, "", ""
		},
		Name: "rails", Cat: "framework", Tag: "rails", Conf: ConfidenceMedium,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			// Spring header signals (the actuator probes also flag spring-boot
			// independently, via stackProbePaths).
			if s := r.Header("X-Application-Context"); s != "" {
				return true, "", "X-Application-Context: " + s
			}
			if strings.Contains(r.Header("Server"), "Spring") {
				return true, "", "Server header references Spring"
			}
			return false, "", ""
		},
		Name: "spring-boot", Cat: "framework", Tag: "spring", Conf: ConfidenceMedium,
	},

	// --- Metaframeworks ---
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if nextDataRe.MatchString(r.Body) {
				return true, "", "__NEXT_DATA__ script block present"
			}
			if strings.Contains(strings.ToLower(r.Header("X-Powered-By")), "next.js") {
				return true, "", "X-Powered-By: " + r.Header("X-Powered-By")
			}
			return false, "", ""
		},
		Name: "next.js", Cat: "metaframework", Tag: "nextjs", Conf: ConfidenceHigh,
	},
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if nuxtRe.MatchString(r.Body) {
				return true, "", "window.__NUXT__ present in body"
			}
			return false, "", ""
		},
		Name: "nuxt", Cat: "metaframework", Tag: "nuxt", Conf: ConfidenceHigh,
	},

	// --- CDN / fronting signals ---
	{
		Match: func(r *probeResponse) (bool, string, string) {
			if r.Header("CF-Ray") != "" || strings.EqualFold(r.Header("Server"), "cloudflare") {
				return true, "", "Cloudflare headers present (CF-Ray / Server: cloudflare)"
			}
			return false, "", ""
		},
		Name: "cloudflare", Cat: "cdn", Tag: "cloudflare", Conf: ConfidenceHigh,
	},
	headerPresentRule("cloudfront", "cdn", "cloudfront", ConfidenceHigh, "X-Amz-Cf-Id"),
}

// extractVersionAfter returns the substring of s immediately following
// prefix up to the next whitespace, slash, or end-of-string. Used to
// pull "1.18.0" out of strings like "nginx/1.18.0 (Ubuntu)".
func extractVersionAfter(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	rest := s[i+len(prefix):]
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		if c == ' ' || c == '\t' || c == ',' || c == ';' || c == '(' {
			return rest[:j]
		}
	}
	return rest
}

// probeResponse is the minimal view of an HTTP response the fingerprint
// rules consume. Keeping this abstract lets us feed both base-URL
// responses and well-known-path responses through the same detector
// without coupling to net/http.Response lifecycle.
type probeResponse struct {
	URL     string
	Status  int
	Headers http.Header
	Body    string // already truncated by the probe loop
}

// Header returns the first value for the named header (case-insensitive).
func (p *probeResponse) Header(name string) string {
	if p == nil || p.Headers == nil {
		return ""
	}
	return p.Headers.Get(name)
}

// HeaderValues returns all values for the named header (case-insensitive),
// or nil if absent. Used for Set-Cookie which legitimately repeats.
func (p *probeResponse) HeaderValues(name string) []string {
	if p == nil || p.Headers == nil {
		return nil
	}
	return p.Headers.Values(name)
}
