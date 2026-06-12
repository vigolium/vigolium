package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/tag"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/spitolas/loginsig"
)

// respiderInput is the decoded view of a discovered record the evaluator needs.
// Built from a record's URL, parsed raw response, and stored content-type.
type respiderInput struct {
	URL         string
	StatusCode  int
	ContentType string
	Location    string // Location header value when StatusCode is 3xx
	Body        []byte
}

// respiderVerdict is the evaluator's decision for one candidate. Reason is a
// short tag used in the phase's skip summary.
type respiderVerdict struct {
	Keep      bool
	Reason    string // spa | spa-shell | interactive | static | login | asset | not-html | bad-path | non-200
	ShellHash string // per-(host,shell) dedup key; set only when Keep
	Score     int    // ranking score among kept candidates
}

var (
	modernAppMatcher = tag.NewModernAppMatcher()

	// scriptSrcRe captures each <script src=…> value; its match count also
	// serves the "how many external scripts" check (one regex, two uses).
	scriptSrcRe   = regexp.MustCompile(`(?i)<script[^>]+\bsrc\s*=\s*["']?([^"'\s>]+)`)
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	styleBlockRe  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	htmlTagRe     = regexp.MustCompile(`(?s)<[^>]+>`)
	volatileTokRe = regexp.MustCompile(`[0-9a-f]{6,}|[0-9]{2,}`) // hash/chunk/digit runs
	interactiveRe = regexp.MustCompile(`(?i)<(button|select|textarea)\b`)
	inputTagRe    = regexp.MustCompile(`(?i)<input\b`)
	formTagRe     = regexp.MustCompile(`(?i)<form\b`)
)

// appMountMarkers are byte patterns for a client-side render mount point.
var appMountMarkers = [][]byte{
	[]byte(`id="root"`), []byte(`id='root'`), []byte(`id=root`),
	[]byte(`id="app"`), []byte(`id='app'`), []byte(`id=app`),
	[]byte(`id="__next"`), []byte(`id="application"`),
	[]byte(`<app-root`), []byte(`ng-app`), []byte(`data-reactroot`),
	[]byte(`window.__nuxt__`), []byte(`__sveltekit`),
}

// pathKeywords boost the ranking of routes that conventionally host an
// interesting authenticated UI.
var pathKeywords = []string{
	"admin", "console", "dashboard", "portal", "account", "settings", "manage", "ui", "app",
}

// evaluateReSpiderCandidate decides whether a discovered route is worth a real
// browser: a JS/SPA shell or an interactive HTML page that is NOT a login/SSO
// wall. Pure function (no I/O) so it is unit-tested directly.
func evaluateReSpiderCandidate(in respiderInput) respiderVerdict {
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" {
		return respiderVerdict{Reason: "bad-path"}
	}

	// Directory-style / extensionless path only (targets /ui/, /console/;
	// excludes /app.js). Login paths still pass this and are caught below.
	// Reuses the same predicate ModernAppMatcher applies, for one definition.
	if !tag.IsValidModernAppPath(u.Path) {
		return respiderVerdict{Reason: "bad-path"}
	}

	// SSO / login screen — cheap, no browser. The URL itself, a redirect to an
	// IdP, or a password field in the body all disqualify.
	if loginsig.LooksLikeLoginURL(u) {
		return respiderVerdict{Reason: "login"}
	}
	if in.StatusCode >= 300 && in.StatusCode < 400 {
		if loc := strings.TrimSpace(in.Location); loc != "" {
			if lu, lerr := u.Parse(loc); lerr == nil && loginsig.LooksLikeLoginURL(lu) {
				return respiderVerdict{Reason: "login"}
			}
		}
		// A non-login redirect is not a renderable page worth a browser here;
		// its real target gets discovered/recorded on its own.
		return respiderVerdict{Reason: "non-200"}
	}
	if in.StatusCode != 200 {
		return respiderVerdict{Reason: "non-200"}
	}
	if loginsig.BodyLooksLikeLogin(in.Body) {
		return respiderVerdict{Reason: "login"}
	}

	// Content-type must be HTML; static assets / non-HTML add nothing a browser
	// would reveal.
	if modkit.IsStaticAssetContentType(in.ContentType) {
		return respiderVerdict{Reason: "asset"}
	}
	if !isHTMLContentType(in.ContentType) || len(in.Body) == 0 {
		return respiderVerdict{Reason: "not-html"}
	}

	// Rich-content gate: SPA framework markers, an empty app shell, or an
	// interactive server-rendered page (login already excluded above).
	var reason string
	switch {
	case modernAppMatcher.Match(&tag.MatchInput{ResponseBody: in.Body, MIMEType: in.ContentType, RequestPath: u.Path}):
		reason = "spa"
	case isEmptyAppShell(in.Body):
		reason = "spa-shell"
	case isInteractiveHTML(in.Body):
		reason = "interactive"
	default:
		return respiderVerdict{Reason: "static"}
	}

	return respiderVerdict{
		Keep:      true,
		Reason:    reason,
		ShellHash: shellFingerprint(u, in.Body),
		Score:     scoreCandidate(u, reason),
	}
}

func isHTMLContentType(ct string) bool {
	if ct == "" {
		return true // unknown — let the body gates decide
	}
	c := strings.ToLower(ct)
	return strings.Contains(c, "text/html") || strings.Contains(c, "application/xhtml")
}

func hasAppMount(lowerBody []byte) bool {
	for _, m := range appMountMarkers {
		if bytes.Contains(lowerBody, m) {
			return true
		}
	}
	return false
}

// isEmptyAppShell recognizes a client-rendered page: an app mount point plus
// several external scripts plus almost no static text.
func isEmptyAppShell(body []byte) bool {
	if !hasAppMount(bytes.ToLower(body)) {
		return false
	}
	if len(scriptSrcRe.FindAllIndex(body, -1)) < 2 {
		return false
	}
	return visibleTextLen(body) < 200
}

// visibleTextLen returns the length of human-visible text after stripping
// script/style blocks and tags.
func visibleTextLen(body []byte) int {
	b := scriptBlockRe.ReplaceAll(body, []byte(" "))
	b = styleBlockRe.ReplaceAll(b, []byte(" "))
	b = htmlTagRe.ReplaceAll(b, []byte(" "))
	return len(bytes.Join(bytes.Fields(b), []byte(" ")))
}

// isInteractiveHTML reports whether a server-rendered page has a real form or
// several interactive controls (login forms are screened out before this).
func isInteractiveHTML(body []byte) bool {
	if formTagRe.Match(body) {
		return true
	}
	controls := len(interactiveRe.FindAllIndex(body, -1)) + len(inputTagRe.FindAllIndex(body, -1))
	return controls >= 3
}

// shellFingerprint builds a per-(host, app-shell) dedup key. SPA routes that
// serve the same index shell share the same set of bundle <script src> paths
// (with volatile hash/chunk tokens normalized), so they collapse to one key and
// a single browser covers the whole client-side router.
func shellFingerprint(u *url.URL, body []byte) string {
	host := strings.ToLower(u.Hostname())
	matches := scriptSrcRe.FindAllSubmatch(body, -1)
	norm := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := strings.ToLower(string(m[1]))
		v = string(volatileTokRe.ReplaceAll([]byte(v), []byte("*")))
		norm = append(norm, v)
	}
	sort.Strings(norm)
	skeleton := strings.Join(norm, "|")
	if skeleton == "" {
		// Shell-less page: fall back to a normalized body prefix so identical
		// pages still dedup.
		nb := volatileTokRe.ReplaceAll(bytes.ToLower(body), []byte("*"))
		if len(nb) > 4096 {
			nb = nb[:4096]
		}
		skeleton = string(nb)
	}
	sum := sha256.Sum256([]byte(host + "::" + skeleton))
	return hex.EncodeToString(sum[:])
}

// scoreCandidate ranks kept candidates so the most promising win a tight budget.
func scoreCandidate(u *url.URL, reason string) int {
	score := 0
	p := strings.ToLower(u.Path)
	for _, kw := range pathKeywords {
		if strings.Contains(p, kw) {
			score += 10
		}
	}
	switch reason {
	case "spa":
		score += 5
	case "spa-shell":
		score += 4
	case "interactive":
		score += 2
	}
	segs := 0
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s != "" {
			segs++
		}
	}
	if segs > 5 {
		segs = 5
	}
	return score + segs
}
