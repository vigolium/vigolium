package aem

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Tag / TagAdobe are the tech-stack tags published for AEM hosts. Adding "aem"
// to modkit.techTagCategories makes every module tagged "aem" auto-gate on the
// fingerprint's MarkTech (see pkg/modules/tech_tags.go).
const (
	Tag      = "aem"
	TagAdobe = "adobe"
)

// techTags is the allow-set consulted on the ConfirmAEM fast path.
var techTags = []string{Tag, TagAdobe}

// strongBodyMarkers are single-hit AEM proofs: any one in a response body means
// the target is AEM. Each is specific to Sling/Granite/CQ and does not appear on
// unrelated stacks.
var strongBodyMarkers = []string{
	"Welcome to Adobe Experience Manager",
	"<title>AEM Sign In</title>",
	"/etc.clientlibs/", // AEM 6.3+ proxied clientlib root
	"cq:template",
	"/libs/granite/",
	"Granite.HTTP",
	"CQ.WCM",
}

// mediumBodyMarkers are weaker on their own (a proxied page could echo one), so
// AEM is only inferred when at least two co-occur — the classic /etc/designs +
// /content/dam pairing the corpus keys on.
var mediumBodyMarkers = []string{
	"/etc/designs/",
	"/content/dam/",
	"data-cq-",
	"cq:page",
	"clientlib",
}

// MatchResponse reports whether a response looks like AEM and which signals fired.
// headerGet reads a response header by name (works for both httpmsg.HttpResponse.Header
// and net/http.Header.Get). ok is true when any strong signal, or at least two
// medium body signals, are present.
func MatchResponse(status int, headerGet func(string) string, body string) (ok bool, signals []string) {
	if headerGet != nil {
		server := strings.ToLower(headerGet("Server"))
		for _, s := range []string{"communique", "day-servlet-engine", "cq5", "adobe experience manager"} {
			if strings.Contains(server, s) {
				signals = append(signals, "Server: "+headerGet("Server"))
				break
			}
		}
		cookie := strings.ToLower(headerGet("Set-Cookie"))
		if strings.Contains(cookie, "login-token=") || strings.Contains(cookie, "cq-authoring-mode") {
			signals = append(signals, "AEM auth cookie (login-token/cq-authoring-mode)")
		}
		// A 401 challenge from the Felix/OSGi console is a definitive AEM signal.
		if status == 401 && strings.Contains(headerGet("WWW-Authenticate"), "OSGi Management Console") {
			signals = append(signals, `WWW-Authenticate: OSGi Management Console`)
		}
	}

	strong := len(signals) > 0
	for _, m := range strongBodyMarkers {
		if strings.Contains(body, m) {
			strong = true
			signals = append(signals, "body marker: "+m)
		}
	}

	mediumHits := 0
	for _, m := range mediumBodyMarkers {
		if strings.Contains(body, m) {
			mediumHits++
			signals = append(signals, "body marker: "+m)
		}
	}

	return strong || mediumHits >= 2, signals
}

// serverVersionRe extracts the AEM-stack version from a Server header. Genuine AEM
// servlet engines announce Communique/<ver> or Day-Servlet-Engine/<ver> (and older
// CQ builds CQ5/<ver>); this is the version reliably readable from a passive
// response without an active probe.
var serverVersionRe = regexp.MustCompile(`(?i)(?:Communique|Day-Servlet-Engine|CQ5?)/v?(\d+(?:\.\d+){1,3})`)

// ExtractVersion returns the AEM-stack version advertised in the Server header, or
// "" when none is present. Conservative by design (Server header only) so it never
// misreports a guessed version from arbitrary body text.
func ExtractVersion(headerGet func(string) string) string {
	if headerGet == nil {
		return ""
	}
	if mm := serverVersionRe.FindStringSubmatch(headerGet("Server")); mm != nil {
		return mm[1]
	}
	return ""
}

// confirmProbe is a canonical AEM surface probed by ConfirmAEM's active gate.
type confirmProbe struct {
	path  string
	match func(ProbeResult) bool
}

var confirmProbes = []confirmProbe{
	{
		// The Granite login page renders "AEM Sign In" only on genuine AEM.
		path: "/libs/granite/core/content/login.html",
		match: func(r ProbeResult) bool {
			return r.Status == 200 && (strings.Contains(r.Body, "AEM Sign In") ||
				strings.Contains(r.Body, "Adobe Experience Manager") ||
				strings.Contains(r.Body, "QUICKSTART_HOMEPAGE"))
		},
	},
	{
		// The Felix/OSGi Web Console answers with a Basic-auth challenge naming the
		// OSGi Management Console realm — unique to Sling/Felix (AEM's runtime).
		path: "/system/console",
		match: func(r ProbeResult) bool {
			return r.Status == 401 && r.Header != nil &&
				strings.Contains(r.Header.Get("WWW-Authenticate"), "OSGi Management Console")
		},
	},
	{
		// Older AEM/CQ builds expose the CQ login page instead.
		path: "/libs/cq/core/content/login.html",
		match: func(r ProbeResult) bool {
			return r.Status == 200 && (strings.Contains(r.Body, "j_username") &&
				(strings.Contains(r.Body, "granite") || strings.Contains(r.Body, "CQ")))
		},
	},
}

// ConfirmAEM is the fail-closed presence gate every active AEM module calls
// before sending its real probes. It returns true only when the target is
// genuinely AEM, established in cheapest-first order:
//
//  1. the host was already fingerprinted as AEM (passive aem_fingerprint or an
//     earlier module's confirmation marked the tech registry);
//  2. the response the module was handed already carries AEM signals; or
//  3. an active probe against a canonical AEM surface (Granite login, the Felix
//     console challenge) confirms it.
//
// A positive verdict marks the tech registry so sibling modules on the same host
// hit the fast path. When nothing confirms AEM it returns false and the module
// skips the host entirely — satisfying "only run against real AEM".
func ConfirmAEM(ctx *httpmsg.HttpRequestResponse, client *http.Requester, sc *modkit.ScanContext) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	host := hostOf(ctx)

	if sc.HasAnyTech(host, techTags) {
		return true
	}

	if resp := ctx.Response(); resp != nil {
		if ok, _ := MatchResponse(resp.StatusCode(), resp.Header, resp.BodyToString()); ok {
			MarkAEM(sc, host)
			return true
		}
	}

	for _, p := range confirmProbes {
		res := Get(ctx, client, p.path, nil)
		if res.OK && p.match(res) {
			MarkAEM(sc, host)
			return true
		}
	}
	return false
}

// MarkAEM records AEM in the tech registry for host so tech-gated sibling modules
// and later re-fingerprints see it. No-op for a nil/registry-less ScanContext.
func MarkAEM(sc *modkit.ScanContext, host string) {
	if sc == nil || host == "" {
		return
	}
	sc.MarkTech(host, Tag)
	sc.MarkTech(host, TagAdobe)
}

// hostOf returns the request host, or "" if unparseable.
func hostOf(ctx *httpmsg.HttpRequestResponse) string {
	urlx, err := ctx.URL()
	if err != nil {
		return ""
	}
	return urlx.Host
}
