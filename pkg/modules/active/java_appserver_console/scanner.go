package java_appserver_console

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type probe struct {
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Generic UI/company words
	// ("Oracle", "Management Console", "Web Console", "Administration Console") never
	// form a group on their own — they match any login wall or landing page that
	// merely mentions them; only the product-name anchor confirms the console.
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	// WildFly / JBoss
	{
		path: "/console",
		name: "WildFly/JBoss Admin Console",
		// Drop the bare "Management Console" UI token; anchor on the product.
		markers:     [][]string{{"WildFly", "JBoss", "HAL Management Console"}},
		antiMarkers: []string{"404", "Not Found", "H2 Console", "h2-console", "WebLogic"},
		sev:         severity.High,
		desc:        "WildFly/JBoss administration console exposed, enabling server management and application deployment",
	},
	{
		path:        "/management",
		name:        "WildFly Management Endpoint",
		markers:     [][]string{{`"management-major-version"`, `"product-name"`, "WildFly", "JBoss"}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE", "actuator"},
		sev:         severity.High,
		desc:        "WildFly/JBoss HTTP management endpoint exposed, providing REST access to server management operations",
	},
	// WebLogic
	{
		path: "/console/login/LoginForm.jsp",
		name: "WebLogic Admin Console",
		// Drop "Oracle" (a company name on countless pages) and "Console Login"
		// (generic); anchor on WebLogic-unique strings.
		markers:     [][]string{{"WebLogic", "wl_login", "console_title"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "Oracle WebLogic Server admin console login page exposed, a high-value target with multiple known CVEs",
	},
	{
		path: "/console/",
		name: "WebLogic Console (root)",
		// Require the WebLogic product string — the bare word "Console" is a common
		// UI/title token and the path slug, and "Oracle" matches any page that
		// mentions the company, so neither confirms a console on its own.
		markers:     [][]string{{"WebLogic", "wl_login"}},
		antiMarkers: []string{"404", "Not Found", "WildFly", "JBoss", "H2"},
		sev:         severity.High,
		desc:        "Oracle WebLogic admin console accessible",
	},
	// GlassFish / Payara
	{
		path: "/common/index.jsf",
		name: "GlassFish Admin Console",
		// Drop the generic "Administration Console" UI token.
		markers:     [][]string{{"GlassFish", "Payara", "Sun Microsystems"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "GlassFish/Payara administration console exposed, enabling server management and application deployment",
	},
	{
		path:        "/admin-console/",
		name:        "GlassFish Admin Console (alt)",
		markers:     [][]string{{"GlassFish", "Payara"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "GlassFish/Payara admin console accessible at alternate path",
	},
	// JBoss legacy
	{
		path: "/jmx-console/",
		name: "JBoss JMX Console",
		// "MBean"/"Agent View" are the JMX-console-specific tokens; drop bare "JMX"
		// (appears on many Java monitoring pages).
		markers:     [][]string{{"JBoss", "MBean", "Agent View", "jboss.system"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Critical,
		desc:        "JBoss JMX Console exposed without authentication, enabling direct MBean access and potential remote code execution",
	},
	{
		path: "/web-console/",
		name: "JBoss Web Console",
		// Anchor on the product; "Web Console"/"Administration Console" are generic.
		markers:     [][]string{{"JBoss"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "JBoss legacy web console exposed",
	},
	{
		path:        "/invoker/JMXInvokerServlet",
		name:        "JBoss JMXInvoker",
		markers:     [][]string{{"\xac\xed"}},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "JBoss JMXInvokerServlet exposed, enabling Java deserialization attacks for remote code execution",
	},
}

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Java App Server Console active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Java App Server Console module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("java_appserver_console"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed Java app server admin consoles.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so an
	// admin console mounted under a context path (e.g. /myapp/admin-console) is
	// reached, not just the root. Claim each (host, base) pair up front so a
	// fully-deduped request issues no traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeEndpoint(ctx, httpClient, p, base+p.path, fp); result != nil {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-appserver-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	probePath string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// Catch-all / shell guard: a body textually equivalent to the originally
	// observed page means the app served its standard shell for this path too —
	// "the same body with or without the probe".
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Strip the reflected probe path before matching so a marker that echoes the
	// requested path (a console path reflected into an href/breadcrumb) can't
	// satisfy the check on its own.
	matchBody := modkit.StripReflectedProbePath(body, probePath)

	// Require every marker group (product anchor + any corroboration), not a single
	// generic UI/company word, then drop the finding if a nonexistent sibling under
	// the same parent satisfies the same groups (a sub-directory catch-all that 200s
	// every child path). Root-level probes are covered by the random-path 404
	// fingerprint above.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, matchBody, p.markers)
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("App Server Console: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"java", "appserver", "admin", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
