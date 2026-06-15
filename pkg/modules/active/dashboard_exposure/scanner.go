// Package dashboard_exposure actively probes for exposed third-party dashboards,
// admin consoles and self-hosted apps (Grafana, Airflow, GitLab, Jenkins, Ollama,
// vLLM, ...) using the shared dashboardsig catalog. It confirms each product via
// its health/version/config endpoints and reports a tiered finding: a reachable
// console is attack-surface (Info/Low), while an unauthenticated version/config/
// data leak is escalated to High. When a confirmed product carries a default-login
// probe (see dashboardsig.LoginProbe), the module then submits that product's
// vendor-documented default credentials — only those, negative-control gated — and
// escalates a working pair to a Critical default-credentials finding.
//
// Cost is bounded like the other exposure modules: per-(host, base) dedup so each
// base is probed once per host, a soft-404 catch-all guard, and a probe budget.
// At normal intensity only each product's single best (Primary) endpoint is
// probed; --intensity deep (ScanContext.DeepScan) and passive tech hints unlock
// the full sweep including product-specific mount paths.
package dashboard_exposure

import (
	"strings"

	"github.com/pkg/errors"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/dashboardsig"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Probe budgets: a hard cap on HTTP requests per host so the catalog sweep stays
// bounded even on hosts with many context-path bases.
const (
	normalBudget = 80
	deepBudget   = 260
	maxBodyMatch = 256 * 1024
)

// Module is the active third-party dashboard exposure scanner.
type Module struct {
	modkit.BaseActiveModule
	hostDS  dedup.Lazy[dedup.DiskSet] // per (host, base) dedup
	loginDS dedup.Lazy[dedup.DiskSet] // per (host, product) default-login dedup
}

// New creates a new dashboard exposure module.
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
		hostDS:  dedup.LazyDiskSet("dashboard_exposure_base"),
		loginDS: dedup.LazyDiskSet("dashboard_exposure_login"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess requires a request with a valid URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

// IncludesBaseCanProcess returns false because we override CanProcess entirely.
func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	hostKey := urlx.Scheme + "|" + urlx.Host
	hostDS := m.hostDS.Get(scanCtx.DedupMgr())
	loginDS := m.loginDS.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(hostDS, hostKey, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	deep := scanCtx != nil && scanCtx.DeepScan
	budget := normalBudget
	if deep {
		budget = deepBudget
	}

	rawHTTP := getRaw(ctx)
	svc := ctx.Service()
	baseURL := urlx.Scheme + "://" + urlx.Host
	host := urlx.Host

	reported := map[string]bool{}
	var results []*output.ResultEvent

	for _, base := range bases {
		if budget <= 0 {
			break
		}
		baseline := m.fetch(httpClient, rawHTTP, svc, base+"/vigolium-dash-"+utils.RandomString(10), false)
		budget--

		// SPA-skip: detect a client-side-routed shell by the *catch-all* property,
		// not by mere framework use — a random, guaranteed-nonexistent path that
		// returns a 2xx SPA shell means the app routes every path to the same shell,
		// so blind probing reaches nothing. This deliberately keys on the baseline
		// (not the observed page): a server-rendered Next.js / Nuxt app carries
		// __NEXT_DATA__/_nuxt markers on every real page yet 404s unknown paths, so
		// it is correctly NOT treated as a blind SPA and its /api/* routes are still
		// probed. Only a true CSR SPA (or a `next export` catch-all) trips this.
		baselineSPA := baseline != nil && baseline.status >= 200 && baseline.status < 400 &&
			dashboardsig.LooksLikeSPAShell(baseline.body)
		// On a blind-SPA host we still probe products the shell itself fingerprints
		// (a dashboard-that-is-an-SPA, e.g. Grafana) or that passive already hinted.
		recognized := recognizedFromBaseline(baseline)

		for i := range dashboardsig.Catalog {
			if budget <= 0 {
				break
			}
			p := &dashboardsig.Catalog[i]
			if reported[p.ID] || len(p.Confirmers) == 0 {
				continue // already reported, or a passive-only product (no active endpoint)
			}
			hinted := scanCtx != nil && scanCtx.TechStack != nil && scanCtx.TechStack.Has(host, p.ID)
			recog := recognized[p.ID]
			if baselineSPA && !hinted && !recog {
				continue // blind-SPA host with no positive signal for this product
			}
			// Full sweep when deep, when the shell fingerprinted the product, or
			// when passive fingerprinting already hinted it on this host.
			full := deep || hinted || recog
			res := m.probeProduct(httpClient, rawHTTP, svc, baseURL, host, base, p, baseline, full, loginDS, &budget)
			if len(res) > 0 {
				results = append(results, res...)
				reported[p.ID] = true
				scanCtx.MarkTech(host, p.ID)
				scanCtx.MarkTech(host, "dashboard")
			}
		}
	}
	return results, nil
}

type hit struct {
	c       *dashboardsig.Confirmer
	version string
	url     string
	prefix  string // the confirmed base+mount, so a default-login probe targets the right context path
	sev     severity.Severity
}

// probeProduct probes a single product's confirmers under the given base (and, in
// full mode, its extra mount paths). It returns the strongest finding for the
// product (preferring an unauthenticated leak over a bare presence hit) and, when
// the confirmed product carries a default-login probe, appends a Critical
// default-credentials finding if a documented pair authenticates.
func (m *Module) probeProduct(
	client *http.Requester, rawHTTP []byte, svc *httpmsg.Service,
	baseURL, host, base string, p *dashboardsig.Product, baseline *probeResp,
	full bool, loginDS *dedup.DiskSet, budget *int,
) []*output.ResultEvent {
	prefixes := []string{base}
	if full {
		for _, mnt := range p.Mounts {
			prefixes = append(prefixes, base+mnt)
		}
	}

	var best *hit
probe:
	for _, prefix := range prefixes {
		for ci := range p.Confirmers {
			c := &p.Confirmers[ci]
			if !full && !c.Primary {
				continue
			}
			if *budget <= 0 {
				break probe
			}
			probePath := prefix + c.Path
			version, ok := m.confirmHit(client, rawHTTP, svc, probePath, c, baseline, budget)
			if !ok {
				continue
			}
			sev := c.Severity()
			if sev == severity.Undefined {
				sev = p.PresenceSeverity()
			}
			if best == nil || sev > best.sev {
				best = &hit{c: c, version: version, url: baseURL + probePath, prefix: prefix, sev: sev}
			}
			// A leak is the strongest possible signal for this product — stop here.
			if c.UnauthLeak {
				break probe
			}
		}
	}

	res := m.buildResult(p, best, host)
	if res == nil {
		return nil
	}
	out := []*output.ResultEvent{res}
	// When the confirmed product carries a default-login probe, attempt its
	// documented default credentials against the confirmed context path.
	if p.Login != nil {
		if lr := m.tryDefaultLogin(client, rawHTTP, svc, baseURL, best.prefix, host, p, loginDS, budget); lr != nil {
			out = append(out, lr)
		}
	}
	return out
}

// confirmHit fetches probePath, evaluates the confirmer, and runs the
// false-positive gauntlet before accepting a match:
//
//  1. Catch-all guard — the soft-404/random-path baseline must NOT already
//     satisfy the confirmer (else it can't discriminate on this host).
//  2. Baseline negative control — the probe response must be distinguishable
//     from the baseline (different status, or a non-similar body).
//  3. Multiple patterns — a single-pattern match (signals < 2) must reproduce on
//     a second fetch (and still differ from the baseline) before it is trusted.
//
// budget is decremented for every HTTP request issued.
func (m *Module) confirmHit(
	client *http.Requester, rawHTTP []byte, svc *httpmsg.Service,
	probePath string, c *dashboardsig.Confirmer, baseline *probeResp, budget *int,
) (string, bool) {
	if baseline != nil {
		if _, _, ok := c.Confirm(baseline.status, baseline.get, baseline.body, baseline.bodyLower); ok {
			return "", false // catch-all: baseline already "confirms" this product
		}
	}
	if *budget <= 0 {
		return "", false
	}
	*budget--
	pr := m.fetch(client, rawHTTP, svc, probePath, false)
	if pr == nil {
		return "", false
	}
	version, signals, ok := c.Confirm(pr.status, pr.get, pr.body, pr.bodyLower)
	if !ok || baselineLikeResponse(baseline, pr) {
		return "", false
	}
	if signals < 2 {
		// Single pattern: require a fresh (uncached) reproduction that still
		// confirms and still differs from the baseline.
		if *budget <= 0 {
			return "", false
		}
		*budget--
		pr2 := m.fetch(client, rawHTTP, svc, probePath, true)
		if pr2 == nil {
			return "", false
		}
		if _, _, ok2 := c.Confirm(pr2.status, pr2.get, pr2.body, pr2.bodyLower); !ok2 || baselineLikeResponse(baseline, pr2) {
			return "", false
		}
	}
	return version, true
}

// baselineLikeResponse reports whether pr is indistinguishable from the soft-404
// baseline (same status AND a similar body) — i.e. not a real, distinct endpoint.
func baselineLikeResponse(baseline, pr *probeResp) bool {
	if baseline == nil || pr == nil {
		return false
	}
	if pr.status != baseline.status {
		return false
	}
	return modkit.BodiesSimilar(pr.body, baseline.body)
}

// recognizedFromBaseline returns the product IDs the soft-404 baseline body
// itself fingerprints. On an SPA host this is how a dashboard-that-is-an-SPA
// (e.g. Grafana, whose shell carries grafanaBootData) stays probeable.
func recognizedFromBaseline(baseline *probeResp) map[string]bool {
	if baseline == nil || baseline.body == "" {
		return nil
	}
	out := map[string]bool{}
	for _, mt := range dashboardsig.MatchPassive(dashboardsig.NewObserved(baseline.header, nil, baseline.body)) {
		out[mt.Product.ID] = true
	}
	return out
}

func (m *Module) buildResult(p *dashboardsig.Product, h *hit, host string) *output.ResultEvent {
	if h == nil {
		return nil
	}
	tags := append([]string{"dashboard", "exposure"}, p.Tags...)
	var name, desc string
	var extracted []string

	if h.c.UnauthLeak {
		tags = append(tags, "info-leak")
		name = p.Name + " — Unauthenticated " + h.c.LeakName
		desc = "An unauthenticated " + p.Name + " endpoint (" + h.c.Path + ") disclosed " + h.c.LeakName +
			". This confirms the product is reachable without authentication and leaks internal detail an attacker can use for default-credential, CVE, or pivot attacks."
	} else {
		name = p.Name + " Console Exposed"
		desc = p.Name + " (" + p.Category + ") is reachable at " + h.c.Path +
			". An exposed off-the-shelf console is attack surface: confirm it requires authentication and is not internet-facing."
	}
	if h.version != "" {
		extracted = append(extracted, "version: "+h.version)
		desc += " Version: " + h.version + "."
	}
	extracted = append(extracted, "endpoint: "+h.url)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              h.url,
		Matched:          h.url,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    h.sev,
			Confidence:  severity.Firm,
			Tags:        tags,
			Reference:   p.References(),
		},
		Metadata: map[string]any{
			"product":  p.ID,
			"category": p.Category,
			"leak":     h.c.UnauthLeak,
		},
	}
}

// probeResp is a copied, decoupled view of a probe response. bodyLower is the
// lowercased body, computed once so confirmers matched against it don't each
// re-lowercase the (potentially large) body.
type probeResp struct {
	status    int
	body      string
	bodyLower string
	header    map[string]string // lowercased name → value
}

func (p *probeResp) get(name string) string {
	if p == nil {
		return ""
	}
	return p.header[strings.ToLower(name)]
}

// fetch issues a GET to probePath (derived from rawHTTP) and copies the result.
// Returns nil on transport error. When noCluster is set the requester's
// short-lived response cluster cache is bypassed so the call is a genuinely fresh
// network observation (used for the reproduction re-fetch).
func (m *Module) fetch(client *http.Requester, rawHTTP []byte, svc *httpmsg.Service, probePath string, noCluster bool) *probeResp {
	modifiedRaw, err := httpmsg.SetPath(rawHTTP, probePath)
	if err != nil {
		return nil
	}
	req, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	req = req.WithService(svc)

	resp, _, err := client.Execute(req, http.Options{NoClustering: noCluster})
	if err != nil {
		return nil
	}
	defer resp.Close()
	return newProbeResp(resp, false)
}

// newProbeResp copies an executed response into a probeResp: the body is read,
// truncated at maxBodyMatch, and lowercased once, and the header map is built with
// lowercase keys. When joinHeaders is set, multi-valued headers (Set-Cookie can
// repeat) are joined with "\n" so a "contains" matcher sees every value; otherwise
// only the first value is kept. Returns nil when the chain carries no response.
func newProbeResp(resp *httpUtils.ResponseChain, joinHeaders bool) *probeResp {
	if resp == nil || resp.Response() == nil {
		return nil
	}
	body := resp.Body().Bytes()
	if len(body) > maxBodyMatch {
		body = body[:maxBodyMatch]
	}
	bodyStr := string(append([]byte(nil), body...))
	pr := &probeResp{
		status:    resp.Response().StatusCode,
		body:      bodyStr,
		bodyLower: strings.ToLower(bodyStr),
		header:    map[string]string{},
	}
	for k, v := range resp.Response().Header {
		if len(v) == 0 {
			continue
		}
		if joinHeaders {
			pr.header[strings.ToLower(k)] = strings.Join(v, "\n")
		} else {
			pr.header[strings.ToLower(k)] = v[0]
		}
	}
	return pr
}

// getRaw returns the observed request as a GET (the dashboard probes are all GETs).
func getRaw(ctx *httpmsg.HttpRequestResponse) []byte {
	if ctx.Request().Method() != "GET" {
		if raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET"); err == nil {
			return raw
		}
	}
	return ctx.Request().Raw()
}
