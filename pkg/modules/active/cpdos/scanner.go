package cpdos

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	// busterParam is the query parameter used as a unique, single-use cache buster
	// so every probe lands on its own cache key and never poisons a shared resource.
	busterParam = "vigolium_cb"
	// benignMethod is an invalid, non-mutating method token sent via method-override
	// headers — it can only ever yield a cacheable 4xx, never delete or modify data.
	benignMethod = "VIGOLIUMX"
	// confirmRounds is how many independent rounds (each with fresh control and
	// poison busters) must reproduce the with-payload/without-payload differential
	// before a finding is emitted. Higher is stricter; cache probing is gated to
	// endpoints already proven cacheable, so the extra rounds are cheap insurance
	// against false positives.
	confirmRounds = 3
)

// hmoHeaders are the method-override headers backends commonly honor.
var hmoHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// hhoSizes are the oversized-header byte lengths tried, smallest first. Many
// origins cap request headers near 8 KB while CDNs forward up to ~16-20 KB.
var hhoSizes = []int{8192, 16384, 32768}

// Module implements the Cache-Poisoned Denial of Service active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CPDoS module.
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
		ds: dedup.LazyDiskSet("cache_poisoned_dos"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess restricts CPDoS to GET requests — cache-poisoned errors only matter
// for cacheable GET resources — layered on the base media/method eligibility checks.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return m.BaseActiveModule.CanProcess(ctx) && ctx.Request().Method() == "GET"
}

// probeResult captures the response signals a single probe needs.
type probeResult struct {
	status int
	cache  infra.CacheInfo
	rawReq string
	resp   string
	ok     bool // a usable response was received
}

// confirmation describes a reproduced cached-error finding.
type confirmation struct {
	status   int
	evidence string
	req      string
	resp     string
}

// ScanPerRequest tests the endpoint for CPDoS via cacheable origin errors (HMO/HHO).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Cheap pre-filter: if the captured response shows no cache/proxy layer at all
	// there is nothing in front to poison — skip without sending any traffic. When
	// no response was captured, fall through to the active pre-flight below.
	if orig := ctx.Response(); orig != nil {
		if !infra.CacheState(orig.Header).Layer {
			return nil, nil
		}
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	basePath, err := httpmsg.GetPath(ctx.Request().Raw())
	if err != nil || basePath == "" {
		return nil, nil
	}

	// Pre-flight: prove the endpoint caches a baseline 200 keyed by our buster.
	// Without this, every error response would be a false positive.
	cacheable, ferr := m.cacheable(httpClient, ctx, basePath)
	if ferr != nil || !cacheable {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, scan := range []func(*http.Requester, *httpmsg.HttpRequestResponse, string) (*output.ResultEvent, error){
		m.scanHMO,
		m.scanHHO,
	} {
		res, serr := scan(httpClient, ctx, basePath)
		if serr != nil {
			if errors.Is(serr, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// cacheable proves the endpoint caches a successful baseline response keyed by
// our buster: a clean request must return <400, and an identical clean request
// on the same buster must come back from cache (HIT).
func (m *Module) cacheable(httpClient *http.Requester, ctx *httpmsg.HttpRequestResponse, basePath string) (bool, error) {
	target := busted(basePath, freshBuster())
	first, err := m.send(httpClient, ctx, target, nil, false)
	if err != nil {
		return false, err
	}
	if !first.ok || first.status >= 400 {
		return false, nil
	}
	second, err := m.send(httpClient, ctx, target, nil, false)
	if err != nil {
		return false, err
	}
	return second.ok && second.cache.Hit, nil
}

// scanHMO tests the HTTP Method Override variant.
func (m *Module) scanHMO(httpClient *http.Requester, ctx *httpmsg.HttpRequestResponse, basePath string) (*output.ResultEvent, error) {
	ok, c, err := m.confirmCachedError(httpClient, ctx, basePath, hmoApply, hmoIsError)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return m.finding(ctx, "HMO", "method-override header ("+benignMethod+")", c), nil
}

// scanHHO tests the HTTP Header Oversize variant, locking onto the smallest
// header size that trips a cacheable 400 before running the multi-round confirm.
func (m *Module) scanHHO(httpClient *http.Requester, ctx *httpmsg.HttpRequestResponse, basePath string) (*output.ResultEvent, error) {
	for _, size := range hhoSizes {
		apply := hhoApply(size) // build the padding once, reuse for probe + confirm rounds
		probe, err := m.send(httpClient, ctx, busted(basePath, freshBuster()), apply, false)
		if err != nil {
			return nil, err
		}
		if !probe.ok || !hhoIsError(probe.status) {
			continue
		}
		ok, c, err := m.confirmCachedError(httpClient, ctx, basePath, apply, hhoIsError)
		if err != nil {
			return nil, err
		}
		if ok {
			return m.finding(ctx, "HHO", fmt.Sprintf("oversized request header (%d bytes)", size), c), nil
		}
	}
	return nil, nil
}

// confirmCachedError runs confirmRounds independent rounds, each performing a
// with-payload / without-payload differential on fresh cache keys. A round passes
// only when all three steps hold; every round must pass.
//
//  1. Control (WITHOUT payload): a fresh, clean buster must return the normal
//     non-error baseline (<400). If the endpoint errors on a clean fresh key, the
//     error is not attributable to our payload — bail to avoid a false positive.
//  2. Poison (WITH payload): a *separate* fresh buster carrying the malicious
//     element must itself produce a cacheable error, and that error status must
//     differ from the clean control. (Same-key with/without comparison is
//     impossible — the cache stores the first response — so the differential is
//     drawn across two equivalent fresh keys whose only difference is the payload.)
//  3. Replay (cache confirm): a clean request on the SAME poisoned buster must be
//     served the cached error (same status, cache HIT) — proving the error was
//     stored by the shared cache, not produced per-request (which also rules out a
//     per-request WAF/edge block masquerading as a cached error).
func (m *Module) confirmCachedError(
	httpClient *http.Requester,
	ctx *httpmsg.HttpRequestResponse,
	basePath string,
	apply func([]byte) ([]byte, error),
	isError func(int) bool,
) (bool, confirmation, error) {
	var c confirmation
	for round := 0; round < confirmRounds; round++ {
		// 1. Control — without payload.
		control, err := m.send(httpClient, ctx, busted(basePath, freshBuster()), nil, false)
		if err != nil {
			return false, c, err
		}
		if !control.ok || control.status >= 400 {
			return false, c, nil
		}

		// 2. Poison — with payload, on a separate fresh key.
		target := busted(basePath, freshBuster())
		poison, err := m.send(httpClient, ctx, target, apply, false)
		if err != nil {
			return false, c, err
		}
		if !poison.ok || !isError(poison.status) || poison.status == control.status {
			return false, c, nil
		}

		// 3. Replay — clean request on the poisoned key must serve the cached error.
		// Only this request's body becomes finding evidence, so only it captures it.
		clean, err := m.send(httpClient, ctx, target, nil, true)
		if err != nil {
			return false, c, err
		}
		if !clean.ok || clean.status != poison.status || !clean.cache.Hit {
			return false, c, nil
		}

		c.status = clean.status
		c.req = clean.rawReq
		c.resp = clean.resp
		c.evidence = clean.cache.Evidence
		if c.evidence == "" {
			c.evidence = "cache HIT"
		}
	}
	return true, c, nil
}

// send issues one request to basePath-derived target with an optional mutation
// and returns the observed status + cache signals. Transport errors are returned
// so the caller can abort on an unresponsive host. The (potentially large)
// response body is serialized into the result only when captureResp is set —
// control/poison probes discard it, so only the confirming replay pays that cost.
func (m *Module) send(
	httpClient *http.Requester,
	ctx *httpmsg.HttpRequestResponse,
	target string,
	apply func([]byte) ([]byte, error),
	captureResp bool,
) (probeResult, error) {
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), target)
	if err != nil {
		return probeResult{}, nil
	}
	if apply != nil {
		raw, err = apply(raw)
		if err != nil {
			return probeResult{}, nil
		}
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return probeResult{}, nil
	}
	req = req.WithService(ctx.Service())

	// NoClustering: the requester normally de-duplicates identical requests and
	// replays a cached response — that would hide the cache HIT this module must
	// observe on the second (identical-buster) request, so each probe must really
	// hit the wire.
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return probeResult{rawReq: string(raw)}, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return probeResult{rawReq: string(raw)}, nil
	}

	pr := probeResult{
		status: resp.Response().StatusCode,
		cache:  infra.CacheState(resp.Response().Header.Get),
		rawReq: string(raw),
		ok:     true,
	}
	if captureResp {
		pr.resp = resp.FullResponseString()
	}
	return pr, nil
}

func (m *Module) finding(ctx *httpmsg.HttpRequestResponse, variant, trigger string, c confirmation) *output.ResultEvent {
	var u string
	if urlx, err := ctx.URL(); err == nil && urlx != nil {
		u = urlx.String()
	}
	return &output.ResultEvent{
		URL:      u,
		Matched:  u,
		Request:  c.req,
		Response: c.resp,
		ExtractedResults: []string{
			"variant=" + variant,
			"trigger=" + trigger,
			fmt.Sprintf("cached-error-status=%d", c.status),
			"cache-evidence=" + c.evidence,
		},
		Info: output.Info{
			Name: fmt.Sprintf("Cache-Poisoned DoS (%s)", variant),
			Description: fmt.Sprintf(
				"The endpoint %s is vulnerable to Cache-Poisoned Denial of Service (%s). A request carrying a %s makes the origin return HTTP %d, which the shared cache stores and replays to subsequent clean requests on the same cache key (%s). An attacker can poison the real cache key for this resource to deny service to other users.",
				u, variant, trigger, c.status, c.evidence,
			),
		},
	}
}

// busted appends the unique cache buster to a request target.
func busted(basePath, buster string) string {
	sep := "?"
	if strings.Contains(basePath, "?") {
		sep = "&"
	}
	return basePath + sep + busterParam + "=" + buster
}

func freshBuster() string { return "vgcb" + utils.RandomString(14) }

// hmoApply adds the benign method-override headers to a request.
func hmoApply(raw []byte) ([]byte, error) {
	var err error
	for _, h := range hmoHeaders {
		raw, err = httpmsg.AddOrReplaceHeader(raw, h, benignMethod)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// hmoIsError reports the cacheable error statuses a method override may produce.
func hmoIsError(status int) bool {
	switch status {
	case 400, 404, 405, 501:
		return true
	default:
		return false
	}
}

// hhoApply returns a mutation adding an oversized padding header of the given size.
func hhoApply(size int) func([]byte) ([]byte, error) {
	pad := strings.Repeat("A", size)
	return func(raw []byte) ([]byte, error) {
		return httpmsg.AddOrReplaceHeader(raw, "X-Vigolium-Pad", pad)
	}
}

// hhoIsError matches only 400 — a 431 (Request Header Fields Too Large) is the
// RFC-correct response and is never cached, so it must not be treated as a hit.
func hhoIsError(status int) bool { return status == 400 }
