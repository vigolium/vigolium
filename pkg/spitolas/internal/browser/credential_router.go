package browser

import (
	"net/http"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// credentialRouter is the per-page Fetch-interception policy installed by
// InstallCredentialRouter and SetResourceBlocking. One policy per page: CDP
// Fetch.enable replaces the pattern list, so the credential router and the
// resource blocker share a single interceptor.
type credentialRouter struct {
	headers       map[string]string
	allow         func(url string) bool
	methodAllowed func(method string) bool
	credPatterns  []string
	// firstParty, when set, turns resource blocking on: fonts and
	// media are failed, and images whose URL it rejects (third-party).
	firstParty func(url string) bool
	// interceptor, when set, decides every request it pauses before the
	// policies above (InstallInterceptor).
	interceptor *Interceptor
}

// CredentialHostPatterns are the Fetch URL patterns covering host and its
// subdomains, for a crawl whose credential scope is the default host scope.
func CredentialHostPatterns(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	return []string{"*://" + host + "/*", "*://" + host + ":*", "*://*." + host + "/*", "*://*." + host + ":*"}
}

// InstallCredentialRouter injects the operator's credential headers per
// request through CDP Fetch interception, only on requests whose URL allow
// admits. Network.setExtraHTTPHeaders would put them on EVERY request the
// page makes — third-party scripts, analytics, CDNs.
//
//   - allowed URL: FetchContinueRequest with the request's own headers plus
//     headers (operator values win);
//   - any other URL: continued unchanged;
//   - a method methodAllowed refuses (the scan's traffic policy):
//     FetchFailRequest(BlockedByClient), so a read-only crawl's XHR/fetch
//     writes never leave the browser.
//
// patterns narrows which requests are paused for the headers ("*" when
// empty); a method policy also pauses every request type that can carry a
// write method (methodPolicyResourceTypes). The credential policy never
// fulfils a response (no rod LoadResponse): requests continue to the network
// untouched apart from headers. Only an Interceptor (InstallInterceptor)
// answers a request itself.
//
// Calling it again replaces the credential policy (headers, allow, method
// filter) on the already-running interceptor, so a re-login can re-apply
// fresh credentials.
func (p *Page) InstallCredentialRouter(headers map[string]string, allow func(url string) bool, methodAllowed func(method string) bool, patterns []string) error {
	cp := make(map[string]string, len(headers))
	for k, v := range headers {
		cp[k] = v
	}
	p.routerMu.Lock()
	cur := p.currentRouter()
	cur.headers, cur.allow, cur.methodAllowed, cur.credPatterns = cp, allow, methodAllowed, patterns
	p.credRouter.Store(cur)
	p.routerMu.Unlock()
	return p.enableInterception(cur)
}

// SetResourceBlocking fails font and media requests and third-party images:
// they cost bandwidth and time and carry no crawlable surface.
// firstParty reports whether an image URL belongs to the target; first-party
// images are never blocked (they can be the surface: an avatar upload, a
// generated chart). nil turns blocking off.
func (p *Page) SetResourceBlocking(firstParty func(url string) bool) error {
	p.routerMu.Lock()
	cur := p.currentRouter()
	cur.firstParty = firstParty
	p.credRouter.Store(cur)
	p.routerMu.Unlock()
	return p.enableInterception(cur)
}

// currentRouter is a copy of the page's router policy (caller holds routerMu).
func (p *Page) currentRouter() *credentialRouter {
	if r := p.credRouter.Load(); r != nil {
		cp := *r
		return &cp
	}
	return &credentialRouter{}
}

// methodPolicyResourceTypes are the request types a page can send with a
// method other than GET: navigations and form posts, XHR/fetch, beacons, CSP
// reports, and the unclassified rest. Preflight is not one of them: a CORS
// preflight is always OPTIONS, and Chrome refuses the type in a Fetch.enable
// filter ("Unknown resource type in fetch filter"), which fails the whole
// call and leaves the page with no interceptor at all.
var methodPolicyResourceTypes = []proto.NetworkResourceType{
	proto.NetworkResourceTypeDocument,
	proto.NetworkResourceTypeXHR,
	proto.NetworkResourceTypeFetch,
	proto.NetworkResourceTypePing,
	proto.NetworkResourceTypeCSPViolationReport,
	proto.NetworkResourceTypeOther,
}

// WriteCapableResourceTypes returns a copy of the request types that can
// carry a method other than GET (methodPolicyResourceTypes), for an
// Interceptor that must see every write a page sends.
func WriteCapableResourceTypes() []proto.NetworkResourceType {
	return append([]proto.NetworkResourceType(nil), methodPolicyResourceTypes...)
}

// enableInterception (re)issues Fetch.enable with the union of the patterns
// r needs and starts the event loop once.
func (p *Page) enableInterception(r *credentialRouter) error {
	var reqPatterns []*proto.FetchRequestPattern
	add := func(url string, rt proto.NetworkResourceType) {
		reqPatterns = append(reqPatterns, &proto.FetchRequestPattern{URLPattern: url, ResourceType: rt, RequestStage: proto.FetchRequestStageRequest})
	}
	// Credential headers pause the requests they may go on: every request
	// without credential patterns, else those patterns' URLs.
	pausesAll := len(r.headers) > 0 && len(r.credPatterns) == 0
	switch {
	case pausesAll:
		add("*", "")
	case len(r.headers) > 0:
		for _, pat := range r.credPatterns {
			add(pat, "")
		}
	}
	// A method policy only needs the request types that can carry a method
	// other than GET; pausing every subresource would put a CDP round trip on
	// each image, script and stylesheet for nothing.
	if r.methodAllowed != nil && !pausesAll {
		for _, rt := range methodPolicyResourceTypes {
			add("*", rt)
		}
	}
	if r.firstParty != nil && !pausesAll {
		add("*", proto.NetworkResourceTypeFont)
		add("*", proto.NetworkResourceTypeMedia)
		add("*", proto.NetworkResourceTypeImage)
	}
	if ic := r.interceptor; ic != nil && !pausesAll {
		for _, pat := range ic.Patterns {
			add(pat, "")
		}
		for _, rt := range ic.Types {
			add("*", rt)
		}
	}
	if len(reqPatterns) == 0 {
		return (proto.FetchDisable{}).Call(p.boundedPage(0))
	}
	if err := (proto.FetchEnable{Patterns: reqPatterns}).Call(p.boundedPage(0)); err != nil {
		return err
	}
	p.credRouterOnce.Do(func() {
		go p.rodPage.EachEvent(func(e *proto.FetchRequestPaused) bool {
			// One goroutine per paused request: a slow CDP round trip for one
			// must not hold every other request of the page.
			go p.routePaused(e)
			return false
		})()
	})
	return nil
}

// routePaused answers one paused request under the current router policy.
func (p *Page) routePaused(e *proto.FetchRequestPaused) {
	r := p.credRouter.Load()
	page := p.boundedPage(0)
	fail := func() {
		if err := (proto.FetchFailRequest{RequestID: e.RequestID, ErrorReason: proto.NetworkErrorReasonBlockedByClient}).Call(page); err != nil {
			zap.L().Debug("browser interceptor: fail request", zap.Error(err))
		}
	}
	if r != nil && r.interceptor != nil && e.Request != nil {
		if p.answerIntercepted(r.interceptor, e, page) {
			return
		}
	}
	if r != nil && e.Request != nil {
		if r.methodAllowed != nil && !r.methodAllowed(e.Request.Method) {
			fail()
			return
		}
		if r.firstParty != nil && blockedResource(e.ResourceType, e.Request.URL, r.firstParty) {
			fail()
			return
		}
	}
	cont := proto.FetchContinueRequest{RequestID: e.RequestID}
	if r != nil && len(r.headers) > 0 && e.Request != nil && r.allow != nil && r.allow(e.Request.URL) {
		cont.Headers = mergeFetchHeaders(e.Request.Headers, r.headers)
	}
	if err := cont.Call(page); err != nil {
		zap.L().Debug("browser interceptor: continue request", zap.Error(err))
	}
}

// blockedResource reports whether a paused request is a resource the crawl
// skips: every font and media request, and third-party images.
func blockedResource(rt proto.NetworkResourceType, url string, firstParty func(string) bool) bool {
	switch rt {
	case proto.NetworkResourceTypeFont, proto.NetworkResourceTypeMedia:
		return true
	case proto.NetworkResourceTypeImage:
		return !firstParty(url)
	}
	return false
}

// mergeFetchHeaders is the request's headers with extra applied over them
// (case-insensitive; extra wins).
func mergeFetchHeaders(orig proto.NetworkHeaders, extra map[string]string) []*proto.FetchHeaderEntry {
	out := make([]*proto.FetchHeaderEntry, 0, len(orig)+len(extra))
	overridden := make(map[string]bool, len(extra))
	for k := range extra {
		overridden[http.CanonicalHeaderKey(k)] = true
	}
	for k, v := range orig {
		if overridden[http.CanonicalHeaderKey(k)] {
			continue
		}
		out = append(out, &proto.FetchHeaderEntry{Name: k, Value: v.Str()})
	}
	for k, v := range extra {
		out = append(out, &proto.FetchHeaderEntry{Name: k, Value: v})
	}
	return out
}
