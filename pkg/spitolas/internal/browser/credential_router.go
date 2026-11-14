package browser

import (
	"net/http"
	"strings"

	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// credentialRouter is the per-page Fetch-interception policy installed by
// InstallCredentialRouter.
type credentialRouter struct {
	headers       map[string]string
	allow         func(url string) bool
	methodAllowed func(method string) bool
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
// admits (SAFE-3). Network.setExtraHTTPHeaders put them on EVERY request the
// page made — third-party scripts, analytics, CDNs — until the crawl itself
// navigated off-scope.
//
//   - allowed URL: FetchContinueRequest with the request's own headers plus
//     headers (operator values win);
//   - any other URL: continued unchanged;
//   - a method methodAllowed refuses (the scan's traffic policy):
//     FetchFailRequest(BlockedByClient), so a read-only crawl's XHR/fetch
//     writes never leave the browser.
//
// patterns narrows which requests are paused at all ("*" when empty or when a
// method policy is set, since every request must then be judged). Responses
// are never fulfilled by the router (no rod LoadResponse): requests continue
// to the network untouched apart from headers.
//
// Calling it again replaces the policy (headers, allow, method filter) on the
// already-running interceptor, so a re-login can re-apply fresh credentials.
// A nil headers map with a nil methodAllowed disables injection.
func (p *Page) InstallCredentialRouter(headers map[string]string, allow func(url string) bool, methodAllowed func(method string) bool, patterns []string) error {
	cp := make(map[string]string, len(headers))
	for k, v := range headers {
		cp[k] = v
	}
	p.credRouter.Store(&credentialRouter{headers: cp, allow: allow, methodAllowed: methodAllowed})

	if methodAllowed != nil || len(patterns) == 0 {
		patterns = []string{"*"}
	}
	reqPatterns := make([]*proto.FetchRequestPattern, 0, len(patterns))
	for _, pat := range patterns {
		reqPatterns = append(reqPatterns, &proto.FetchRequestPattern{URLPattern: pat, RequestStage: proto.FetchRequestStageRequest})
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
	if r != nil && r.methodAllowed != nil && e.Request != nil && !r.methodAllowed(e.Request.Method) {
		if err := (proto.FetchFailRequest{RequestID: e.RequestID, ErrorReason: proto.NetworkErrorReasonBlockedByClient}).Call(page); err != nil {
			zap.L().Debug("credential router: fail request", zap.Error(err))
		}
		return
	}
	cont := proto.FetchContinueRequest{RequestID: e.RequestID}
	if r != nil && len(r.headers) > 0 && e.Request != nil && r.allow != nil && r.allow(e.Request.URL) {
		cont.Headers = mergeFetchHeaders(e.Request.Headers, r.headers)
	}
	if err := cont.Call(page); err != nil {
		zap.L().Debug("credential router: continue request", zap.Error(err))
	}
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
