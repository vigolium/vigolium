package browser

import (
	"github.com/go-rod/rod/lib/proto"
	"go.uber.org/zap"
)

// InterceptVerdict is what an Interceptor does with one paused request.
type InterceptVerdict int

const (
	// InterceptContinue hands the request to the page's other policies
	// (credential headers, method filter, resource blocking) and then the
	// network.
	InterceptContinue InterceptVerdict = iota
	// InterceptFulfill answers the request from InterceptDecision without
	// sending it: nothing reaches the network.
	InterceptFulfill
	// InterceptFail fails the request with BlockedByClient: nothing reaches
	// the network.
	InterceptFail
)

// InterceptDecision is an Interceptor's answer for one request. Status,
// ContentType and Body are read only for InterceptFulfill.
type InterceptDecision struct {
	Verdict     InterceptVerdict
	Status      int
	ContentType string
	Body        []byte
}

// Interceptor answers paused requests ahead of the page's credential, method
// and resource policies. It shares the page's single Fetch.enable pattern list
// with them (one interceptor per page, see credentialRouter).
type Interceptor struct {
	// Patterns are Fetch URL patterns paused for every resource type.
	Patterns []string
	// Types are resource types paused for every URL.
	Types []proto.NetworkResourceType
	// Decide is called once per paused request, on its own goroutine, before
	// the request is answered. Whatever it records about the request happens
	// before any network event the answer causes (loadingFinished,
	// loadingFailed).
	Decide func(e *proto.FetchRequestPaused) InterceptDecision
}

// InstallInterceptor installs ic on the page's Fetch interceptor (nil removes
// it). Requests ic pauses are decided by ic first; a Continue verdict falls
// through to the credential router and resource blocking unchanged.
func (p *Page) InstallInterceptor(ic *Interceptor) error {
	p.routerMu.Lock()
	cur := p.currentRouter()
	cur.interceptor = ic
	p.credRouter.Store(cur)
	p.routerMu.Unlock()
	return p.enableInterception(cur)
}

// BypassServiceWorker makes every request of the page go to the network (or
// the interceptor) instead of a registered service worker. A service worker
// answers requests in its own target, out of reach of the page's Fetch
// interceptor, so a page whose requests must all be decided by an Interceptor
// turns it off.
func (p *Page) BypassServiceWorker() error {
	return proto.NetworkSetBypassServiceWorker{Bypass: true}.Call(p.boundedPage(0))
}

// answerIntercepted runs ic on one paused request and answers it unless the
// verdict is Continue. Reports whether the request was answered.
func (p *Page) answerIntercepted(ic *Interceptor, e *proto.FetchRequestPaused, page proto.Client) bool {
	if ic.Decide == nil {
		return false
	}
	d := ic.Decide(e)
	switch d.Verdict {
	case InterceptFulfill:
		var headers []*proto.FetchHeaderEntry
		if d.ContentType != "" {
			headers = append(headers, &proto.FetchHeaderEntry{Name: "Content-Type", Value: d.ContentType})
		}
		body := d.Body
		if body == nil {
			// Fetch.fulfillRequest requires the body field; an empty one is a
			// zero-length response.
			body = []byte{}
		}
		if err := (proto.FetchFulfillRequest{RequestID: e.RequestID, ResponseCode: d.Status, ResponseHeaders: headers, Body: body}).Call(page); err != nil {
			zap.L().Debug("browser interceptor: fulfill request", zap.Error(err))
		}
		return true
	case InterceptFail:
		if err := (proto.FetchFailRequest{RequestID: e.RequestID, ErrorReason: proto.NetworkErrorReasonBlockedByClient}).Call(page); err != nil {
			zap.L().Debug("browser interceptor: fail request", zap.Error(err))
		}
		return true
	}
	return false
}
