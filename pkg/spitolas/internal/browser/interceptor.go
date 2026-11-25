package browser

import (
	"encoding/base64"
	"net/http"

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
	// InterceptRewrite is a response-stage verdict (DecideResponse only): the
	// request already reached the network, and the page receives the upstream
	// response as InterceptDecision.Rewrite changes it. A rewrite that returns
	// an error lets the upstream response through unchanged.
	InterceptRewrite
)

// InterceptDecision is an Interceptor's answer for one request. Status,
// ContentType and Body are read only for InterceptFulfill; Rewrite only for
// InterceptRewrite.
type InterceptDecision struct {
	Verdict     InterceptVerdict
	Status      int
	ContentType string
	Body        []byte
	// Rewrite receives the upstream status and body (nil when the browser
	// could not read it) and returns the status and body the page receives.
	// The upstream headers are kept, less the ones that describe the old body's
	// framing (Content-Length, Content-Encoding, Transfer-Encoding).
	Rewrite func(status int, body []byte) (int, []byte, error)
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
	// ResponsePatterns are Fetch URL patterns paused a second time, once their
	// response headers arrive (the Fetch response stage), for DecideResponse.
	ResponsePatterns []string
	// DecideResponse is called once per request paused at the response stage.
	// Continue passes the upstream response to the page; Rewrite changes it;
	// Fulfill replaces it; Fail fails it. Like Decide, whatever it (and a
	// Rewrite it returns) records happens before the page sees the answer.
	DecideResponse func(e *proto.FetchRequestPaused) InterceptDecision
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

// rewriteDroppedHeaders describe the upstream body's framing and encoding.
// Fetch.getResponseBody returns the decoded body, so a rewritten answer
// carries neither the old length nor the old content-coding.
var rewriteDroppedHeaders = map[string]bool{
	"Content-Length":    true,
	"Content-Encoding":  true,
	"Transfer-Encoding": true,
}

// answerResponse answers one request paused at the response stage under ic.
// A request paused with a network error, or with no DecideResponse, continues
// unchanged.
func (p *Page) answerResponse(ic *Interceptor, e *proto.FetchRequestPaused, page proto.Client) {
	pass := func() {
		if err := (proto.FetchContinueResponse{RequestID: e.RequestID}).Call(page); err != nil {
			// A response paused with a network error takes continueRequest.
			if err2 := (proto.FetchContinueRequest{RequestID: e.RequestID}).Call(page); err2 != nil {
				zap.L().Debug("browser interceptor: continue response", zap.Error(err), zap.Error(err2))
			}
		}
	}
	if ic == nil || ic.DecideResponse == nil || e.ResponseErrorReason != "" || e.ResponseStatusCode == nil {
		pass()
		return
	}
	d := ic.DecideResponse(e)
	switch d.Verdict {
	case InterceptFulfill, InterceptFail:
		p.answerIntercepted(&Interceptor{Decide: func(*proto.FetchRequestPaused) InterceptDecision { return d }}, e, page)
	case InterceptRewrite:
		if d.Rewrite == nil {
			pass()
			return
		}
		var body []byte
		if res, err := (proto.FetchGetResponseBody{RequestID: e.RequestID}).Call(page); err == nil {
			body = []byte(res.Body)
			if res.Base64Encoded {
				if dec, derr := base64.StdEncoding.DecodeString(res.Body); derr == nil {
					body = dec
				} else {
					body = nil
				}
			}
		}
		status, out, err := d.Rewrite(*e.ResponseStatusCode, body)
		if err != nil {
			pass()
			return
		}
		headers := make([]*proto.FetchHeaderEntry, 0, len(e.ResponseHeaders))
		for _, h := range e.ResponseHeaders {
			if h != nil && !rewriteDroppedHeaders[http.CanonicalHeaderKey(h.Name)] {
				headers = append(headers, h)
			}
		}
		if out == nil {
			out = []byte{}
		}
		if ferr := (proto.FetchFulfillRequest{RequestID: e.RequestID, ResponseCode: status, ResponseHeaders: headers, Body: out}).Call(page); ferr != nil {
			zap.L().Debug("browser interceptor: fulfill rewritten response", zap.Error(ferr))
		}
	default:
		pass()
	}
}
