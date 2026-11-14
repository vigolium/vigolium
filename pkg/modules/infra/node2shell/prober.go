package node2shell

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

const (
	// maxEvidenceBytes caps the response kept on an Exchange.
	maxEvidenceBytes = 2048
	// streamEvidenceBytes is how much of a multi-MiB request is kept before the
	// elision marker: enough for the request line, the headers and the start of
	// the stream, which is all a reader needs to reproduce it.
	streamEvidenceBytes = 512
)

// Prober replays one method+path against a record's origin with a varying body
// and headers. The request is rebuilt once; each probe swaps only the body and
// at most one header, so both modules send byte-identical framing and their
// response classes are comparable.
type Prober struct {
	ctx    *httpmsg.HttpRequestResponse
	client *http.Requester
	base   []byte
}

// NewProber rewrites the record's request into a method+path+Content-Type
// probe. The record's own headers (cookies, auth) are kept so an authenticated
// route is probed as the operator sees it; framing headers are replaced.
func NewProber(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, path, contentType string) (*Prober, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err == nil {
		raw, err = httpmsg.SetPath(raw, path)
	}
	if err == nil {
		raw, err = httpmsg.RemoveHeader(raw, "Transfer-Encoding")
	}
	if err == nil {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", contentType)
	}
	if err == nil {
		raw, err = httpmsg.RemoveHeader(raw, "Content-Encoding")
	}
	if err != nil {
		return nil, false
	}
	return &Prober{ctx: ctx, client: client, base: raw}, true
}

// Send is a SendFunc: it fires the base request with body and one extra header
// (none when value is empty). Intended for the gate's sub-32-byte bodies, which
// are kept verbatim as evidence.
func (p *Prober) Send(name, value string, body []byte) (Exchange, bool) {
	raw := p.base
	var err error
	if value != "" {
		if raw, err = httpmsg.AddOrReplaceHeader(raw, name, value); err != nil {
			return Exchange{}, false
		}
	}
	if raw, err = httpmsg.SetBody(raw, body); err != nil {
		return Exchange{}, false
	}
	return p.exec(raw, string(raw))
}

// SendStream fires a multi-MiB body under the given Content-Encoding.
//
// Two headers differ from Send. "Expect: 100-continue" gives an edge with a
// body-size limit the chance to answer 413 off the advertised Content-Length
// before 22 MiB goes up the wire — the transport waits for the 100 because
// ExpectContinueTimeout is set on it. "Connection: close" retires the
// connection afterwards rather than returning a socket that just carried a
// probe to the pool.
//
// The body is elided from the evidence: a finding travels through the database,
// the JSON envelope and the report, and must not carry 22 MiB through any of
// them.
func (p *Prober) SendStream(encoding string, body []byte) (Exchange, bool) {
	raw, err := httpmsg.AddOrReplaceHeader(p.base, ContentEncoding, encoding)
	if err == nil {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Expect", "100-continue")
	}
	if err == nil {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "Connection", "close")
	}
	if err == nil {
		raw, err = httpmsg.SetBody(raw, body)
	}
	if err != nil {
		return Exchange{}, false
	}
	return p.exec(raw, modkit.ElideRequestBody(raw, len(body), streamEvidenceBytes))
}

// exec sends raw and renders the outcome. The caller supplies the request
// evidence string, because only it knows whether the body is small enough to
// keep verbatim.
func (p *Prober) exec(raw []byte, requestEvidence string) (Exchange, bool) {
	req := httpmsg.NewRequestResponseRaw(raw, p.ctx.Service())
	// Redirects are not followed and the response cache is bypassed: probes
	// differ only in a header or a byte, and every one must reach the decoder.
	// PreserveConnection: SendStream's deliberate "Connection: close" must
	// reach the wire (the requester drops a stored one by default, ECON-13).
	resp, _, err := p.client.Execute(req, http.Options{NoRedirects: true, NoClustering: true, PreserveConnection: true})
	if err != nil {
		return Exchange{}, false
	}
	defer resp.Close()
	hr := resp.Response()
	if hr == nil {
		return Exchange{}, false
	}
	return Exchange{
		Sig:      modkit.NewResponseSignature(hr.StatusCode, resp.BodyString(), ""),
		Header:   hr.Header,
		Request:  requestEvidence,
		Response: modkit.Truncate(resp.FullResponseString(), maxEvidenceBytes),
	}, true
}
