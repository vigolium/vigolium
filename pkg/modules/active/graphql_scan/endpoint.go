package graphql_scan

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// gqlResp is a snapshot of a GraphQL probe response, captured before the
// underlying ResponseChain is closed (its pooled buffers are recycled on Close).
type gqlResp struct {
	status  int
	ctype   string
	body    string
	blocked bool
}

// isHTML reports whether the response was served as HTML — the precondition for
// error-message XSS to be browser-executable.
func (r *gqlResp) isHTML() bool {
	return r != nil && modkit.ClassifyContentType(r.ctype) == modkit.ContentClassHTML
}

// buildRaw shapes a well-formed raw HTTP request off the observed request with
// an explicit method / path / content-type / body. A GET (empty body) clears any
// inherited body. Shared by send (which executes it), the legacy probe helpers
// in scanner.go, and the operations phase (which feeds it into the pipeline for
// the executor to execute).
func buildRaw(
	ctx *httpmsg.HttpRequestResponse,
	method, path, contentType, body string,
) ([]byte, error) {
	raw := ctx.Request().Raw()

	modified, err := httpmsg.SetPath(raw, path)
	if err != nil {
		return nil, err
	}
	modified, err = httpmsg.SetMethod(modified, method)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		modified, err = httpmsg.AddOrReplaceHeader(modified, "Content-Type", contentType)
		if err != nil {
			return nil, err
		}
	}
	if body != "" {
		modified, err = httpmsg.SetBodyString(modified, body)
	} else {
		modified, err = httpmsg.ClearBody(modified)
	}
	if err != nil {
		return nil, err
	}
	return modified, nil
}

// send issues one GraphQL probe with an explicit method / content-type / body and
// returns a snapshot. NoClustering is set so the multi-round confirmation gate
// gets genuinely independent network observations: without it the requester's
// clusterer serves byte-identical back-to-back probes (a confirmation round's
// repeat) from its short-TTL cache, which would make confirmRounds re-check a
// cached response instead of the live endpoint.
func (m *Module) send(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	method, path, contentType, body string,
) (*gqlResp, error) {
	modified, err := buildRaw(ctx, method, path, contentType, body)
	if err != nil {
		return nil, err
	}

	fuzzedReq := httpmsg.NewRequestResponseRaw(modified, ctx.Service())
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	out := &gqlResp{
		body:    resp.BodyString(),
		blocked: isBlockedResponse(resp),
	}
	if r := resp.Response(); r != nil {
		out.status = r.StatusCode
		out.ctype = r.Header.Get("Content-Type")
	}
	return out, nil
}

// confirmRounds runs check up to rounds times and reports true only when every
// round agrees (all true). Any false or error short-circuits to false. It is the
// shared anti-false-positive gate for the active phases: a genuine vulnerability
// reproduces on every independent observation, while a flaky/non-deterministic
// signal (transient error page, rate-limit blip) fails at least one round. The
// probes it drives set NoClustering (see send) so each round is a fresh
// observation, not a cached repeat. rounds < 1 is treated as 1.
func confirmRounds(rounds int, check func() (bool, error)) bool {
	if rounds < 1 {
		rounds = 1
	}
	for i := 0; i < rounds; i++ {
		ok, err := check()
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// defaultConfirmRounds is the number of independent confirmations required
// before an active GraphQL phase reports a finding.
const defaultConfirmRounds = 2
