package sqli_boolean_blind

import (
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// maxConsecutiveBlockedPairs: after this many plain TRUE/FALSE pairs in a row
// came back blocked, the rest of the plain pairs are skipped for the point
// (WAF variants and the HPP fallback still run).
const maxConsecutiveBlockedPairs = 3

// recordBaselineKey memoises the step-1 baseline per record.
const recordBaselineKey = "boolean-baseline-v1"

// recordBaselineTTL bounds reuse of one baseline response across points.
const recordBaselineTTL = 2 * time.Minute

// rawBaseline is the unmodified request's response, before any per-point
// signature normalisation.
type rawBaseline struct {
	full    string
	body    string
	status  int
	blocked bool
}

// recordBaseline fetches the record's unmodified response once per record
// (memoised across insertion points). A transport error is returned and
// not cached.
func (m *Module) recordBaseline(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) (rawBaseline, error) {
	var fetchErr error
	v := scanCtx.EndpointMemo(recordBaselineKey, ctx, recordBaselineTTL, func() (any, bool) {
		req := httpmsg.NewRequestResponseRaw(ctx.Request().Raw(), ctx.Service())
		// NoClustering for the same reason as sendPayload: a stability oracle
		// must never read a cached copy.
		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
		if err != nil {
			fetchErr = err
			return rawBaseline{}, false
		}
		defer resp.Close()
		rb := rawBaseline{blocked: infra.IsBlockedResponse(resp)}
		if r := resp.Response(); r != nil {
			rb.full = resp.FullResponseString()
			rb.body = resp.Body().String()
			rb.status = r.StatusCode
		}
		return rb, true
	})
	if fetchErr != nil {
		return rawBaseline{}, fetchErr
	}
	rb, _ := v.(rawBaseline)
	return rb, nil
}
