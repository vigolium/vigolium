package input_behavior_probe

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// probeParamFuzz appends each character from paramFuzzChars to the insertion
// point's base value and checks for behavior changes.
func probeParamFuzz(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	urlx, err := ctx.URL()
	if err != nil {
		return nil
	}
	urlStr := urlx.String()
	var results []*output.ResultEvent

	for _, char := range paramFuzzChars {
		payload := ip.BaseValue() + char
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		req, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		req = req.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(req, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results
			}
			continue
		}

		change := detectChange(baseline, resp.Body().String(), resp.Response().StatusCode)
		if change.IsInteresting {
			results = append(results, buildProbeResult(
				urlStr, fuzzedRaw, resp.FullResponseString(),
				ip.Name(), "param_char_fuzz", payload, change,
			))
		}
		resp.Close()
	}

	return results
}
