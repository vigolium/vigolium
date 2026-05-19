package input_behavior_probe

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// probeHeaders injects probe values into known and unusual header names,
// comparing each response against the baseline for behavior changes.
func probeHeaders(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	urlx, err := ctx.URL()
	if err != nil {
		return nil
	}
	urlStr := urlx.String()
	var results []*output.ResultEvent

	// Phase 1: each header name × each value
	for _, header := range probeHeaderNames {
		for _, value := range probeHeaderValues {
			raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), header, value)
			if err != nil {
				continue
			}

			req, err := httpmsg.ParseRawRequest(string(raw))
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
					urlStr, raw, resp.FullResponse().String(),
					header, "header", value, change,
				))
			}
			resp.Close()
		}
	}

	// Phase 2: weird header NAMES (%00, %ff) with a fixed value
	for _, name := range weirdHeaderNames {
		raw, err := httpmsg.AddHeader(ctx.Request().Raw(), name, "127.0.0.1")
		if err != nil {
			continue
		}

		req, err := httpmsg.ParseRawRequest(string(raw))
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
				urlStr, raw, resp.FullResponse().String(),
				name, "weird_header", "127.0.0.1", change,
			))
		}
		resp.Close()
	}

	return results
}
