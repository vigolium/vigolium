package input_behavior_probe

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// probePaths applies prefix and postfix manipulations to each path segment,
// comparing each response against the baseline for behavior changes.
func probePaths(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	urlx, err := ctx.URL()
	if err != nil {
		return nil
	}

	path := urlx.EscapedPath()
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return nil
	}

	urlStr := urlx.String()
	var results []*output.ResultEvent

	for segIdx, segment := range segments {
		for _, manip := range pathManipulations {
			// Postfix: segment + manip
			postfix := rebuildPath(segments, segIdx, segment+manip)
			if r := testPathVariant(ctx, httpClient, baseline, urlStr, postfix, manip, "path_postfix"); r != nil {
				results = append(results, r)
			}

			// Prefix: manip + segment
			prefix := rebuildPath(segments, segIdx, manip+segment)
			if r := testPathVariant(ctx, httpClient, baseline, urlStr, prefix, manip, "path_prefix"); r != nil {
				results = append(results, r)
			}
		}
	}

	return results
}

// rebuildPath reconstructs a path with segments[idx] replaced by replacement.
func rebuildPath(segments []string, idx int, replacement string) string {
	rebuilt := make([]string, len(segments))
	copy(rebuilt, segments)
	rebuilt[idx] = replacement
	return "/" + strings.Join(rebuilt, "/")
}

// testPathVariant sends a request with a modified path and checks for behavior change.
func testPathVariant(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baseline *detectionBaseline,
	urlStr, newPath, payload, probeType string,
) *output.ResultEvent {
	raw, err := httpmsg.SetPathOnly(ctx.Request().Raw(), newPath)
	if err != nil {
		return nil
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil
		}
		return nil
	}
	defer resp.Close()

	change := detectChange(baseline, resp.Body().String(), resp.Response().StatusCode)
	if change.IsInteresting {
		return buildProbeResult(
			urlStr, raw, resp.FullResponseString(),
			"path", probeType, payload, change,
		)
	}

	return nil
}
