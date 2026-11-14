package js_devserver_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the JS dev server exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JS Dev Server Exposure module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("js_devserver_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerRequest probes for exposed dev server endpoints per request.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	// Fingerprint the 404 response (body hash + status) so probes can tell a
	// distinctive dev-server response from the host's generic answer to any path.
	notFoundHash, notFoundStatus := fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	target := ctx.Target()

	for _, probe := range devProbes {
		probePath := probe.path
		if !strings.HasPrefix(probePath, "/") {
			probePath = "/" + probePath
		}

		probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probePath)
		if err != nil {
			continue
		}
		probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

		// probeRaw is internally built (well-formed), so wrap directly instead
		// of re-parsing on this hot path.
		probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

		resp, _, err := httpClient.Execute(probeReq, http.Options{})
		if err != nil {
			continue
		}

		if resp.Response() == nil {
			resp.Close()
			continue
		}

		statusCode := resp.Response().StatusCode

		// Check expected status. Require the status to be DISTINCTIVE — if the
		// random 404 probe returned the same status, the host answers every path
		// that way (a blanket 204/200 catch-all) and the match proves nothing.
		if probe.expectedStatus > 0 {
			if statusCode == probe.expectedStatus && statusCode != notFoundStatus {
				results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponseString()))
			}
			resp.Close()
			continue
		}

		// Must be 2xx
		if statusCode < 200 || statusCode >= 300 {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		ct := resp.Response().Header.Get("Content-Type")

		// Catch-all / echo-server guard: none of these dev-server endpoints serve a
		// full HTML document — the HMR endpoints stream text/event-stream, sockjs /
		// info serves JSON, open-in-editor returns a plaintext error. A 200 text/html
		// body on one of these paths is the host's catch-all / SPA shell served for
		// literally any path (or, under a gzip + bogus `Content-Length: 0` transport
		// quirk, a truncated TAIL fragment of it whose weak reflected marker survives
		// the exact-hash 404 and observed-page guards). The Content-Type header
		// survives that truncation, so reject an HTML document outright before the
		// content-type / marker checks below.
		if modkit.ClassifyContentType(ct) == modkit.ContentClassHTML {
			resp.Close()
			continue
		}

		// Skip if body hash matches 404
		if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
			resp.Close()
			continue
		}

		// Catch-all / SPA shell guard: a real dev-server endpoint streams SSE or
		// serves a terse JSON status — it never returns the application page. A
		// probe whose body is the observed page is the catch-all shell, even when
		// the exact-hash 404 check above misses a shell that varies per path.
		if modkit.ResemblesObservedPage(ctx, body) {
			resp.Close()
			continue
		}

		// Check expected Content-Type
		if probe.expectedCT != "" && strings.Contains(strings.ToLower(ct), probe.expectedCT) {
			results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponseString()))
			resp.Close()
			continue
		}

		// Check markers. Every probe declares a positive signal — a distinctive
		// status (expectedStatus), an SSE/stream content-type (expectedCT), or a
		// body marker. A probe that declares NONE deliberately does not fire: the
		// former "any non-404, non-HTML 2xx body is a dev server" fallback flagged
		// any app returning a small JSON/text 200 on one of these paths (an API
		// gateway echoing the route, a catch-all `{"error":...}`) as a Medium/Firm
		// dev-server exposure — the same weakness as an empty-marker fingerprint.
		if len(probe.markers) > 0 {
			for _, marker := range probe.markers {
				if strings.Contains(body, marker) {
					results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponseString()))
					break
				}
			}
		}

		resp.Close()
	}

	return results, nil
}

// fingerprint404 fetches a known-missing path to learn the host's answer to an
// unknown path: the body hash (to drop probes that echo the 404 page) and the
// status code (to drop status-only probes whose expected status the host returns
// for every path). Returns ("", 0) on any error.
func fingerprint404(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (hash string, status int) {
	notFoundPath := "/vigolium-nonexistent-path-404-check"
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), notFoundPath)
	if err != nil {
		return "", 0
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return "", 0
	}
	defer resp.Close()

	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}
	return utils.Sha1(resp.Body().String()), status
}

func buildResult(target, host string, probe devProbe, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      target,
		Matched:  fmt.Sprintf("%s%s", target, probe.path),
		Request:  request,
		Response: response,
		ExtractedResults: []string{
			fmt.Sprintf("Endpoint: %s", probe.path),
			fmt.Sprintf("Server: %s", probe.name),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Dev Server Exposed: %s", probe.name),
			Description: probe.desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"devserver", "misconfiguration", "information-disclosure"},
			Reference:   []string{"https://webpack.js.org/configuration/dev-server/"},
		},
	}
}
