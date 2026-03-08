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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Fingerprint 404 response body hash
	notFoundHash := get404Hash(ctx, httpClient)

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

		probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
		if err != nil {
			continue
		}
		probeReq = probeReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(probeReq, http.Options{})
		if err != nil {
			continue
		}

		if resp.Response() == nil {
			resp.Close()
			continue
		}

		statusCode := resp.Response().StatusCode

		// Check expected status
		if probe.expectedStatus > 0 {
			if statusCode == probe.expectedStatus {
				results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponse().String()))
				resp.Close()
				continue
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

		// Skip if body hash matches 404
		if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
			resp.Close()
			continue
		}

		// Check expected Content-Type
		if probe.expectedCT != "" && strings.Contains(strings.ToLower(ct), probe.expectedCT) {
			results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponse().String()))
			resp.Close()
			continue
		}

		// Check markers
		if len(probe.markers) > 0 {
			for _, marker := range probe.markers {
				if strings.Contains(body, marker) {
					results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponse().String()))
					break
				}
			}
			resp.Close()
			continue
		}

		// For probes without markers or expectedCT (open-in-editor, remix dev),
		// a non-404 2xx with different body from 404 is enough
		if len(probe.markers) == 0 && probe.expectedCT == "" && body != "" {
			results = append(results, buildResult(target, host, probe, string(probeRaw), resp.FullResponse().String()))
		}

		resp.Close()
	}

	return results, nil
}

// get404Hash fetches a known-missing path to fingerprint the 404 page.
func get404Hash(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	notFoundPath := "/vigolium-nonexistent-path-404-check"
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), notFoundPath)
	if err != nil {
		return ""
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return ""
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	return utils.Sha1(resp.Body().String())
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
