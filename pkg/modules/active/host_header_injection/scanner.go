package host_header_injection

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

const evilHost = "evil.vigolium-test.example.com"

// hostProbe defines a host header injection test case.
type hostProbe struct {
	headerName string
	value      string // literal value, or "" to use evilHost
	desc       string
}

var probes = []hostProbe{
	{
		headerName: "Host",
		desc:       "Direct Host header override",
	},
	{
		headerName: "X-Forwarded-Host",
		desc:       "X-Forwarded-Host header injection",
	},
	{
		headerName: "X-Host",
		desc:       "X-Host header injection",
	},
	{
		headerName: "X-Original-URL",
		desc:       "X-Original-URL header injection",
	},
	{
		headerName: "Forwarded",
		value:      "host=" + evilHost,
		desc:       "RFC 7239 Forwarded header injection",
	},
	{
		headerName: "X-Forwarded-Proto",
		value:      "nothttps",
		desc:       "X-Forwarded-Proto header injection",
	},
	{
		headerName: "X-Forwarded-Port",
		value:      "1337",
		desc:       "X-Forwarded-Port header injection",
	},
	{
		headerName: "X-Real-IP",
		desc:       "X-Real-IP header injection",
	},
	{
		headerName: "Cf-Connecting-IP",
		desc:       "Cloudflare Cf-Connecting-IP header injection",
	},
}

// Module implements the Host Header Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Host Header Injection module.
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
		ds: dedup.LazyDiskSet("host_header_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for host header injection.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		value := probe.value
		if value == "" {
			value = evilHost
		}

		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, value)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		// Check if evil host is reflected in response body
		body := resp.Body().String()
		headers := resp.Headers().String()

		reflected := false
		var location string

		if strings.Contains(body, evilHost) {
			reflected = true
		}

		// Check Location header for host reflection (password reset poisoning)
		if strings.Contains(headers, evilHost) {
			reflected = true
			if resp.Response() != nil {
				location = resp.Response().Header.Get("Location")
			}
		}

		if reflected {
			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, value),
			}
			if location != "" {
				extracted = append(extracted, fmt.Sprintf("Location: %s", location))
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
				ExtractedResults: extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Host Header Injection: %s", probe.headerName),
					Description: probe.desc,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
