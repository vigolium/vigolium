package http_request_smuggling

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// smugglingProbe defines a request smuggling test case.
type smugglingProbe struct {
	name    string
	headers map[string]string
	body    string
	desc    string
}

// CL.TE: backend uses Transfer-Encoding, frontend uses Content-Length
// TE.CL: backend uses Content-Length, frontend uses Transfer-Encoding
var probes = []smugglingProbe{
	{
		name: "CL.TE Basic",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "CL.TE desync: frontend uses Content-Length, backend uses Transfer-Encoding. The extra data after the chunked body may be treated as a separate request.",
	},
	{
		name: "TE.CL Basic",
		headers: map[string]string{
			"Content-Length":    "6",
			"Transfer-Encoding": "chunked",
		},
		body: "0\r\n\r\nX",
		desc: "TE.CL desync: frontend uses Transfer-Encoding, backend uses Content-Length. Content after the terminating chunk may be treated as a separate request.",
	},
	{
		name: "TE.TE Obfuscation",
		headers: map[string]string{
			"Content-Length":     "4",
			"Transfer-Encoding":  "chunked",
			"Transfer-encoding":  "x",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "TE.TE desync via header obfuscation: uses duplicate Transfer-Encoding headers with different casing to confuse parsers.",
	},
	{
		name: "Chunked Extension",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		},
		body: "1;ext=val\r\nZ\r\n0\r\n\r\n",
		desc: "Chunked extension confusion: uses chunk extension syntax that may be parsed differently.",
	},
	{
		name: "TE Tab Obfuscation",
		headers: map[string]string{
			"Content-Length":     "4",
			"Transfer-Encoding": "\tchunked",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "Transfer-Encoding with leading tab may bypass header parsing.",
	},
}

// Module implements the HTTP Request Smuggling active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new HTTP Request Smuggling module.
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
		ds: dedup.LazyDiskSet("http_request_smuggling"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess checks if the request is suitable for smuggling tests.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerHost runs smuggling probes once per unique host.
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// First, measure baseline response time
	baselineStart := time.Now()
	baseResp, _, err := httpClient.Execute(ctx, http.Options{})
	if err != nil {
		return nil, nil
	}
	baseResp.Close()
	baselineDuration := time.Since(baselineStart)

	var results []*output.ResultEvent

	for _, probe := range probes {
		modifiedRaw := ctx.Request().Raw()
		var modErr error

		// Set method to POST for smuggling tests
		modifiedRaw, modErr = httpmsg.SetMethod(modifiedRaw, "POST")
		if modErr != nil {
			continue
		}

		// Set the smuggling headers
		for k, v := range probe.headers {
			modifiedRaw, modErr = httpmsg.AddOrReplaceHeader(modifiedRaw, k, v)
			if modErr != nil {
				continue
			}
		}

		// Set the body
		modifiedRaw, modErr = httpmsg.SetBody(modifiedRaw, []byte(probe.body))
		if modErr != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		start := time.Now()
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		elapsed := time.Since(start)
		if err != nil {
			// A timeout itself can be an indicator of smuggling
			if elapsed > baselineDuration*5 && elapsed > 5*time.Second {
				results = append(results, &output.ResultEvent{
					URL:     ctx.Target(),
					Matched: ctx.Target(),
					Request: string(modifiedRaw),
					ExtractedResults: []string{
						fmt.Sprintf("Probe: %s", probe.name),
						fmt.Sprintf("Baseline: %s, Probe: %s (timeout)", baselineDuration, elapsed),
					},
					Info: output.Info{
						Name:        fmt.Sprintf("HTTP Request Smuggling: %s (Timeout)", probe.name),
						Description: probe.desc,
						Severity:    severity.High,
						Confidence:  severity.Tentative,
					},
				})
			}
			continue
		}

		// Check for timing anomaly: probe takes significantly longer than baseline
		if elapsed > baselineDuration*5 && elapsed > 5*time.Second {
			results = append(results, &output.ResultEvent{
				URL:     ctx.Target(),
				Matched: ctx.Target(),
				Request: string(modifiedRaw),
				ExtractedResults: []string{
					fmt.Sprintf("Probe: %s", probe.name),
					fmt.Sprintf("Baseline: %s, Probe: %s", baselineDuration, elapsed),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("HTTP Request Smuggling: %s", probe.name),
					Description: probe.desc,
					Severity:    severity.High,
					Confidence:  severity.Tentative,
				},
			})
		}
		resp.Close()
	}

	return results, nil
}
