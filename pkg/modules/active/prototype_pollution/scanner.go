package prototype_pollution

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// pollutionPayload defines a prototype pollution test case.
type pollutionPayload struct {
	payload string
	desc    string
}

var payloads = []pollutionPayload{
	{
		payload: `{"__proto__":{"vigolium_pp_test":"polluted"}}`,
		desc:    "__proto__ property injection",
	},
	{
		payload: `{"constructor":{"prototype":{"vigolium_pp_test":"polluted"}}}`,
		desc:    "constructor.prototype injection",
	},
	{
		payload: `{"__proto__":{"status":510}}`,
		desc:    "__proto__ status code pollution (expects 510 response)",
	},
	{
		payload: `{"__proto__":{"__proto__":{"vigolium_pp_test":"polluted"}}}`,
		desc:    "Nested __proto__ injection",
	},
	{
		payload: `{"__proto__":{"toString":"polluted"}}`,
		desc:    "__proto__ toString gadget injection",
	},
}

// Module implements the Prototype Pollution active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Prototype Pollution module.
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
		rhm: dedup.LazyDefaultRHM("prototype_pollution"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess limits to requests with JSON bodies.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Request() == nil {
		return false
	}
	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	method := ctx.Request().Method()
	// Only process POST/PUT/PATCH with JSON content
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}
	if !strings.Contains(ct, "json") {
		return false
	}
	return true
}

// ScanPerRequest tests the request for server-side prototype pollution.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Get baseline response (cached across modules)
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, nil
	}
	baseStatus := entry.StatusCode
	baseBody := entry.Response.BodyToString()

	var results []*output.ResultEvent

	for _, p := range payloads {
		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(p.payload))
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

		detected := false
		var evidence string

		// Check for status code pollution (510)
		if resp.Response() != nil && strings.Contains(p.payload, "status") {
			if resp.Response().StatusCode == 510 && baseStatus != 510 {
				detected = true
				evidence = fmt.Sprintf("Status code changed from %d to 510", baseStatus)
			}
		}

		// Check for pollution marker reflected in response
		body := resp.Body().String()
		if strings.Contains(body, "vigolium_pp_test") && !strings.Contains(baseBody, "vigolium_pp_test") {
			detected = true
			evidence = "Pollution marker 'vigolium_pp_test' reflected in response"
		}

		if detected {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
				ExtractedResults: []string{p.payload, evidence},
				Info: output.Info{
					Name:        fmt.Sprintf("Prototype Pollution: %s", p.desc),
					Description: evidence,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
