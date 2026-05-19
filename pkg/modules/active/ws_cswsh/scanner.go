package ws_cswsh

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"net/http"
)

var wsHeaders = []struct{ name, value string }{
	{"Upgrade", "websocket"},
	{"Connection", "Upgrade"},
	{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
	{"Sec-WebSocket-Version", "13"},
}

// originTest describes one CSWSH origin-validation test case.
type originTest struct {
	label string
	// buildOrigin returns the origin to set and whether to remove the header instead.
	buildOrigin func(host string) (origin string, removeHeader bool)
}

var originTests = []originTest{
	{
		label: "CSWSH via Evil Origin",
		buildOrigin: func(_ string) (string, bool) {
			return "https://evil.example.com", false
		},
	},
	{
		label: "CSWSH via Null Origin",
		buildOrigin: func(_ string) (string, bool) {
			return "null", false
		},
	},
	{
		label: "CSWSH via Subdomain Origin",
		buildOrigin: func(host string) (string, bool) {
			return fmt.Sprintf("https://attacker.%s", host), false
		},
	},
	{
		label: "CSWSH Missing Origin Check",
		buildOrigin: func(_ string) (string, bool) {
			return "", true
		},
	},
}

// Module implements an active scanner for Cross-Site WebSocket Hijacking.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSWSH scanner module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("ws_cswsh"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests WebSocket upgrade endpoints for CSWSH vulnerabilities.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *vighttp.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Skip media and JS URLs.
	if utils.IsMediaAndJSURL(urlx.EscapedPath()) {
		return nil, nil
	}

	// Dedup by host+path.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Step 1: verify the endpoint supports WebSocket upgrades with matching origin.
	scheme := "https"
	if urlx.Scheme == "http" {
		scheme = "http"
	}
	legitimateOrigin := fmt.Sprintf("%s://%s", scheme, urlx.Host)

	if !m.tryUpgrade(ctx, httpClient, legitimateOrigin, false) {
		return nil, nil
	}

	// Step 2: test each malicious origin scenario.
	var results []*output.ResultEvent

	for _, test := range originTests {
		origin, removeHeader := test.buildOrigin(urlx.Host)

		if m.tryUpgrade(ctx, httpClient, origin, removeHeader) {
			var details []string
			if removeHeader {
				details = []string{
					fmt.Sprintf("Test: %s", test.label),
					"Origin header: absent",
					"Server accepted WebSocket upgrade without Origin header",
				}
			} else {
				details = []string{
					fmt.Sprintf("Test: %s", test.label),
					fmt.Sprintf("Origin sent: %s", origin),
					"Server accepted WebSocket upgrade from unauthorized origin",
				}
			}
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: details,
				MatcherStatus:    true,
			})
		}
	}

	return results, nil
}

// tryUpgrade sends a WebSocket upgrade request with the given origin and returns
// true if the server responds with 101 Switching Protocols.
func (m *Module) tryUpgrade(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *vighttp.Requester,
	origin string,
	removeOrigin bool,
) bool {
	rawRequest := ctx.Request().Raw()
	modified := rawRequest

	// Add standard WS upgrade headers.
	for _, h := range wsHeaders {
		modified, _ = httpmsg.AddOrReplaceHeader(modified, h.name, h.value)
	}

	// Set or remove the Origin header.
	if removeOrigin {
		modified, _ = httpmsg.RemoveHeader(modified, "Origin")
	} else {
		modified, _ = httpmsg.AddOrReplaceHeader(modified, "Origin", origin)
	}

	fuzzedReq, parseErr := httpmsg.ParseRawRequest(string(modified))
	if parseErr != nil {
		return false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, execErr := httpClient.Execute(fuzzedReq, vighttp.Options{NoRedirects: true})
	if execErr != nil {
		if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
			return false
		}
		return false
	}
	defer resp.Close()

	return resp.Response().StatusCode == http.StatusSwitchingProtocols
}
