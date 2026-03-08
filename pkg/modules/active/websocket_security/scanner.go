package websocket_security

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

const evilOrigin = "https://evil.example.com"

// wsHeaders are the standard WebSocket upgrade headers.
var wsHeaders = []struct {
	name  string
	value string
}{
	{"Upgrade", "websocket"},
	{"Connection", "Upgrade"},
	{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
	{"Sec-WebSocket-Version", "13"},
}

// Module implements the WebSocket Security active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new WebSocket Security module.
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
		ds: dedup.LazyDiskSet("websocket_security"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for insecure WebSocket upgrade policies.
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

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Derive matching origin from the target URL
	matchingOrigin := fmt.Sprintf("%s://%s", urlx.Scheme, urlx.Host)

	// Step 1: Send WebSocket upgrade with matching origin to confirm WS support
	accepted, err := m.sendUpgrade(ctx, httpClient, matchingOrigin)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, nil
	}
	if !accepted {
		// Server does not support WebSocket on this endpoint
		return nil, nil
	}

	var results []*output.ResultEvent

	// Step 2: Send upgrade with evil origin
	evilAccepted, err := m.sendUpgrade(ctx, httpClient, evilOrigin)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		// Continue to next check
	}
	if evilAccepted {
		results = append(results, &output.ResultEvent{
			URL:     urlx.String(),
			Matched: urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Origin sent: %s", evilOrigin),
				"Server accepted WebSocket upgrade from unauthorized origin",
			},
			Info: output.Info{
				Name:        "WebSocket Origin Not Validated",
				Description: "The server accepts WebSocket upgrade requests from arbitrary origins, allowing cross-site WebSocket hijacking.",
			},
		})
		return results, nil
	}

	// Step 3: Send upgrade with no Origin header
	noOriginAccepted, err := m.sendUpgradeNoOrigin(ctx, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return results, nil
	}
	if noOriginAccepted {
		results = append(results, &output.ResultEvent{
			URL:     urlx.String(),
			Matched: urlx.String(),
			ExtractedResults: []string{
				"Origin header: absent",
				"Server accepted WebSocket upgrade without Origin header",
			},
			Info: output.Info{
				Name:        "WebSocket Missing Origin Check",
				Description: "The server accepts WebSocket upgrade requests without an Origin header, indicating missing origin validation.",
			},
		})
	}

	return results, nil
}

// sendUpgrade sends a WebSocket upgrade request with the given Origin and returns
// true if the server responds with 101 Switching Protocols.
func (m *Module) sendUpgrade(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	origin string,
) (bool, error) {
	rawRequest := ctx.Request().Raw()

	// Add WebSocket upgrade headers
	modified := rawRequest
	var err error
	for _, h := range wsHeaders {
		modified, err = httpmsg.AddOrReplaceHeader(modified, h.name, h.value)
		if err != nil {
			return false, err
		}
	}

	// Set Origin header
	modified, err = httpmsg.AddOrReplaceHeader(modified, "Origin", origin)
	if err != nil {
		return false, err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modified))
	if err != nil {
		return false, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return false, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return false, nil
	}

	return resp.Response().StatusCode == 101, nil
}

// sendUpgradeNoOrigin sends a WebSocket upgrade request without an Origin header.
func (m *Module) sendUpgradeNoOrigin(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (bool, error) {
	rawRequest := ctx.Request().Raw()

	// Add WebSocket upgrade headers
	modified := rawRequest
	var err error
	for _, h := range wsHeaders {
		modified, err = httpmsg.AddOrReplaceHeader(modified, h.name, h.value)
		if err != nil {
			return false, err
		}
	}

	// Remove Origin header by setting it to empty, then remove the line
	// We use AddOrReplaceHeader to ensure no Origin is present by replacing with
	// a marker, then stripping it. However, to properly remove the header,
	// we simply do not add an Origin header — the original request may or may
	// not have one. We need to remove it if present.
	modified, err = httpmsg.RemoveHeader(modified, "Origin")
	if err != nil {
		// If RemoveHeader is not available or fails, proceed without removal.
		// The original request likely has no Origin header for non-CORS requests.
		_ = err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modified))
	if err != nil {
		return false, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return false, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return false, nil
	}

	return resp.Response().StatusCode == 101, nil
}
