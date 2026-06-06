package upgrade_routing_ssrf

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	limitPerHost  = 1
	confirmRounds = 2
)

// upgradeHeaders are the standard WebSocket handshake headers whose presence is
// the hypothesised bypass. Cache-Control: no-transform discourages intermediaries
// from mangling the payload (the "Cracking the lens" trick).
var upgradeHeaders = map[string]string{
	"Connection":            "Upgrade",
	"Upgrade":               "websocket",
	"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
	"Sec-WebSocket-Version": "13",
	"Cache-Control":         "no-transform",
}

// Module implements the WebSocket-upgrade SSRF filter-bypass active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new upgrade-routing-ssrf module.
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
		ds: dedup.LazyDiskSet("upgrade_routing_ssrf"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest probes each internal/metadata endpoint with an absolute-form
// request line, once with the upgrade handshake headers and once without, and
// reports only a marker that the upgrade headers uniquely unlock.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	baseRaw := ctx.Request().Raw()
	if ctx.Request().Method() != "GET" {
		baseRaw = infra.SwapToGetMethodRequest(baseRaw)
	}
	service := ctx.Service()

	for _, tgt := range infra.InternalSSRFTargets() {
		target := "http://" + tgt.Effective

		// (1) Probe WITH the upgrade handshake.
		pStatus, pBody, pResp, pBlocked, ok, fatal := m.fire(httpClient, service, baseRaw, target, withUpgrade(tgt.ExtraHeaders))
		if fatal {
			return nil, nil
		}
		if !ok || pBlocked || !is2xx(pStatus) {
			continue
		}
		marker := firstMarker(pBody, tgt.Markers)
		if marker == "" {
			continue
		}

		// (2) Control WITHOUT the upgrade handshake. If the marker is present here
		// too, this is a plain request-line routing SSRF (routing-ssrf reports it) —
		// not an upgrade bypass — so we must NOT double-report it.
		cStatus, cBody, cResp, cBlocked, ok2, _ := m.fire(httpClient, service, baseRaw, target, tgt.ExtraHeaders)
		if !ok2 {
			continue // cannot establish the control → fail closed
		}
		if !cBlocked && is2xx(cStatus) && containsFold(cBody, marker) {
			continue // marker present without upgrade → not an upgrade bypass
		}

		// (3) Reproduce the upgrade-only behaviour to reject per-request noise.
		ev := modkit.NewEvidenceCollector()
		ev.Add("with-upgrade (candidate)", displayRequest(baseRaw, target, true), pResp)
		ev.Add("without-upgrade (control)", displayRequest(baseRaw, target, false), cResp)
		if !m.reproduce(httpClient, service, baseRaw, target, tgt, marker, ev) {
			continue
		}

		desc := fmt.Sprintf(
			"WebSocket-upgrade SSRF bypass: the proxy reached %s (marker %q) only when the request carried Connection: Upgrade / Upgrade: websocket — the same request without the upgrade handshake did not. The connection and Host header named the victim.",
			tgt.Label, marker,
		)
		return []*output.ResultEvent{{
			URL:                urlx.String(),
			Request:            displayRequest(baseRaw, target, true),
			Response:           pResp,
			FuzzingParameter:   "request-line+upgrade",
			ExtractedResults:   []string{target, tgt.Label, "marker=" + marker, "bypass=Connection: Upgrade"},
			AdditionalEvidence: ev.Entries(),
			Info: output.Info{
				Name:        "WebSocket-Upgrade SSRF Filter Bypass",
				Description: desc,
				Severity:    severity.High,
				Confidence:  severity.Firm,
			},
		}}, nil
	}
	return nil, nil
}

// reproduce re-sends the with-upgrade probe confirmRounds times; the marker must
// reappear on a 2xx, non-blocked response every time.
func (m *Module) reproduce(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	target string,
	tgt infra.SSRFInternalTarget,
	marker string,
	ev *modkit.EvidenceCollector,
) bool {
	for i := 0; i < confirmRounds; i++ {
		status, body, resp, blocked, ok, fatal := m.fire(httpClient, service, baseRaw, target, withUpgrade(tgt.ExtraHeaders))
		if fatal || !ok || blocked || !is2xx(status) || !containsFold(body, marker) {
			return false
		}
		ev.Add(fmt.Sprintf("reproduce-%d", i+1), displayRequest(baseRaw, target, true), resp)
	}
	return true
}

// fire sends baseRaw with the literal request-line target and the given header
// overlay. The connection still goes to service's host.
func (m *Module) fire(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	target string,
	headers map[string]string,
) (status int, body, fullResp string, blocked, ok, fatal bool) {
	raw := baseRaw
	var err error
	for k, v := range headers {
		raw, err = httpmsg.AddOrReplaceHeader(raw, k, v)
		if err != nil {
			return 0, "", "", false, false, false
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", "", false, false, false
	}
	req = req.WithService(service)

	resp, _, err := httpClient.Execute(req, http.Options{
		RawRequest:       true,
		RawRequestTarget: target,
		NoRedirects:      true,
		NoClustering:     true,
	})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return 0, "", "", false, false, true
		}
		return 0, "", "", false, false, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", "", false, false, false
	}
	return resp.Response().StatusCode, resp.Body().String(), resp.FullResponseString(), infra.IsBlockedResponse(resp), true, false
}

// withUpgrade merges the endpoint's required headers with the upgrade handshake
// headers (upgrade headers win on conflict).
func withUpgrade(extra map[string]string) map[string]string {
	out := make(map[string]string, len(extra)+len(upgradeHeaders))
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range upgradeHeaders {
		out[k] = v
	}
	return out
}

func firstMarker(body string, markers []string) string {
	for _, mk := range markers {
		if containsFold(body, mk) {
			return mk
		}
	}
	return ""
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// displayRequest renders the wire-form request for evidence, optionally including
// the upgrade headers, with the literal target on the request line.
func displayRequest(baseRaw []byte, target string, upgrade bool) string {
	s := string(baseRaw)
	rest := ""
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		rest = strings.TrimLeft(s[i+1:], "\r")
	}
	head := "GET " + target + " HTTP/1.1\r\n"
	if upgrade {
		head += "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	}
	return head + rest
}

func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	_, shouldContinue := diskSet.IncrementAndCheck(urlx.Hostname(), limitPerHost)
	return shouldContinue
}
