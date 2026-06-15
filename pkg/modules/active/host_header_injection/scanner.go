package host_header_injection

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
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

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// injected-Host request and verifying it reproducibly introduces content absent
// from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

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

		// NoRedirects: the host-injection sink we care about is the IMMEDIATE
		// response (a reflected Location header is the password-reset/cache-poisoning
		// signal). Following the 3xx would consume that Location and chase the
		// injected host off-target.
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}

		// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
		// reflecting the injected host — skip it so its body/headers can't trip
		// the marker (the SSO/Cloudflare-challenge false-positive class).
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// Check if the injected host is reflected in the response body or headers.
		body := resp.Body().String()
		headers := resp.Headers().String()

		reflectedInHeader := strings.Contains(headers, evilHost)
		reflectedInBody := strings.Contains(body, evilHost)

		var location string
		if reflectedInHeader && resp.Response() != nil {
			location = resp.Response().Header.Get("Location")
		}

		if reflectedInHeader || reflectedInBody {
			// Re-confirm the reflection is genuine and header-attributable, not a
			// coincidental static string, a cached/volatile page, or a catch-all that
			// serves the same body with or without our header: re-send the SAME header
			// with a FRESH random canary host each round and require the canary to
			// reflect every round. A fresh canary is by construction absent from the
			// no-header baseline, so a value that tracks our input proves the app
			// trusts the client host; one that doesn't (an identical body each time)
			// is dropped. Fails OPEN only on a transport error so a transient failure
			// never suppresses a genuine finding.
			if confirmed, cerr := m.confirmHostReflection(ctx, httpClient, probe.headerName, probe.value); cerr == nil && !confirmed {
				resp.Close()
				continue
			}

			// A reflection into a response header / Location is the URL-generation
			// sink that enables password-reset poisoning and cache poisoning — report
			// it Firm. A body-only echo is a weaker signal (the value may never reach a
			// generated link or redirect), so it ships as Tentative.
			findingConfidence := severity.Tentative
			if reflectedInHeader {
				findingConfidence = severity.Firm
			}

			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, value),
			}
			if location != "" {
				extracted = append(extracted, fmt.Sprintf("Location: %s", location))
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Host Header Injection: %s", probe.headerName),
					Description: probe.desc,
					Confidence:  findingConfidence,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// confirmHostReflection re-sends headerName with a FRESH random canary host each
// round (mirroring the probe's value template) and requires the canary to reflect
// in the response every round. Because each canary is unique and absent from the
// no-header baseline, a reflection that reproduces proves the app echoes the
// client-supplied host; a fixed string, a cached page, or a catch-all that serves
// an identical body regardless of the header does not track the canary and is
// dropped. A blocked/challenge page is never counted as a reflection. Returns
// (confirmed, err); err != nil signals a transport failure so the caller can fail
// open rather than suppress a genuine finding.
func (m *Module) confirmHostReflection(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	headerName, probeValue string,
) (bool, error) {
	return modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		canaryHost := canary + ".vgn-hhi.example"
		value := canaryHost
		if probeValue != "" {
			// Probes with a structured value (e.g. Forwarded: host=<h>) keep their
			// shape with the fresh canary swapped in for the sentinel host.
			value = strings.ReplaceAll(probeValue, evilHost, canaryHost)
		}
		raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), headerName, value)
		if err != nil {
			return false, err
		}
		req, err := httpmsg.ParseRawRequest(string(raw))
		if err != nil {
			return false, err
		}
		req = req.WithService(ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
		if err != nil {
			return false, err
		}
		defer resp.Close()
		if resp.Response() == nil {
			return false, fmt.Errorf("host-header confirmation: nil response")
		}
		if infra.IsBlockedResponse(resp) {
			return false, nil // a WAF/challenge page is not a host reflection
		}
		return strings.Contains(resp.FullResponseString(), canaryHost), nil
	})
}
