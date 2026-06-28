package web_cache_poisoning

import (
	"fmt"
	mrand "math/rand/v2"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

const poisonMarker = "vigolium-cache-test.example.com"

// cacheProbe defines a web cache poisoning test case.
type cacheProbe struct {
	headerName string
	value      string
	desc       string
	// hostShaped marks a probe whose value is a hostname: its reflection only
	// matters when it lands in URL-authority position (the host of a cached link /
	// redirect that other users then load), not as an incidental substring inside a
	// query parameter (a continue=/redirect_uri= echo whose real authority is
	// unchanged). Non-host probes (scheme, path override, port, language) keep plain
	// substring matching.
	hostShaped bool
	// newConfirmValue, when non-nil, returns a FRESH, distinct value (different from
	// `value` and from prior calls) used to re-probe the header during reflection-
	// tracking confirmation. It mirrors `value`'s shape (a port number for the port
	// probe, a token for the scheme probe) so a genuine verbatim echo still reflects,
	// while a coincidental static substring match cannot track the changing value. It
	// is set only for probes whose value is generic enough to appear in a body by
	// chance (the X-Forwarded-Port: 1337 false positive — 1337 matching an asset
	// hash / story id — and the short X-Forwarded-Scheme token). Probes carrying a
	// long unique sentinel (host, X-Original-URL, Accept-Language) leave it nil:
	// coincidental collision is negligible and they are already authority- or
	// sentinel-gated.
	newConfirmValue func() string
}

var probes = []cacheProbe{
	{
		headerName: "X-Forwarded-Host",
		value:      poisonMarker,
		desc:       "X-Forwarded-Host reflection in cached response",
		hostShaped: true,
	},
	{
		headerName:      "X-Forwarded-Scheme",
		value:           "nothttps",
		desc:            "X-Forwarded-Scheme manipulation causing redirect to attacker-controlled scheme",
		newConfirmValue: func() string { return "vgnscheme-" + modkit.FreshCanary() },
	},
	{
		headerName: "X-Original-URL",
		value:      "/vigolium-cache-test-path",
		desc:       "X-Original-URL override affecting cached content",
	},
	{
		headerName: "X-Rewrite-URL",
		value:      "/vigolium-cache-test-path",
		desc:       "X-Rewrite-URL override affecting cached content",
	},
	{
		headerName:      "X-Forwarded-Port",
		value:           "1337",
		desc:            "X-Forwarded-Port injection reflected in response URLs",
		newConfirmValue: freshPort,
	},
	{
		headerName: "Accept-Language",
		value:      "vigolium-cache-test-lang",
		desc:       "Accept-Language header reflected in cached response",
	},
}

// Module implements the Web Cache Poisoning active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Web Cache Poisoning module.
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
		ds: dedup.LazyDiskSet("web_cache_poisoning"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// unkeyed-header request and verifying it reproducibly introduces content absent
// from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// ScanPerRequest tests the request for web cache poisoning via unkeyed headers.
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
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, probe.value)
		if err != nil {
			continue
		}

		// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		respObj := resp.Response()
		if respObj == nil {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		location := respObj.Header.Get("Location")
		reflectedInBody, reflectedInLocation := probeReflected(probe, probe.value, body, location)

		if !reflectedInBody && !reflectedInLocation {
			resp.Close()
			continue
		}

		// A reflected unkeyed-header value is only a poisoning risk if the response
		// is one a shared cache would actually store and replay to other users.
		// Without this gate the module fired on uncacheable responses — most
		// notably 302 login redirects that echo X-Forwarded-Host into a `continue`
		// return URL (normal SSO behavior, never cached by a shared cache).
		cacheable, evidence := genuinelyCacheable(respObj.Header.Get, respObj.StatusCode, probe.headerName)
		if !cacheable {
			resp.Close()
			continue
		}

		// Reflection-tracking confirmation: a generic value — notably
		// X-Forwarded-Port: 1337 — routinely appears in a body by coincidence (an
		// asset/chunk hash, a story id, a timestamp), so a single substring hit is
		// NOT proof the unkeyed header is reflected. Re-inject the header with fresh,
		// distinct values and require each to reflect the same way; a value that
		// truly flows from the header into the response tracks the change, while a
		// coincidental static match cannot. Fail OPEN on a transport error (err !=
		// nil) so a transient failure never suppresses a genuine finding.
		if tracked, err := m.confirmReflectionTracks(ctx, httpClient, probe); err == nil && !tracked {
			resp.Close()
			continue
		}

		where := "response body"
		if !reflectedInBody {
			where = "Location header"
		}

		results = append(results, &output.ResultEvent{
			URL:      urlx.String(),
			Request:  string(modifiedRaw),
			Response: resp.FullResponseString(),
			ExtractedResults: []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, probe.value),
				"Reflected in " + where,
				"Cacheable: " + evidence,
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Web Cache Poisoning: %s", probe.headerName),
				Description: probe.desc,
			},
		})
		resp.Close()
		return results, nil
	}

	return results, nil
}

// probeReflected reports whether value is reflected in the response body and/or
// the Location header the way the probe cares about. A host-shaped probe poisons a
// shared cache only when its value becomes the AUTHORITY of a cached URL (a
// link/script src/redirect other users load), so it is matched in authority
// position — not as an incidental substring inside a query value whose real
// destination is unchanged (the continue=/redirect_uri= false positive the
// host-trust modules guard). Other probes (scheme, path override, port, language)
// reflect verbatim, so a plain substring match is correct.
func probeReflected(probe cacheProbe, value, body, location string) (inBody, inLocation bool) {
	if probe.hostShaped {
		return modkit.HostReflectedAsAuthority(body, value), modkit.HostReflectedAsAuthority(location, value)
	}
	return strings.Contains(body, value), strings.Contains(location, value)
}

// confirmReflectionTracks re-injects probe.headerName with FRESH, distinct values
// (probe.newConfirmValue) and requires each to reflect the same way the primary
// value did. A value that genuinely flows from the unkeyed header into the
// (already-confirmed cacheable) response tracks the change every round; a
// coincidental static substring — the generic X-Forwarded-Port: 1337 matching a
// CSS/chunk hash or story id already in the page — does not, so two independent
// fresh values both reflecting is decisive. Each request bypasses the response
// cache (NoClustering) so every round is a genuinely fresh observation.
//
// It delegates the round loop to modkit.ConfirmReflectionWithValue, supplying the
// probe's value generator: err != nil signals a transport/parse failure so the
// caller fails OPEN (keeps the finding). A probe with no newConfirmValue carries a
// long unique sentinel whose coincidental collision is negligible, so it is treated
// as already confirmed.
func (m *Module) confirmReflectionTracks(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	probe cacheProbe,
) (bool, error) {
	if probe.newConfirmValue == nil {
		return true, nil
	}
	return modkit.ConfirmReflectionWithValue(2, probe.newConfirmValue, func(value string) (bool, error) {
		raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, value)
		if err != nil {
			return false, err
		}
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
		if err != nil {
			return false, err
		}
		respObj := resp.Response()
		if respObj == nil {
			resp.Close()
			return false, fmt.Errorf("cache-poisoning confirmation: nil response")
		}
		inBody, inLoc := probeReflected(probe, value, resp.Body().String(), respObj.Header.Get("Location"))
		resp.Close()
		return inBody || inLoc, nil
	})
}

// freshPort returns a fresh, pseudo-random high TCP port as a string, used as a
// reflection-tracking confirmation value for the X-Forwarded-Port probe. It stays
// numeric so a port-validating origin still echoes it, and the range (20000-64535)
// keeps it well clear of the primary 1337 probe and of common service ports. A
// lock-free PRNG is enough: the only requirement is that successive values differ,
// which makes two coincidental matches astronomically unlikely.
func freshPort() string {
	return strconv.Itoa(20000 + mrand.IntN(44536))
}

// genuinelyCacheable reports whether a response is one a shared cache would
// actually store — and therefore could be poisoned — along with a short evidence
// string. It replaces the original heuristic, which marked any response lacking
// Cache-Control: no-store/private as cacheable and so fired on directive-less
// 302 redirects (the root of the X-Forwarded-Host-in-Location false positive). A
// reflected header value only matters when the response carrying it is stored
// and replayed to other users.
func genuinelyCacheable(get func(string) string, status int, injectedHeader string) (bool, string) {
	if get == nil {
		return false, ""
	}

	// Per-user (Set-Cookie) or explicitly-uncacheable responses are never stored
	// by a well-behaved shared cache.
	if get("Set-Cookie") != "" {
		return false, ""
	}
	cc := strings.ToLower(get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return false, ""
	}

	// Vary: * is uncacheable; a Vary that already keys on the injected header
	// means the cache is keyed by it — so the header is not "unkeyed" and the
	// response cannot be poisoned through it.
	vary := strings.ToLower(get("Vary"))
	if strings.Contains(vary, "*") {
		return false, ""
	}
	if injectedHeader != "" && strings.Contains(vary, strings.ToLower(injectedHeader)) {
		return false, ""
	}

	// Strongest signal: the edge already served this from its cache.
	if c := infra.CacheState(get); c.Hit {
		return true, c.Evidence
	}

	// Otherwise require an explicit directive that authorizes shared caching; the
	// mere absence of no-store is not enough.
	positive := strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") || hasPositiveMaxAge(cc)

	// 3xx redirects are the common false-positive surface: 302/307 are not
	// heuristically cacheable, and 301/308 routinely reflect Host/forwarded
	// headers into a continue/return URL. Trust a cached redirect only when an
	// explicit directive marks it cacheable.
	if status >= 300 && status < 400 {
		if positive {
			return true, "redirect cacheable via Cache-Control: " + get("Cache-Control")
		}
		return false, ""
	}

	if positive {
		return true, "Cache-Control: " + get("Cache-Control")
	}
	return false, ""
}

// hasPositiveMaxAge reports whether a lowercased Cache-Control value carries
// max-age=N with N > 0. A max-age of 0 means "must revalidate" and is not a
// storable directive for our purposes. (s-maxage is checked separately by the
// caller; "max-age=" is not a substring of "s-maxage=".)
func hasPositiveMaxAge(cc string) bool {
	idx := strings.Index(cc, "max-age=")
	if idx < 0 {
		return false
	}
	rest := cc[idx+len("max-age="):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return false
	}
	n, err := strconv.Atoi(rest[:end])
	return err == nil && n > 0
}
