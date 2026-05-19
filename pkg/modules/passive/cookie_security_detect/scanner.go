package cookie_security_detect

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the Cookie Security Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Cookie Security Detect module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		rhm: dedup.LazyDefaultRHM("passive_cookie_security_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes Set-Cookie headers for insecure attributes.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Collect Set-Cookie header values from response headers
	var setCookies []string
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			setCookies = append(setCookies, h.Value)
		}
	}

	if len(setCookies) == 0 {
		return nil, nil
	}

	isHTTPS := strings.EqualFold(urlx.Scheme, "https")

	var results []*output.ResultEvent

	for _, cookie := range setCookies {
		cookieLower := strings.ToLower(cookie)

		// Extract cookie name
		cookieName := cookie
		if idx := strings.Index(cookie, "="); idx > 0 {
			cookieName = cookie[:idx]
		}

		var issues []string

		if isHTTPS && !strings.Contains(cookieLower, "secure") {
			issues = append(issues, "Missing Secure flag")
		}

		if !strings.Contains(cookieLower, "httponly") {
			issues = append(issues, "Missing HttpOnly flag")
		}

		if !strings.Contains(cookieLower, "samesite") {
			issues = append(issues, "Missing SameSite attribute")
		}

		if len(issues) > 0 {
			results = append(results, &output.ResultEvent{
				Host: urlx.Host,
				URL:  urlx.String(),
				ExtractedResults: []string{
					fmt.Sprintf("Cookie: %s", cookieName),
					fmt.Sprintf("Issues: %s", strings.Join(issues, ", ")),
				},
				Info: output.Info{
					Description: fmt.Sprintf("Cookie %q: %s", cookieName, strings.Join(issues, ", ")),
				},
			})
		}
	}

	return results, nil
}
