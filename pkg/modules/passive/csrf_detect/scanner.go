package csrf_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// csrfParamPattern matches common CSRF token parameter names.
var csrfParamPattern = regexp.MustCompile(`(?i)(csrf|xsrf|token|authenticity.token|__RequestVerificationToken|antiforgery|_token|nonce|csrfmiddlewaretoken)`)

// csrfHeaderPattern matches custom headers used for CSRF protection.
var csrfHeaderPattern = regexp.MustCompile(`(?i)^(x-csrf-token|x-xsrf-token|x-requested-with|x-csrftoken|anti-csrf-token)$`)

// sameSitePattern matches SameSite cookie attribute with Strict or Lax.
var sameSitePattern = regexp.MustCompile(`(?i)samesite=(strict|lax)`)

// stateChangingMethods are HTTP methods that modify server state.
var stateChangingMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
}

// Module implements passive CSRF detection.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSRF detection passive module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("csrf_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes state-changing requests for missing CSRF protections.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only check state-changing methods
	method := strings.ToUpper(ctx.Request().Method())
	if !stateChangingMethods[method] {
		return nil, nil
	}

	// Skip JSON APIs with Origin header (CORS-protected)
	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	origin := ctx.Request().Header("Origin")
	if strings.Contains(ct, "application/json") && origin != "" {
		return nil, nil
	}

	// Dedup by method:host:path
	dedupKey := utils.Sha1(fmt.Sprintf("%s:%s:%s", method, urlx.Host, urlx.Path))
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Check 1: CSRF token in parameters
	params, err := ctx.Request().Parameters()
	if err == nil {
		for _, param := range params {
			if csrfParamPattern.MatchString(param.Name()) {
				return nil, nil // has CSRF token
			}
		}
	}

	// Check 2: CSRF header
	rawReq := string(ctx.Request().Raw())
	for _, line := range strings.Split(rawReq, "\n") {
		if idx := strings.Index(line, ":"); idx > 0 {
			headerName := strings.TrimSpace(line[:idx])
			if csrfHeaderPattern.MatchString(headerName) {
				return nil, nil // has CSRF header
			}
		}
	}

	// Check 3: SameSite cookie in response
	if ctx.HasResponse() {
		for _, hdr := range ctx.Response().Headers() {
			if strings.EqualFold(hdr.Name, "Set-Cookie") {
				if sameSitePattern.MatchString(hdr.Value) {
					return nil, nil // has SameSite protection
				}
			}
		}
	}

	// No CSRF protection found
	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			Info: output.Info{
				Name:        "Missing CSRF Protection",
				Description: fmt.Sprintf("State-changing %s request to %s lacks anti-CSRF token, custom header, and SameSite cookie protection", method, urlx.Path),
				Severity:    severity.Medium,
				Confidence:  severity.Tentative,
				Tags:        []string{"csrf", "session", "web-security"},
				Reference:   []string{"https://owasp.org/www-community/attacks/csrf"},
			},
			Metadata: map[string]any{
				"method": method,
				"path":   urlx.Path,
			},
		},
	}, nil
}
