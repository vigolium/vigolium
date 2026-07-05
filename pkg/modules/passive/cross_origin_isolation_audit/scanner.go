package cross_origin_isolation_audit

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements the Cross-Origin Isolation Headers passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new module instance.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("cross_origin_isolation_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost flags authenticated responses missing COOP/CORP. It runs once per
// host and only on an authenticated, document-like response so it doesn't fire on
// static assets or unauthenticated pages.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil || ctx.Request() == nil {
		return nil, nil
	}
	resp := ctx.Response()

	// Only document/JSON responses carry XS-Leak-relevant content.
	ct := strings.ToLower(resp.Header("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	// Authenticated gate: the response sets a session cookie OR the request carried
	// credentials (Authorization or a Cookie). Unauthenticated pages are not the
	// XS-Leaks target and would only add noise.
	if !isAuthenticated(ctx) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(urlx.Host) {
		return nil, nil
	}

	var missing []string
	if resp.Header("Cross-Origin-Opener-Policy") == "" {
		missing = append(missing, "Cross-Origin-Opener-Policy (COOP) — recommended: same-origin")
	}
	if resp.Header("Cross-Origin-Resource-Policy") == "" {
		missing = append(missing, "Cross-Origin-Resource-Policy (CORP) — recommended: same-origin")
	}
	if len(missing) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: append([]string{"missing cross-origin isolation headers on an authenticated response"}, missing...),
		Info: output.Info{
			Name:        "Cross-Origin Isolation Headers Missing",
			Description: "This authenticated response omits " + strings.Join(missing, " and ") + ". These headers block cross-site leak (XS-Leaks) oracles (window-reference probing, embedding, error/timing/cache side channels). Set COOP: same-origin and CORP: same-origin on authenticated responses.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// isAuthenticated reports whether the transaction carries an authentication
// signal: a Set-Cookie session cookie on the response, or an Authorization/Cookie
// header on the request.
func isAuthenticated(ctx *httpmsg.HttpRequestResponse) bool {
	req := ctx.Request()
	if req.Header("Authorization") != "" {
		return true
	}
	if c := req.Header("Cookie"); c != "" && looksSessioned(c) {
		return true
	}
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") && looksSessioned(h.Value) {
			return true
		}
	}
	return false
}

// looksSessioned reports whether a cookie string carries an auth/session marker.
func looksSessioned(cookie string) bool {
	lc := strings.ToLower(cookie)
	return strings.Contains(lc, "sess") || strings.Contains(lc, "sid") ||
		strings.Contains(lc, "token") || strings.Contains(lc, "auth")
}
