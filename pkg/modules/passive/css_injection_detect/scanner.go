package css_injection_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

var (
	styleBlockRe  = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)
	styleAttrDQRe = regexp.MustCompile(`(?is)\bstyle\s*=\s*"([^"]*)"`)
	styleAttrSQRe = regexp.MustCompile(`(?is)\bstyle\s*=\s*'([^']*)'`)
	// cssContextRes are the CSS-sink extractors, built once (not per response).
	cssContextRes   = []*regexp.Regexp{styleBlockRe, styleAttrDQRe, styleAttrSQRe}
	minReflectedLen = 8 // avoid coincidental short-value matches at Info severity
)

// Module implements the CSS Injection passive scanner.
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
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("css_injection_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest flags request parameter values reflected into a CSS context.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html") {
		return nil, nil
	}

	// Cheap gate first: only scan the body for CSS contexts when the request has a
	// parameter value long enough to be a meaningful reflection. Most HTML responses
	// have none, so this avoids three full-body regex passes on the hot path.
	params, err := ctx.Request().Parameters()
	if err != nil || len(params) == 0 {
		return nil, nil
	}
	hasCandidate := false
	for _, p := range params {
		if len(p.Value()) >= minReflectedLen {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return nil, nil
	}

	cssContexts := collectCSSContexts(ctx.Response().BodyToString())
	if len(cssContexts) == 0 {
		return nil, nil
	}

	var reflected []string
	seen := map[string]struct{}{}
	for _, p := range params {
		val := p.Value()
		if len(val) < minReflectedLen {
			continue
		}
		if _, dup := seen[p.Name()]; dup {
			continue
		}
		for _, css := range cssContexts {
			if strings.Contains(css, val) {
				reflected = append(reflected, fmt.Sprintf("%s=%s", p.Name(), val))
				seen[p.Name()] = struct{}{}
				break
			}
		}
	}
	if len(reflected) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := urlx.Host + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: reflected,
		Info: output.Info{
			Name:        "CSS Injection Surface (input reflected into CSS)",
			Description: fmt.Sprintf("%d request parameter value(s) are reflected inside a <style> block or style= attribute. If not contextually encoded, an attacker can inject CSS to exfiltrate data (attribute selectors + background:url()), overlay the page, or steal tokens via dangling markup. Verify the value is CSS-escaped.", len(reflected)),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// collectCSSContexts returns the text of every <style> block and style= attribute
// in the body — the CSS sinks where a reflected value is dangerous.
func collectCSSContexts(body string) []string {
	var out []string
	for _, re := range cssContextRes {
		for _, mm := range re.FindAllStringSubmatch(body, -1) {
			if len(mm) > 1 && strings.TrimSpace(mm[1]) != "" {
				out = append(out, mm[1])
			}
		}
	}
	return out
}
