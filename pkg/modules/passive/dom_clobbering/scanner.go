package dom_clobbering

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// clobberSinkRe matches a sink assignment sourced from a named-property global:
// e.g. `script.src = window.config`, `el.innerHTML = document.data`,
// `location.href = window.next`. The captured group is the global's property name,
// which is then checked against the standard-DOM set (a real gadget reads a
// custom, clobberable name — location/cookie/etc. are legitimate).
var clobberSinkRe = regexp.MustCompile(`(?is)(?:[\w$][\w$.]*\.(?:src|href|innerHTML|outerHTML|action)|location(?:\.href)?)\s*=\s*(?:window|document|self|top)\.([a-zA-Z_$][\w$]*)`)

// standardDOMProps are legitimate window/document properties; reading them is not a
// clobbering gadget. Matched lowercased.
var standardDOMProps = map[string]struct{}{
	"location": {}, "cookie": {}, "referrer": {}, "url": {}, "documenturi": {},
	"baseuri": {}, "title": {}, "body": {}, "head": {}, "documentelement": {},
	"forms": {}, "images": {}, "links": {}, "scripts": {}, "domain": {},
	"readystate": {}, "activeelement": {}, "currentscript": {}, "defaultview": {},
	"all": {}, "anchors": {}, "embeds": {}, "plugins": {}, "stylesheets": {},
	"name": {}, "top": {}, "self": {}, "parent": {}, "opener": {}, "length": {},
	"closed": {}, "frames": {}, "history": {}, "navigator": {}, "screen": {},
	"localstorage": {}, "sessionstorage": {}, "document": {}, "window": {},
	"innerheight": {}, "innerwidth": {}, "scrollx": {}, "scrolly": {}, "origin": {},
}

// Module implements the DOM Clobbering passive scanner.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("dom_clobbering"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest flags a sink assigned from a non-standard named-property global.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "javascript") {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	var gadgets []string
	seen := map[string]struct{}{}
	for _, mm := range clobberSinkRe.FindAllStringSubmatch(body, -1) {
		if len(mm) < 2 {
			continue
		}
		name := mm[1]
		if _, std := standardDOMProps[strings.ToLower(name)]; std {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		gadgets = append(gadgets, strings.TrimSpace(mm[0]))
		if len(gadgets) >= 8 {
			break
		}
	}
	if len(gadgets) == 0 {
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

	extracted := append([]string{fmt.Sprintf("%d DOM-clobbering gadget(s)", len(gadgets))}, gadgets...)
	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "DOM Clobbering Gadget (sink fed from named global)",
			Description: "JavaScript on this page assigns a dangerous sink (script.src/href/innerHTML/location) from a non-standard named-property global (window.X / document.X). If an HTML-injection point exists, an attacker can inject an element with a matching id/name to clobber that global and redirect the sink to attacker-controlled data. Confirm the global's origin and add a type check / trusted reference.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}
