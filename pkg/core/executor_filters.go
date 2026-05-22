package core

import (
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func filterActiveModulesByScanScope(mods []modules.ActiveModule, scope modules.ScanScope) []modules.ActiveModule {
	var result []modules.ActiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
}

func filterPassiveModulesByScanScope(mods []modules.PassiveModule, scope modules.ScanScope) []modules.PassiveModule {
	var result []modules.PassiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
}

// modulePriority returns the priority of a module. Lower values = higher priority.
// Modules implementing the Prioritized interface declare their own priority;
// others default to DefaultModulePriority (100).
func modulePriority(m modules.Module) int {
	if p, ok := m.(modules.Prioritized); ok {
		return p.Priority()
	}
	return modkit.DefaultModulePriority
}

// sortActiveByPriority sorts active modules by priority (lower = higher priority).
// Uses stable sort to preserve registration order for modules with equal priority.
func sortActiveByPriority(mods []modules.ActiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return modulePriority(mods[i]) < modulePriority(mods[j])
	})
}

// filterNonScopeAware removes passive modules that declared themselves as
// scope-aware. Called when the current item is out of scope so that only
// modules that explicitly want all traffic (e.g., fingerprinting) still run.
func filterNonScopeAware(mods []modules.PassiveModule) []modules.PassiveModule {
	out := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if sa, ok := m.(modules.ScopeAwareModule); ok && sa.ScopeAware() {
			continue
		}
		out = append(out, m)
	}
	return out
}

func paramFindingLocationKeyFromItem(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if urlx, err := item.URL(); err == nil && urlx != nil {
		return normalizeParamFindingLocation(urlx.Scheme, urlx.Host, urlx.Path)
	}
	if item.Request() != nil {
		host, _ := httpmsg.GetHeaderValue(item.Request().Raw(), "Host")
		return normalizeParamFindingLocation("", host, item.Request().Path())
	}
	return ""
}

func paramFindingLocationKeyFromResult(result *output.ResultEvent) string {
	if result == nil {
		return ""
	}
	if result.URL != "" {
		if parsed, err := url.Parse(result.URL); err == nil {
			return normalizeParamFindingLocation(parsed.Scheme, parsed.Host, parsed.Path)
		}
	}
	if result.Matched != "" {
		if parsed, err := url.Parse(result.Matched); err == nil && parsed.Host != "" {
			return normalizeParamFindingLocation(parsed.Scheme, parsed.Host, parsed.Path)
		}
	}
	if result.Request != "" {
		host, _ := httpmsg.GetHeaderValue([]byte(result.Request), "Host")
		path, _ := httpmsg.GetPath([]byte(result.Request))
		return normalizeParamFindingLocation(result.Scheme, host, path)
	}
	return normalizeParamFindingLocation(result.Scheme, result.Host, "")
}

func normalizeParamFindingLocation(scheme, host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if scheme == "" {
		return host + path
	}
	return scheme + "://" + host + path
}
