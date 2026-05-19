package httpmsg

import (
	"strings"
	"sync"
)

// BuiltinUserAgent is the Chrome-like User-Agent used for every outgoing
// scanner request unless overridden via config. It is intentionally a real
// browser string so requests look natural and survive naive WAF filtering.
const BuiltinUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

// versionPlaceholder is replaced with the running binary version inside a
// configured User-Agent. Lets operators pin a stable identifier
// (e.g. "Vigolium/{version}") that stays correct across upgrades.
const versionPlaceholder = "{version}"

var (
	uaMu         sync.RWMutex
	uaOverride   string // empty => use BuiltinUserAgent
	buildVersion string // set once at startup from the CLI layer
)

// SetDefaultUserAgent installs a process-global User-Agent override applied to
// every outgoing HTTP request across all scan phases. An empty/blank value is
// ignored so the built-in Chrome default is preserved (pure opt-in). Safe for
// concurrent use; last writer wins.
func SetDefaultUserAgent(ua string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return
	}
	uaMu.Lock()
	uaOverride = ua
	uaMu.Unlock()
}

// SetBuildVersion records the running binary version so a configured
// User-Agent containing the {version} placeholder resolves correctly. Called
// once from the CLI layer (httpmsg cannot import the version, that would cycle).
func SetBuildVersion(v string) {
	v = strings.TrimSpace(v)
	uaMu.Lock()
	buildVersion = v
	uaMu.Unlock()
}

// DefaultUserAgent returns the effective User-Agent: the configured override
// (with {version} expanded) when set, otherwise the built-in Chrome string.
func DefaultUserAgent() string {
	uaMu.RLock()
	ua, ver := uaOverride, buildVersion
	uaMu.RUnlock()

	if ua == "" {
		return BuiltinUserAgent
	}
	if strings.Contains(ua, versionPlaceholder) {
		if ver == "" {
			ver = "dev"
		}
		ua = strings.ReplaceAll(ua, versionPlaceholder, ver)
	}
	return ua
}
