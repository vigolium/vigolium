package csti_detection

import (
	"regexp"
	"sync"
)

// angularRe matches AngularJS indicators in HTML.
var angularRe = regexp.MustCompile(`(?i)(ng-app|ng-controller|ng-bind|data-ng-app|angular[.\-](?:min\.)?js)`)

// vueRe matches Vue.js indicators in HTML.
var vueRe = regexp.MustCompile(`(?i)(v-bind|v-model|v-if|v-for|vue[.\-](?:min\.)?js)`)

// svelteRe matches Svelte indicators in HTML.
var svelteRe = regexp.MustCompile(`(?i)(svelte[.\-](?:min\.)?js|__svelte_|svelte-kit)`)

// alpineRe matches Alpine.js indicators in HTML.
var alpineRe = regexp.MustCompile(`(?i)(x-data|x-bind|x-on|x-show|alpine[.\-](?:min\.)?js)`)

// scopeRe matches framework scope markers preceding the injection point.
var scopeRe = regexp.MustCompile(`(?i)(ng-app|data-ng-app|v-app|id="app"|x-data)`)

// frameworkInfo holds the detected framework name.
type frameworkInfo struct {
	Name string
}

// frameworkCache stores per-host framework detection results.
// Keys are host strings, values are *frameworkInfo or nil (stored as empty struct marker).
var frameworkCache sync.Map

// sentinel is stored to distinguish "checked but no framework" from "not checked".
type cacheEntry struct {
	info *frameworkInfo
}

// detectFramework inspects the HTML body for AngularJS or Vue.js indicators.
func detectFramework(body string) *frameworkInfo {
	if angularRe.MatchString(body) {
		return &frameworkInfo{Name: "AngularJS"}
	}
	if vueRe.MatchString(body) {
		return &frameworkInfo{Name: "Vue.js"}
	}
	if svelteRe.MatchString(body) {
		return &frameworkInfo{Name: "Svelte"}
	}
	if alpineRe.MatchString(body) {
		return &frameworkInfo{Name: "Alpine.js"}
	}
	return nil
}

// getFramework returns the cached framework info for the host,
// or detects and caches it on first call.
func getFramework(host, body string) *frameworkInfo {
	if v, ok := frameworkCache.Load(host); ok {
		return v.(*cacheEntry).info
	}
	info := detectFramework(body)
	frameworkCache.Store(host, &cacheEntry{info: info})
	return info
}

// isInsideFrameworkScope checks if the reflected payload appears
// within a framework-controlled DOM scope (e.g., inside an ng-app element).
func isInsideFrameworkScope(body, payload string) bool {
	idx := findIndex(body, payload)
	if idx == -1 {
		return false
	}
	start := 0
	if idx > 2000 {
		start = idx - 2000
	}
	preceding := body[start:idx]
	return scopeRe.MatchString(preceding)
}

// findIndex returns the index of the first occurrence of substr in s, or -1.
func findIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
