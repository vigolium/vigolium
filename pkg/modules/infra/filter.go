package infra

import (
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
)

// IsValidForInjectionVulns checks if the URL is valid for injection vulnerability testing.
// Rejects media/JS URLs and OPTIONS/CONNECT methods.
func IsValidForInjectionVulns(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse) bool {
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Request().Method() == "OPTIONS" || ctx.Request().Method() == "CONNECT" {
		return false
	}
	return true
}

// urlParamNames are parameter-name fragments that suggest the value is a URL the
// server may fetch or redirect to. Package-level so it is allocated once, not per
// call.
var urlParamNames = []string{
	"url", "uri", "link", "src", "href", "dest", "redirect",
	"path", "file", "page", "target", "callback", "endpoint",
	"resource", "fetch", "load", "proxy", "request",
}

// LooksLikeURLParam reports whether a parameter — by its name or its current
// value — looks like it accepts a URL. Shared by the SSRF / SSRF-bypass modules
// so they target the same parameter surface.
func LooksLikeURLParam(name, value string) bool {
	nameLower := strings.ToLower(name)
	for _, n := range urlParamNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}
	return strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "//")
}
