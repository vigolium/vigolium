package infra

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
	urlutil "github.com/projectdiscovery/utils/url"
)

// IsValidForInjectionVulns checks if the URL is valid for injection vulnerability testing.
// Deprecated: Filtering is now handled per-module via CanProcess() method.
// This function remains for backward compatibility with existing modules.
func IsValidForInjectionVulns(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse) bool {
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Request().Method() == "OPTIONS" || ctx.Request().Method() == "CONNECT" {
		return false
	}
	return true
}
