package infra

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
	urlutil "github.com/projectdiscovery/utils/url"
)

// IsValidForInjectionVulns checks if the URL is valid for injection vulnerability testing.
// Rejects media/JS URLs and OPTIONS/CONNECT methods.
func IsValidForInjectionVulns(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse) bool {
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Request().Method() == "OPTIONS" || ctx.Request().Method() == "CONNECT" {
		return false
	}
	return true
}
