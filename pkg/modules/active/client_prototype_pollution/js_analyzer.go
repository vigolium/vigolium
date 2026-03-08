package client_prototype_pollution

import (
	"net/url"
	"regexp"
	"strings"
)

// scriptBlockRe matches <script> blocks and captures their content.
var scriptBlockRe = regexp.MustCompile(`(?si)<script[^>]*>(.*?)</script>`)

// scriptSrcRe matches <script src="..."> and captures the URL.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]*\bsrc=["']([^"']+)["']`)

// cdnDomains contains known CDN domains to skip (not custom code).
var cdnDomains = []string{
	"cdnjs.cloudflare.com",
	"unpkg.com",
	"jsdelivr.net",
	"cdn.jsdelivr.net",
	"ajax.googleapis.com",
	"code.jquery.com",
	"stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com",
	"cdn.bootcss.com",
	"cdn.bootcdn.net",
	"libs.baidu.com",
}

// extractInlineScripts extracts JavaScript content from inline <script> blocks.
// It skips script tags that have a src attribute (those are external).
func extractInlineScripts(htmlBody string) []string {
	matches := scriptBlockRe.FindAllStringSubmatch(htmlBody, -1)
	var scripts []string
	for _, m := range matches {
		// m[0] is the full match, m[1] is the script content
		// Skip scripts with src= (external scripts fetched separately)
		tagEnd := strings.Index(m[0], ">")
		if tagEnd == -1 {
			continue
		}
		openTag := m[0][:tagEnd]
		if strings.Contains(openTag, "src=") {
			continue
		}
		content := strings.TrimSpace(m[1])
		if content != "" {
			scripts = append(scripts, content)
		}
	}
	return scripts
}

// extractExternalScriptURLs extracts src URLs from <script> tags.
func extractExternalScriptURLs(htmlBody string) []string {
	matches := scriptSrcRe.FindAllStringSubmatch(htmlBody, -1)
	var urls []string
	for _, m := range matches {
		if m[1] != "" {
			urls = append(urls, m[1])
		}
	}
	return urls
}

// isCDNURL checks if a URL belongs to a known CDN domain.
func isCDNURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Host)
	for _, cdn := range cdnDomains {
		if host == cdn || strings.HasSuffix(host, "."+cdn) {
			return true
		}
	}
	return false
}

// resolveScriptURL resolves a potentially relative script URL against the page URL.
func resolveScriptURL(pageURL, scriptSrc string) string {
	if strings.HasPrefix(scriptSrc, "http://") || strings.HasPrefix(scriptSrc, "https://") {
		return scriptSrc
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return scriptSrc
	}
	ref, err := url.Parse(scriptSrc)
	if err != nil {
		return scriptSrc
	}
	return base.ResolveReference(ref).String()
}
