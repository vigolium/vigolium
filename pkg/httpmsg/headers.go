package httpmsg

// DefaultBrowserHeaders are headers that mimic a real Chrome browser.
// Applied if not already present in the request.
var DefaultBrowserHeaders = map[string]string{
	"Cache-Control":      "max-age=0",
	"Sec-Ch-Ua":          `"Google Chrome";v="143", "Not=A?Brand";v="8", "Chromium";v="143"`,
	"Sec-Ch-Ua-Mobile":   "?0",
	"Sec-Ch-Ua-Platform": `"macOS"`,
	"Accept-Language":    "en-US;q=0.9,en;q=0.8",
	"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
	"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Sec-Fetch-Site":     "none",
	"Sec-Fetch-Mode":     "navigate",
	"Sec-Fetch-User":     "?1",
	"Sec-Fetch-Dest":     "document",
	"Accept-Encoding":    "gzip, deflate, br",
}

// DefaultBrowserHeadersOrder defines the canonical order for browser headers.
// This ensures requests look natural/realistic.
var DefaultBrowserHeadersOrder = []string{
	"Cache-Control",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Accept-Language",
	"User-Agent",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Accept-Encoding",
}
