package network

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ToHttpRequestResponse converts a TrafficEntry captured by CDP into
// vigolium's httpmsg.HttpRequestResponse by building raw HTTP request/response bytes.
func ToHttpRequestResponse(entry *TrafficEntry) (*httpmsg.HttpRequestResponse, error) {
	if entry == nil {
		return nil, fmt.Errorf("nil TrafficEntry")
	}

	parsedURL, err := url.Parse(entry.Request.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", entry.Request.URL, err)
	}

	// Build raw HTTP request
	rawReq := buildRawRequest(entry, parsedURL)

	// Determine service info (host, port, scheme)
	host := parsedURL.Hostname()
	port := defaultPort(parsedURL)
	isHTTPS := parsedURL.Scheme == "https"

	service := httpmsg.NewServiceSecure(host, port, isHTTPS)
	httpReq := httpmsg.NewHttpRequestWithService(service, rawReq)

	// Build response if present
	var httpResp *httpmsg.HttpResponse
	if entry.Response != nil {
		rawResp := buildRawResponse(entry)
		httpResp = httpmsg.NewHttpResponse(rawResp)
	}

	return httpmsg.NewHttpRequestResponse(httpReq, httpResp), nil
}

// buildRawRequest constructs raw HTTP/1.1 request bytes from TrafficEntry fields.
func buildRawRequest(entry *TrafficEntry, u *url.URL) []byte {
	var b strings.Builder

	// Request line: METHOD /path?query HTTP/1.1
	pathAndQuery := u.RequestURI()
	b.WriteString(entry.Request.Method)
	b.WriteByte(' ')
	b.WriteString(pathAndQuery)
	b.WriteString(" HTTP/1.1\r\n")

	// Host header (always first)
	b.WriteString("Host: ")
	b.WriteString(u.Host)
	b.WriteString("\r\n")

	// Other headers (skip Host since we already wrote it)
	for k, v := range entry.Request.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}

	// End of headers
	b.WriteString("\r\n")

	// Body
	if len(entry.Request.Body) > 0 {
		b.Write(entry.Request.Body)
	}

	return []byte(b.String())
}

// buildRawResponse constructs raw HTTP/1.1 response bytes from TrafficEntry fields.
func buildRawResponse(entry *TrafficEntry) []byte {
	if entry.Response == nil {
		return nil
	}

	var b strings.Builder

	// Status line
	b.WriteString("HTTP/1.1 ")
	b.WriteString(strconv.Itoa(entry.Response.Status))
	b.WriteByte(' ')
	b.WriteString(statusText(entry.Response.Status))
	b.WriteString("\r\n")

	// Headers
	if entry.Response.Headers != nil {
		for k, v := range entry.Response.Headers {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}

	// End of headers
	b.WriteString("\r\n")

	// Body
	if len(entry.Response.Body) > 0 {
		b.Write(entry.Response.Body)
	}

	return []byte(b.String())
}

// defaultPort returns the port as int from a parsed URL (80 for http, 443 for https).
func defaultPort(u *url.URL) int {
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err == nil {
			return p
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// statusText returns a short text for common HTTP status codes.
func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}
