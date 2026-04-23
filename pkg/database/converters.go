package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/anomaly/htmlutils"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// dnsCache caches hostname → IP resolution results to avoid repeated lookups.
// A zero-value (empty string) means the lookup was attempted but failed.
var dnsCache = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// resolveHostnameIP resolves a hostname to its first IPv4 (or IPv6) address,
// caching the result so subsequent calls for the same hostname skip DNS.
// Returns empty string on failure (also cached to avoid repeated failures).
func resolveHostnameIP(hostname string) string {
	// Check cache first (fast path)
	dnsCache.RLock()
	ip, found := dnsCache.m[hostname]
	dnsCache.RUnlock()
	if found {
		return ip
	}

	// If the hostname is already an IP address, cache and return it directly
	if parsed := net.ParseIP(hostname); parsed != nil {
		dnsCache.Lock()
		dnsCache.m[hostname] = hostname
		dnsCache.Unlock()
		return hostname
	}

	// Resolve via DNS
	addrs, err := net.LookupHost(hostname)
	resolved := ""
	if err == nil && len(addrs) > 0 {
		resolved = addrs[0]
	}

	// Cache the result (including empty string for failed lookups)
	dnsCache.Lock()
	dnsCache.m[hostname] = resolved
	dnsCache.Unlock()

	return resolved
}

// FromHttpRequestResponse populates an HTTPRecord from httpmsg.HttpRequestResponse
func (r *HTTPRecord) FromHttpRequestResponse(ctx *httpmsg.HttpRequestResponse) error {
	if ctx == nil || ctx.Request() == nil {
		return fmt.Errorf("invalid HttpRequestResponse")
	}

	req := ctx.Request()
	u, err := ctx.URL()
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Generate UUID
	r.UUID = uuid.New().String()

	// Host info
	r.Scheme = u.Scheme
	r.Hostname = u.Hostname()
	port := 0
	if u.Port() != "" {
		_, _ = fmt.Sscanf(u.Port(), "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	r.Port = port

	// Resolve hostname to IP (cached per hostname)
	if ip := resolveHostnameIP(r.Hostname); ip != "" {
		r.IP = ip
	}

	// Request fields
	r.Method = req.Method()
	r.Path = req.Path()
	r.HTTPVersion = "HTTP/1.1"
	r.URL = u.String()

	// Request body metadata (derived from parsed request, not persisted)
	r.RequestContentType = req.Header("Content-Type")
	r.RequestContentLength = int64(len(req.Body()))

	// Request authorization (prefer Authorization header, fall back to Cookie)
	if auth := req.Header("Authorization"); auth != "" {
		r.RequestAuthorization = auth
	} else if cookie := req.Header("Cookie"); cookie != "" {
		r.RequestAuthorization = cookie
	}

	// Raw request data (single source of truth for body + headers)
	r.RawRequest = req.Raw()

	// Request hash
	hash := sha256.Sum256(r.RawRequest)
	r.RequestHash = hex.EncodeToString(hash[:])

	// Response (if available)
	if ctx.HasResponse() {
		resp := ctx.Response()
		r.HasResponse = true
		r.StatusCode = resp.StatusCode()
		r.ResponseHTTPVersion = extractResponseHTTPVersion(resp.Raw())

		r.ResponseContentType = resp.Header("Content-Type")
		r.ResponseContentLength = int64(len(resp.Body()))
		r.RawResponse = resp.Raw()

		// Derive title/word-count from parsed response (in-memory only, not persisted)
		respBody := resp.Body()
		if strings.Contains(strings.ToLower(r.ResponseContentType), "html") {
			r.ResponseTitle = extractHTMLTitle(respBody)
		}
		r.ResponseWords = countResponseWords(respBody, resp.Headers())

		respHash := sha256.Sum256(r.RawResponse)
		r.ResponseHash = hex.EncodeToString(respHash[:])

		r.ReceivedAt = time.Now()
	}

	// Parameters
	params, err := req.Parameters()
	if err == nil && len(params) > 0 {
		r.Parameters = make([]EmbeddedParam, 0, len(params))
		for _, p := range params {
			r.Parameters = append(r.Parameters, EmbeddedParam{
				Name:       p.Name(),
				Value:      p.Value(),
				Type:       ParameterTypeFromParamType(p.Type()),
				NameStart:  p.NameStart(),
				NameEnd:    p.NameEnd(),
				ValueStart: p.ValueStart(),
				ValueEnd:   p.ValueEnd(),
			})
		}
	}

	// Timestamps
	r.SentAt = time.Now()

	return nil
}

// FromResultEvent converts output.ResultEvent to Finding
func (f *Finding) FromResultEvent(event *output.ResultEvent) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}

	f.ModuleID = event.ModuleID
	f.ModuleName = event.Info.Name
	f.Description = event.Info.Description
	f.Severity = event.Info.Severity.String()
	f.Confidence = event.Info.Confidence.String()
	f.Tags = event.Info.Tags

	f.URL = firstNonEmpty(event.URL, event.Matched)
	f.Hostname = resolveFindingHostname(event.Host, event.URL, event.Matched)

	if event.Matched != "" {
		f.MatchedAt = []string{event.Matched}
	}
	f.ExtractedResults = event.ExtractedResults

	f.Request = event.Request
	f.Response = event.Response
	f.AdditionalEvidence = event.AdditionalEvidence
	f.ModuleType = event.ModuleType
	f.FindingSource = event.FindingSource
	f.ModuleShort = event.ModuleShort

	f.FindingHash = event.ID()
	f.FoundAt = time.Now()

	// Native scan results come from deterministic engines — they're trusted by
	// default and skip the triage queue. Caller may override (e.g. user import).
	f.Status = StatusTriaged

	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveFindingHostname picks the hostname for a finding, preferring the
// explicit Host field on the event, then parsing the URL or matched-at value.
func resolveFindingHostname(host, url, matched string) string {
	if host != "" {
		return host
	}
	for _, candidate := range []string{url, matched} {
		if candidate == "" {
			continue
		}
		if parsed, err := neturl.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return ""
}

// extractResponseHTTPVersion extracts the HTTP version from the raw response status line.
// Falls back to "HTTP/1.1" if parsing fails.
func extractResponseHTTPVersion(raw []byte) string {
	if len(raw) == 0 {
		return "HTTP/1.1"
	}
	// Find end of first line (status line)
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		end = len(raw)
	}
	line := string(raw[:end])
	// Status line format: "HTTP/1.1 200 OK" — version is the first space-delimited token
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		version := strings.TrimSpace(line[:idx])
		if strings.HasPrefix(version, "HTTP/") {
			return version
		}
	}
	return "HTTP/1.1"
}

// extractHTMLTitle parses the <title> element from an HTML body.
// Returns empty string on parse failure or missing title. Caps at 512 chars.
func extractHTMLTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	doc, err := htmlutils.FastParse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	tags := htmlutils.GetElementsByTagName(doc, "title")
	if len(tags) == 0 {
		return ""
	}
	title := strings.TrimSpace(htmlutils.TextContent(tags[0]))
	if len(title) > 512 {
		title = title[:512]
	}
	return title
}

// countResponseWords counts whitespace-delimited words in the response body and headers.
// Uses byte-level scanning to avoid allocating a string copy or []string slice.
func countResponseWords(body []byte, headers []httpmsg.HttpHeader) int64 {
	count := int64(countWordsBytes(body))
	for _, h := range headers {
		count += int64(countWordsString(h.Name))
		count += int64(countWordsString(h.Value))
	}
	return count
}

// countWordsBytes counts whitespace-delimited words in a byte slice without allocations.
func countWordsBytes(b []byte) int {
	n := 0
	inWord := false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// countWordsString counts whitespace-delimited words in a string without allocations.
func countWordsString(s string) int {
	n := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// ParameterTypeFromParamType converts ParamType to database parameter type string
func ParameterTypeFromParamType(ptype httpmsg.ParamType) string {
	switch ptype {
	case httpmsg.ParamURL:
		return "url"
	case httpmsg.ParamBody, httpmsg.ParamBodyMultipart:
		return "body"
	case httpmsg.ParamJSON:
		return "json"
	case httpmsg.ParamXML, httpmsg.ParamXMLAttr:
		return "xml"
	case httpmsg.ParamCookie:
		return "cookie"
	case httpmsg.ParamPathFolder, httpmsg.ParamPathFilename:
		return "path"
	case httpmsg.ParamMultipartAttr:
		return "multipart"
	default:
		return "unknown"
	}
}
