package spider

import (
	"bufio"
	"bytes"
	"context"
	"net/url"
	"strings"
)

// RobotsTxtParser extracts URLs from robots.txt files.
//
// Parses Allow, Disallow, and Sitemap directives from robots.txt responses.
// Only processes responses where the URL path is /robots.txt.
//
// Burp mapping: c0c.java (Robots.txt parser)
type RobotsTxtParser struct {
	urlResolver *URLResolver
}

// NewRobotsTxtParser creates a new robots.txt parser.
func NewRobotsTxtParser(urlResolver *URLResolver) *RobotsTxtParser {
	return &RobotsTxtParser{
		urlResolver: urlResolver,
	}
}

// Extract examines a robots.txt response and reports discovered URLs.
//
// Only processes if response.URL path is /robots.txt.
// Parses plain text line by line, extracting:
//   - Allow: /path → https://host/path
//   - Disallow: /path → https://host/path
//   - Sitemap: https://example.com/sitemap.xml
//
// Ignores comments (#) and handles case-insensitive directive matching.
// For Allow/Disallow, also creates variant with trailing slash if not present.
//
// Burp mapping: c0c.a(hik var1, hkk var2, byte[] var3, fi3 var4) - Lines 16-89
func (p *RobotsTxtParser) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Only process robots.txt files
	// Burp mapping: Line 99-101: Check if URL path is "/robots.txt"
	if response.URL == nil || !isRobotsTxtURL(response.URL) {
		return nil
	}

	// Skip if body is empty
	if len(response.Body) == 0 {
		return nil
	}

	// Parse response body line by line
	// Burp mapping: Line 24: new BufferedReader()
	scanner := bufio.NewScanner(bytes.NewReader(response.Body))

	for scanner.Scan() {
		// Read next line
		// Burp mapping: Line 32: var7 = var10001.readLine()
		line := scanner.Text()

		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Strip leading # characters (comments)
		// Burp mapping: Lines 35-40: while (var7.startsWith("#"))
		for strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if line == "" {
				break
			}
		}

		// Skip if line became empty after comment removal
		if line == "" {
			continue
		}

		// Detect directive type (case-insensitive)
		// Burp mapping: Lines 43-66: Switch on lowercase directive
		directiveType, path := p.parseDirective(line)

		// Skip unrecognized directives
		if directiveType == directiveUnknown {
			continue
		}

		// Burp mapping: Lines 68-71: Strip inline comments
		path = p.stripInlineComment(path)
		if path == "" {
			continue
		}

		// Create link from path
		// Burp mapping: Lines 73-76: a(var0, var8, var1, var7, var4)
		p.createLink(baseURL, directiveType, path, callback)

		// For Allow/Disallow, also add variant with trailing slash if not present
		// Skip if path contains wildcards (Burp doesn't process them anyway)
		// Burp mapping: Lines 74-76: if (!var7.endsWith("/") && var8 == 4)
		if directiveType == directiveAllowDisallow && !strings.HasSuffix(path, "/") && !strings.Contains(path, "*") {
			p.createLink(baseURL, directiveType, path+"/", callback)
		}
	}

	return nil
}

// directiveType represents the type of robots.txt directive
type directiveType int

const (
	directiveUnknown       directiveType = 0
	directiveAllowDisallow directiveType = 4 // Allow or Disallow
	directiveSitemap       directiveType = 5 // Sitemap
)

// parseDirective detects the directive type and extracts the value.
// Returns (directiveType, value, found).
//
// Burp mapping: Lines 45-65
func (p *RobotsTxtParser) parseDirective(line string) (directiveType, string) {
	lower := strings.ToLower(line)

	// Check for Allow directive
	// Burp mapping: Line 46: if (var9.startsWith("allow:"))
	if strings.HasPrefix(lower, "allow:") {
		value := strings.TrimPrefix(line, line[:6])
		return directiveAllowDisallow, strings.TrimSpace(value)
	}

	// Check for Disallow directive
	// Burp mapping: Line 53: if (var9.startsWith("disallow:"))
	if strings.HasPrefix(lower, "disallow:") {
		value := strings.TrimPrefix(line, line[:9])
		return directiveAllowDisallow, strings.TrimSpace(value)
	}

	// Check for Sitemap directive
	// Burp mapping: Line 60: if (var9.startsWith("sitemap:"))
	if strings.HasPrefix(lower, "sitemap:") {
		value := strings.TrimPrefix(line, line[:8])
		return directiveSitemap, strings.TrimSpace(value)
	}

	return directiveUnknown, ""
}

// stripInlineComment removes everything after # character.
// Burp mapping: Lines 68-71
func (p *RobotsTxtParser) stripInlineComment(s string) string {
	idx := strings.IndexByte(s, '#')
	if idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// createLink resolves a path to a URL and reports it.
// Rejects URLs containing wildcards (*).
//
// Burp mapping: Lines 91-97
func (p *RobotsTxtParser) createLink(baseURL *url.URL, dirType directiveType, path string, callback LinkCallback) {
	var resolved *url.URL
	var err error

	// Handle sitemap directive specially - it's usually an absolute URL
	if dirType == directiveSitemap {
		// Try to parse as absolute URL first
		resolved, err = url.Parse(path)
		if err != nil {
			return
		}

		// If parsed URL has no scheme, treat as relative to base
		if resolved.Scheme == "" {
			resolved, err = p.urlResolver.Resolve(baseURL, path)
			if err != nil {
				return
			}
		}
	} else {
		// For Allow/Disallow, resolve as relative path
		resolved, err = p.urlResolver.Resolve(baseURL, path)
		if err != nil {
			return
		}
	}

	// Reject if URL is nil
	if resolved == nil {
		return
	}

	// Reject URLs containing wildcards
	// Burp mapping: Line 93: if (var5 != null && !var5.bV().contains("*"))
	// Check both literal * and URL-encoded %2A
	if strings.Contains(resolved.String(), "*") || strings.Contains(resolved.String(), "%2A") {
		return
	}

	// Determine resource type based on directive
	// Burp doesn't distinguish XML separately, use Binary for sitemaps
	resourceType := ResourceHTML // Default for Allow/Disallow
	if dirType == directiveSitemap {
		resourceType = ResourceBinary // Sitemap files
	}

	// Report discovered link
	// Burp mapping: Line 94: new v2(var1, var5, at.a(var3), null, null, (short)0, -1, -1)
	link := &DiscoveredLink{
		SourceType:   SourceRobotsTxt,
		URL:          resolved,
		RawURL:       path,
		ResourceType: resourceType,
		StartPos:     -1, // Position not tracked
		EndPos:       -1,
		Element:      "robots.txt",
	}

	callback(link)
}

// isRobotsTxtURL checks if the URL path is /robots.txt.
// Burp mapping: Lines 99-101
func isRobotsTxtURL(u *url.URL) bool {
	return strings.EqualFold(u.Path, "/robots.txt")
}

// Ensure RobotsTxtParser implements LinkExtractor
var _ LinkExtractor = (*RobotsTxtParser)(nil)
