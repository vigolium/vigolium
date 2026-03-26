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
func (p *RobotsTxtParser) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Only process robots.txt files
	if response.URL == nil || !isRobotsTxtURL(response.URL) {
		return nil
	}

	// Skip if body is empty
	if len(response.Body) == 0 {
		return nil
	}

	// Parse response body line by line
	scanner := bufio.NewScanner(bytes.NewReader(response.Body))

	for scanner.Scan() {
		line := scanner.Text()

		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Strip leading # characters (comments)
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
		directiveType, path := p.parseDirective(line)

		// Skip unrecognized directives
		if directiveType == directiveUnknown {
			continue
		}

		// Strip inline comments
		path = p.stripInlineComment(path)
		if path == "" {
			continue
		}

		// Create link from path
		p.createLink(baseURL, directiveType, path, callback)

		// For Allow/Disallow, also add variant with trailing slash if not present
		// Skip if path contains wildcards
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
func (p *RobotsTxtParser) parseDirective(line string) (directiveType, string) {
	lower := strings.ToLower(line)

	// Check for Allow directive
	if strings.HasPrefix(lower, "allow:") {
		value := strings.TrimPrefix(line, line[:6])
		return directiveAllowDisallow, strings.TrimSpace(value)
	}

	// Check for Disallow directive
	if strings.HasPrefix(lower, "disallow:") {
		value := strings.TrimPrefix(line, line[:9])
		return directiveAllowDisallow, strings.TrimSpace(value)
	}

	// Check for Sitemap directive
	if strings.HasPrefix(lower, "sitemap:") {
		value := strings.TrimPrefix(line, line[:8])
		return directiveSitemap, strings.TrimSpace(value)
	}

	return directiveUnknown, ""
}

// stripInlineComment removes everything after # character.
func (p *RobotsTxtParser) stripInlineComment(s string) string {
	idx := strings.IndexByte(s, '#')
	if idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// createLink resolves a path to a URL and reports it.
// Rejects URLs containing wildcards (*).
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
	// Check both literal * and URL-encoded %2A
	if strings.Contains(resolved.String(), "*") || strings.Contains(resolved.String(), "%2A") {
		return
	}

	// Determine resource type based on directive
	resourceType := ResourceHTML // Default for Allow/Disallow
	if dirType == directiveSitemap {
		resourceType = ResourceBinary // Sitemap files
	}

	// Report discovered link
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
func isRobotsTxtURL(u *url.URL) bool {
	return strings.EqualFold(u.Path, "/robots.txt")
}

// Ensure RobotsTxtParser implements LinkExtractor
var _ LinkExtractor = (*RobotsTxtParser)(nil)
