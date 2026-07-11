package modkit

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// appPageMarkers are substrings that appear only on a rendered application, CMS,
// or single-page-app content page — never in a machine-generated serve-index /
// Nginx / Apache / IIS directory listing. All are matched against a lowercased
// body. Their presence is proof the body is real page content, not an autoindex,
// even when it happens to carry a heading, a table, and links.
var appPageMarkers = []string{
	`<meta name="generator"`, // Gatsby, Hugo, WordPress, Drupal, Next.js, ...
	`data-react-helmet`,      // React Helmet (Gatsby / CRA)
	`__next_data__`,          // Next.js
	`window.__nuxt__`,        // Nuxt
	`ng-version`,             // Angular
	`data-reactroot`,         // React
	`id="___gatsby"`,         // Gatsby root node
	`property="og:`,          // Open Graph tags
	`name="twitter:`,         // Twitter cards
	`wp-content`,             // WordPress
	`wp-includes`,            // WordPress
	`data-drupal`,            // Drupal
}

// LooksLikeAppPage reports whether lowerBody is a rendered application / CMS / SPA
// content page rather than a bare, machine-emitted response such as a directory
// listing. Directory-listing detectors call it as a negative guard: a real
// serve-index / Nginx / Apache / IIS autoindex never carries framework,
// static-site-generator, or SEO/social markers, so their presence rules a
// listing out — killing the class of false positive where a content page (a
// Gatsby/Next.js route, a "Directory of X" landing page) has an <h1>, a <table>,
// and <a href=> links yet is not a listing.
//
// lowerBody MUST already be lowercased (via strings.ToLower). Callers process the
// same response body through several of these classifiers, so lowercasing is
// hoisted to the caller to avoid re-copying a large body per check.
func LooksLikeAppPage(lowerBody string) bool {
	for _, marker := range appPageMarkers {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

// HasParentDirLink reports whether lowerBody links to a parent directory ("../" or
// a "Parent Directory" label) — the near-universal entry of a real autoindex and a
// strong structural signal that a <table>/<pre>/<ul> of links is a generated file
// index rather than page content. lowerBody MUST already be lowercased (see
// LooksLikeAppPage for the rationale).
func HasParentDirLink(lowerBody string) bool {
	return strings.Contains(lowerBody, `href="../"`) ||
		strings.Contains(lowerBody, `href='../'`) ||
		strings.Contains(lowerBody, `href="..">`) ||
		strings.Contains(lowerBody, "parent directory")
}

// iisListingPattern matches the IIS default directory-listing HTML structure
// (case-sensitive: IIS emits an uppercase <H1>).
var iisListingPattern = regexp.MustCompile(`</title></head><body><H1>.*?-.*?</H1><hr>`)

// genericListingTitlePattern matches auto-generated directory-listing <title>s
// like "listing directory /ftp/", "Directory listing for /", "Index of /uploads",
// "Directory of /path". It is deliberately loose, so callers MUST corroborate it
// with a listing STRUCTURE (see hasListingStructure) — a bare title match alone is
// shared by ordinary content pages ("Directory of Physicians", "Index of Terms").
// It is matched against an already-lowercased body (no (?i) flag), which is both
// cheaper and avoids a second case-insensitive pass over the response.
var genericListingTitlePattern = regexp.MustCompile(`<title>\s*(?:(?:listing|index)\s+(?:of|directory)|directory\s+(?:listing|index|of))\b`)

// hasListingStructure reports whether the (lowercased) body carries the file-index
// structure a generated directory listing has: a parent-directory link, the
// serve-index file container (id="files"), or an <hr>-bracketed <pre>/<ul> of
// links (Nginx autoindex, Python http.server). A content page that merely happens
// to be titled "Directory of X" lacks all of these.
func hasListingStructure(lower string) bool {
	if HasParentDirLink(lower) {
		return true
	}
	if strings.Contains(lower, `id="files"`) { // serve-index file container
		return true
	}
	// Nginx autoindex / Python http.server: a file list bracketed by <hr>.
	if strings.Contains(lower, "<hr") && strings.Contains(lower, "<a href=") &&
		(strings.Contains(lower, "<pre") || strings.Contains(lower, "<ul")) {
		return true
	}
	return false
}

// DetectDirectoryListingServer classifies body as an auto-generated directory
// listing and returns the emitting server ("Jetty", "IIS", "Apache", "Nginx",
// "Generic"), or "" when body is not a listing. It is the shared classifier
// behind the active and passive directory-listing modules.
//
// Two guards keep it from firing on ordinary pages:
//   - LooksLikeAppPage rejects rendered application/CMS/SPA content up front, so a
//     framework page with a heading + table + links is never mistaken for a listing.
//   - the Generic (title-only) branch additionally requires a listing STRUCTURE
//     (hasListingStructure), so a content page merely titled "Directory of X" /
//     "Index of X" does not false-positive. The server-specific branches already
//     require two corroborating markers (title + heading / <pre> / css) and are left
//     as-is.
func DetectDirectoryListingServer(body string) string {
	// The body is scanned by every branch below, so lowercase it once and thread
	// the result through the substring/structure helpers. Only the IIS branch needs
	// the raw body (its signature is case-sensitive on an uppercase <H1>).
	lower := strings.ToLower(body)

	// Rendered application/CMS/SPA content is never an autoindex.
	if LooksLikeAppPage(lower) {
		return ""
	}

	// Jetty: <title>Directory: ... AND its stylesheet.
	if strings.Contains(lower, "<title>directory:") && strings.Contains(lower, "jetty-dir.css") {
		return "Jetty"
	}

	// IIS: </title></head><body><H1>...-...</H1><hr> structural signature.
	if iisListingPattern.MatchString(body) {
		return "IIS"
	}

	// Apache autoindex: "Index of" in both the <title> and the <h1>.
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<h1>index of") {
		return "Apache"
	}

	// Nginx autoindex: "Index of" title plus the <pre> file block.
	if strings.Contains(lower, "<title>index of") && strings.Contains(lower, "<pre>") {
		return "Nginx"
	}

	// Generic (serve-index, Python http.server, ...): a listing <title> corroborated
	// by real listing structure. The structure requirement is what separates a true
	// listing from a content page that is merely titled "Directory of X"; it is the
	// cheaper check, so it gates the regex (which only runs on structured bodies).
	if hasListingStructure(lower) && genericListingTitlePattern.MatchString(lower) {
		return "Generic"
	}

	return ""
}

// ServiceBaseURL builds the scheme://host[:port] origin for service, omitting the
// port for the protocol default (443 for https, 80 for http, or an unset port) so
// probed/matched URLs read cleanly. It gives path-probing modules a correct base
// to append their probe path to, instead of concatenating onto the observed
// request's full URL (which carries an unrelated path and query string).
func ServiceBaseURL(service *httpmsg.Service) string {
	proto := service.Protocol()
	host := service.Host()
	port := service.Port()
	if port == 0 ||
		(proto == "https" && port == 443) ||
		(proto == "http" && port == 80) {
		return fmt.Sprintf("%s://%s", proto, host)
	}
	return fmt.Sprintf("%s://%s:%d", proto, host, port)
}
