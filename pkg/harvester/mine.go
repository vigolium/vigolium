package harvester

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/sourcegraph/conc/pool"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Mining budgets.
//
// Every CDX-style source answers with URLs some crawler already recorded, which
// means an endpoint that was never linked from a captured page — or that only
// ever appeared inside a JavaScript bundle — is invisible to all of them. Mining
// reads the archived *bodies* and pulls the endpoints back out.
//
// The phase is on by default, so the cost is bounded by constants rather than by
// flags: the caps below hold one domain's mining to a few dozen extra requests
// on top of the index query it already paid for.
const (
	// mineMaxBodies caps archived responses fetched per domain per source.
	mineMaxBodies = 25
	// mineMaxRobotsHosts caps how many hosts get a robots.txt history lookup.
	mineMaxRobotsHosts = 3
	// mineMaxRobotsSnaps caps distinct robots.txt versions fetched per host.
	// Old versions are the point: a Disallow line naming an admin path survives
	// in the archive long after the path stopped being linked anywhere.
	mineMaxRobotsSnaps = 6
	// mineMaxSitemaps caps sitemap documents fetched per domain.
	mineMaxSitemaps = 8
	// mineMaxBodyBytes caps a single archived body read. Bundles run large and
	// the tail of a huge one is not worth the transfer inside a phase timeout.
	mineMaxBodyBytes = 2 << 20
	// mineMaxLinksPerBody caps what one body may contribute, so a sitemap-like
	// page cannot crowd out every other mining candidate.
	mineMaxLinksPerBody = 500
	// mineConcurrency caps mining requests in flight against one archive.
	mineConcurrency = 5
	// mineMaxRows caps the mineable index rows retained for candidate selection.
	// Rows are filtered on the way in, so this bounds the *interesting* ones; a
	// selection made from thousands of candidates is no worse than one made from
	// a hundred thousand, and the difference is megabytes held for the length of
	// a network-bound phase.
	mineMaxRows = 5000
)

// cdxRow is one index row, kept only long enough to choose mining candidates.
type cdxRow struct {
	URL       string
	Timestamp string
	MIME      string
	Status    string

	// Filename, Offset and Length locate the record inside a WARC file. Only
	// Common Crawl reports them; the Wayback CDX replays by timestamp instead.
	Filename string
	Offset   string
	Length   string
}

// capture identifies one archived snapshot: what was captured, and when. It is
// all the mining fetchers need out of an index row, and it is also the shape a
// sitemap reference takes — a sitemap named by a 2016 robots.txt is a 2016
// document, so it carries the date of the file that named it.
type capture struct {
	URL       string
	Timestamp string
}

func (row cdxRow) capture() capture {
	return capture{URL: row.URL, Timestamp: row.Timestamp}
}

// junkExtensions are static assets that add transfer and scan volume without
// adding attack surface.
//
// This is deliberately not `utils.IsMediaURL` or the discovery engine's asset
// lists: those exclude `js` and `css`, and a JavaScript bundle (and its source
// map) is the single highest-yield target there is. The table is applied to
// mined URLs and, through normalizeURL, to every harvested URL before dedup.
var junkExtensions = map[string]bool{
	"css": true, "jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true,
	"webp": true, "bmp": true, "ico": true, "tif": true, "tiff": true, "avif": true,
	"woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true,
	"mp3": true, "mp4": true, "m4a": true, "wav": true, "avi": true, "flv": true,
	"mov": true, "webm": true, "ogv": true, "wmv": true, "ogg": true, "pdf": true,
}

// archiveHosts are the archives' own hostnames. A replayed page routinely
// references them, and following those back into the scan would target the
// archive rather than the domain under test.
var archiveHosts = map[string]bool{
	"web.archive.org":           true,
	"archive.org":               true,
	"data.commoncrawl.org":      true,
	"index.commoncrawl.org":     true,
	"commoncrawl.org":           true,
	"arquivo.pt":                true,
	"contentdelivery.pt":        true,
	"analytics.archive.org":     true,
	"athena.archive.org":        true,
	"web.archive.org.uk":        true,
	"timetravel.mementoweb.org": true,
}

// emitter carries the three values every mining pass needs to report a URL, so
// they are not threaded through each function as separate parameters.
type emitter struct {
	ctx    context.Context
	ch     chan<- Result
	source string
}

// send reports one mined URL, unless the context has already been cancelled.
func (e emitter) send(rawURL string) {
	emit(e.ctx, e.ch, Result{Source: e.source, URL: rawURL, Mined: true})
}

// emit sends one result unless the context has already been cancelled.
func emit(ctx context.Context, results chan<- Result, result Result) {
	select {
	case <-ctx.Done():
	case results <- result:
	}
}

// mineExtracted reads a bounded selection of archived bodies through the
// caller's fetcher and emits the in-scope URLs written inside them.
//
// Wayback and Common Crawl differ only in how a body is retrieved — a replay by
// timestamp versus a ranged read of a WARC record — so that difference is the
// fetch parameter and everything around it is shared.
func mineExtracted(domain string, targets []cdxRow, fetch func(cdxRow) []byte, e emitter) {
	p := pool.New().WithMaxGoroutines(mineConcurrency)
	for _, row := range targets {
		p.Go(func() {
			body := fetch(row)
			if len(body) == 0 {
				return
			}
			base, err := url.Parse(row.URL)
			if err != nil {
				return
			}
			for _, link := range extractLinks(body, base, domain) {
				e.send(link)
			}
		})
	}
	p.Wait()
}

// absoluteURLPattern matches an absolute http(s) URL inside markup or script.
// The excluded run of characters is what terminates a URL in the surrounding
// syntax — quotes, angle brackets, whitespace, and the bracket family that
// wraps URLs in CSS and template literals.
var absoluteURLPattern = regexp.MustCompile(`https?://[^\s"'<>\\^{}|` + "`" + `\[\]()]+`)

// relativeURLPattern matches a root-relative path inside a string literal. The
// quote is required: an unanchored `/...` match would take every division
// operator in a JavaScript bundle.
//
// An opening parenthesis is deliberately NOT accepted as a delimiter. In
// JavaScript, `(` followed by `/` is a regular-expression literal far more often
// than a URL, and one framework bundle contributes dozens of them — Angular
// alone yields `/&/gi`, `/=/gi`, `/@/gi`, `/,/gi` and friends from its
// `.replace(/x/gi, …)` calls, each of which resolves to a plausible-looking
// endpoint that does not exist.
var relativeURLPattern = regexp.MustCompile(`["'` + "`" + `]\s*(//?[a-zA-Z0-9._~%!$&*+,;=:@/?#\-]{1,400})`)

// jsRegexLiteralPattern matches a regular-expression literal with flags, which
// survives the quote requirement whenever one is stored as a string. `/e/i` is
// not a two-segment path.
var jsRegexLiteralPattern = regexp.MustCompile(`^/[^/\s]{0,40}/[gimsuyd]{1,7}$`)

// locPattern matches a sitemap <loc> entry.
var locPattern = regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)

// extractLinks pulls in-scope URLs out of one archived body.
//
// Both absolute and root-relative forms are taken: a bundle written for a single
// origin refers to its own API entirely in relative form, and those paths are the
// endpoints worth having.
func extractLinks(body []byte, base *url.URL, domain string) []string {
	if len(body) == 0 {
		return nil
	}

	var (
		out  []string
		seen = make(map[string]bool)
	)

	// keep reports whether extraction should continue. Rendering the URL back to
	// a string is deferred until after the scope check, because most of what a
	// page references — analytics, fonts, CDNs — is out of scope and would pay
	// for a string it never uses.
	keep := func(raw string) bool {
		if len(out) >= mineMaxLinksPerBody {
			return false
		}
		parsed := resolveMinedURL(raw, base)
		if parsed == nil || !hostInScope(parsed.Hostname(), domain) {
			return true
		}
		resolved := parsed.String()
		if !seen[resolved] {
			seen[resolved] = true
			out = append(out, resolved)
		}
		return true
	}

	for _, match := range absoluteURLPattern.FindAll(body, -1) {
		if !keep(string(match)) {
			return out
		}
	}
	for _, match := range relativeURLPattern.FindAllSubmatch(body, -1) {
		// Validation runs on the cleaned form, not the raw match. `'/g,` is the
		// tail of a `.replace(…, '/g,')`-shaped expression: raw it looks like a
		// two-character path, and only once the trailing comma is trimmed is it
		// recognisable as the single-letter regex flag it is.
		candidate := cleanCandidate(string(match[1]))
		if !looksLikeRelativePath(candidate) {
			continue
		}
		if !keep(candidate) {
			return out
		}
	}
	return out
}

// entityDecoder undoes the escaping markup applies to a URL. A query string
// arrives as `a=1&amp;b=2`, and leaving it that way invents a parameter named
// "amp".
//
// This is deliberately narrower than html.UnescapeString: the extraction
// patterns cannot produce `<` or `>`, so decoding `&lt;`/`&gt;` would put back
// exactly the markup fragments the character classes exist to exclude.
var entityDecoder = strings.NewReplacer(
	"&amp;", "&",
	"&#38;", "&",
	"&quot;", "",
	"&apos;", "",
)

// cleanCandidate normalizes one extracted candidate: entity-decoded, and with
// the surrounding syntax's punctuation trimmed off the end.
func cleanCandidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	// Replace allocates unconditionally, so the common case — a URL with no
	// entity in it at all — skips it.
	if strings.IndexByte(candidate, '&') >= 0 {
		candidate = entityDecoder.Replace(candidate)
	}
	return strings.TrimRight(candidate, `.,;:!)\"'`)
}

// looksLikeRelativePath rejects the string literals that begin with a slash but
// are not paths.
//
// A minified bundle is full of them — regular-expression sources, framework
// sentinel values like React's `/$`, single-letter regex flags — and each one
// that survives becomes a request against the target for an endpoint that never
// existed.
func looksLikeRelativePath(candidate string) bool {
	// A scheme-relative reference is host-anchored, so the segment rules below
	// do not apply to it.
	if strings.HasPrefix(candidate, "//") {
		return len(candidate) > 2
	}
	if !strings.HasPrefix(candidate, "/") {
		return false
	}

	rest := candidate[1:]
	// One character after the slash is a regex flag (`/g`, `/i`) far more often
	// than it is a route.
	if len(rest) < 2 {
		return false
	}
	// A path segment starts with a name character. Every other leading byte —
	// `$`, `*`, `&`, `:`, `.`, a space — comes from an expression, not a URL.
	if !isPathStartByte(rest[0]) {
		return false
	}
	return !jsRegexLiteralPattern.MatchString(candidate)
}

// isPathStartByte reports whether b can begin a URL path segment in practice.
func isPathStartByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '-', b == '~':
		return true
	default:
		return false
	}
}

// resolveMinedURL cleans one extracted candidate and resolves it against the
// page it came from, returning nil for anything that is not a fetchable http(s)
// URL or that is a static asset.
func resolveMinedURL(raw string, base *url.URL) *url.URL {
	candidate := cleanCandidate(raw)
	if candidate == "" {
		return nil
	}

	// A scheme-relative reference inherits the page's scheme.
	if strings.HasPrefix(candidate, "//") {
		if base == nil {
			return nil
		}
		candidate = base.Scheme + ":" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return nil
	}
	if !parsed.IsAbs() {
		if base == nil {
			return nil
		}
		parsed = base.ResolveReference(parsed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil
	}
	if parsed.Hostname() == "" {
		return nil
	}

	parsed.Fragment = ""
	if junkExtensions[utils.GetExtensionOfPath(parsed.Path)] {
		return nil
	}
	return parsed
}

// minedURLInScope reports whether a mined URL belongs to the domain being
// harvested. Index sources are scoped by their own query; a mined body is not,
// and every page references third-party analytics, fonts and CDNs.
func minedURLInScope(rawURL, domain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return hostInScope(parsed.Hostname(), domain)
}

// hostInScope compares on a label boundary, so notexample.com is not accepted
// as a subdomain of example.com.
func hostInScope(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if host == "" || domain == "" {
		return false
	}
	if archiveHosts[host] {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// parseRobots turns an archived robots.txt into fetchable URLs.
//
// Disallow is the interesting directive: it names paths the site owner did not
// want indexed, which is a different — and frequently more sensitive — set than
// anything a crawler recorded. Sitemap lines are returned too, so the caller can
// follow them.
func parseRobots(body []byte, base *url.URL) (paths, sitemaps []string) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		directive, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(directive)) {
		case "disallow", "allow":
			if resolved := resolveMinedURL(robotsPathPrefix(value), base); resolved != nil {
				paths = append(paths, resolved.String())
			}
		case "sitemap":
			// A Sitemap line carries an absolute URL, so it is resolved as-is
			// rather than through the path cleaner.
			if resolved := resolveMinedURL(value, base); resolved != nil {
				sitemaps = append(sitemaps, resolved.String())
			}
		}
	}
	return paths, sitemaps
}

// robotsPathPrefix reduces a robots.txt pattern to the longest literal prefix
// that is actually fetchable. `/admin/*.php` names a set, not a page, so the
// wildcard and everything after it is dropped and `/admin/` is kept.
func robotsPathPrefix(value string) string {
	if i := strings.IndexAny(value, "*$"); i >= 0 {
		value = value[:i]
	}
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	return value
}

// parseSitemap returns the <loc> entries of a sitemap or sitemap index. The two
// are the same document shape, so one parser covers both and the caller decides
// whether an entry is a page or another sitemap.
func parseSitemap(body []byte, base *url.URL, domain string) []string {
	var (
		out  []string
		seen = make(map[string]bool)
	)
	for _, match := range locPattern.FindAllSubmatch(body, -1) {
		parsed := resolveMinedURL(string(match[1]), base)
		if parsed == nil || !hostInScope(parsed.Hostname(), domain) {
			continue
		}
		resolved := parsed.String()
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, resolved)
		if len(out) >= mineMaxLinksPerBody {
			break
		}
	}
	return out
}

// isSitemapURL reports whether a URL looks like a sitemap document.
func isSitemapURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.Path)
	if !strings.Contains(lower, "sitemap") {
		return false
	}
	return strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, ".xml.gz") ||
		strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, "/sitemap")
}

// isRobotsURL reports whether a URL is a robots.txt.
func isRobotsURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), "/robots.txt")
}

// minePrio orders mining candidates by how many endpoints a body is likely to
// hold. A JavaScript bundle names every route the front end can reach; an HTML
// page names the handful it links to.
type minePrio int

const (
	prioScript minePrio = iota
	prioJSON
	prioXML
	prioOther
	prioCount
)

// mineClass reports how promising a row's body is, and whether it is worth
// reading at all.
//
// Extension and MIME are read once here rather than by a separate worthiness
// check and priority check, which used to scan the same URL string twice per
// candidate across the whole index.
func mineClass(row cdxRow) (minePrio, bool) {
	// A capture that was not a 200 has no useful body.
	if row.Status != "" && row.Status != "200" {
		return prioOther, false
	}

	ext := utils.GetExtensionOfPath(row.URL)
	if junkExtensions[ext] {
		return prioOther, false
	}
	mime := strings.ToLower(row.MIME)

	switch {
	case ext == "js", ext == "mjs", strings.Contains(mime, "javascript"):
		return prioScript, true
	case ext == "json", strings.Contains(mime, "json"):
		return prioJSON, true
	case ext == "xml", strings.Contains(mime, "xml"):
		return prioXML, true
	}

	// HTML and text are where the remaining endpoints are written down. A source
	// that reports no MIME still carries a mineable body; the extension check
	// above already removed the obvious assets.
	switch {
	case mime == "", mime == "unk",
		strings.Contains(mime, "html"),
		strings.Contains(mime, "text/plain"):
		return prioOther, true
	}
	return prioOther, false
}

// mineWorthy reports whether a row's body is worth reading, for callers that
// only need to filter.
func mineWorthy(row cdxRow) bool {
	_, ok := mineClass(row)
	return ok
}

// selectMineTargets picks the rows to fetch, highest yield first and at most one
// per path so a page captured under many query strings cannot fill the budget.
func selectMineTargets(rows []cdxRow, limit int) []cdxRow {
	if limit <= 0 {
		return nil
	}

	// Bucket by priority rather than sorting: the rows arrive in index order and
	// a stable bucket walk keeps selection deterministic without a comparator.
	// No bucket needs to hold more than the whole result, since a full
	// higher-priority bucket already fills it.
	buckets := make([][]cdxRow, prioCount)
	seen := make(map[string]bool)

	for _, row := range rows {
		prio, ok := mineClass(row)
		if !ok {
			continue
		}
		key := minePathKey(row.URL)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true

		if len(buckets[prio]) < limit {
			buckets[prio] = append(buckets[prio], row)
		}
		// Once the top bucket is full nothing else can reach the result.
		if len(buckets[prioScript]) >= limit {
			break
		}
	}

	out := make([]cdxRow, 0, limit)
	for _, bucket := range buckets {
		for _, row := range bucket {
			if len(out) >= limit {
				return out
			}
			out = append(out, row)
		}
	}
	return out
}

// selectRobotsHosts picks the hosts whose robots.txt history is worth walking.
//
// The apex leads because it is the host most likely to have been archived for
// the longest; the rest follow in the order the index reported them, which puts
// the hosts with the most captures first.
func selectRobotsHosts(rows []cdxRow, domain string) []string {
	var (
		hosts []string
		seen  = make(map[string]bool)
	)

	add := func(host string) {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || seen[host] || !hostInScope(host, domain) {
			return
		}
		seen[host] = true
		hosts = append(hosts, host)
	}

	add(domain)
	for _, row := range rows {
		if len(hosts) >= mineMaxRobotsHosts {
			break
		}
		parsed, err := url.Parse(row.URL)
		if err != nil {
			continue
		}
		add(parsed.Hostname())
	}
	return hosts
}

// minePathKey is the host+path identity used to spread selection across distinct
// endpoints instead of query-string variants of one.
//
// This walks the string rather than calling url.Parse: it runs once per index
// row, which is hundreds of thousands of times per domain, and none of the rest
// of a parsed URL is wanted.
func minePathKey(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	host, path, _ := strings.Cut(rest, "/")
	if host == "" {
		return ""
	}
	return strings.ToLower(host) + "/" + path
}

// readCappedBody reads an archived response, bounded by mineMaxBodyBytes and
// transparently gunzipped. A partial read is kept rather than discarded: a
// truncated bundle still names endpoints.
func readCappedBody(resp *http.Response) []byte {
	body, err := io.ReadAll(io.LimitReader(resp.Body, mineMaxBodyBytes))
	if err != nil && len(body) == 0 {
		return nil
	}
	return decompress(body)
}

// decompress transparently gunzips a body that carries the gzip magic bytes.
// Archived sitemaps are routinely served as .xml.gz, and a WARC member is always
// gzipped, so the callers cannot tell from the URL alone.
func decompress(body []byte) []byte {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body
	}

	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer func() { _ = reader.Close() }()

	// A gzip stream can expand enormously, so the same ceiling that bounds a
	// fetched body bounds its expansion.
	expanded, err := io.ReadAll(io.LimitReader(reader, mineMaxBodyBytes))
	if err != nil && len(expanded) == 0 {
		return body
	}
	return expanded
}
