package database

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg/pathshape"
)

// The endpoint inventory (`vigolium endpoints`) and the parameter inventory
// (`vigolium params`) answer "what does this application expose" from the
// stored traffic without shipping it.
//
// Both stream the matched records through QueryBuilder.applyFilters — the one
// predicate set every record read uses, so `--host x --status 200` describes
// exactly the rows `traffic --host x --status 200` would list — reading only
// light columns (never raw_request/raw_response) in uuid-keyset pages. Memory is
// O(endpoints): every per-endpoint set is capped, and the number of distinct
// endpoints is capped too, with the overflow counted rather than dropped.
//
// Paths are grouped by pathshape, the one shared normalizer: /users/42 and
// /users/7 are one endpoint, /users/me and /about stay distinct.

const (
	// inventoryPageSize is the keyset page for the light-record stream.
	inventoryPageSize = 2000

	// DefaultMaxEndpoints bounds the distinct endpoints one aggregate holds.
	// Records that would open a new endpoint past it are counted as unbucketed.
	DefaultMaxEndpoints = 100000

	endpointSamplePaths      = 3
	endpointDistinctPathCap  = 1000
	endpointParamNamesCap    = 50
	endpointContentTypesOut  = 5
	endpointContentTypesHeld = 32
	endpointStatusCap        = 64
	endpointSourcesCap       = 16
	endpointJSOutcomesCap    = 16
)

// inventoryRecord is the light projection the inventories read. It never
// carries the raw request/response.
type inventoryRecord struct {
	UUID                string          `bun:"uuid"`
	Scheme              string          `bun:"scheme"`
	Hostname            string          `bun:"hostname"`
	Port                int             `bun:"port"`
	Method              string          `bun:"method"`
	Path                string          `bun:"path"`
	StatusCode          int             `bun:"status_code"`
	HasResponse         bool            `bun:"has_response"`
	RequestContentType  string          `bun:"request_content_type"`
	ResponseContentType string          `bun:"response_content_type"`
	Parameters          []EmbeddedParam `bun:"parameters,type:jsonb"`
	IsAuthenticated     bool            `bun:"is_authenticated"`
	HasAuthorization    bool            `bun:"has_authorization"`
	Source              string          `bun:"source"`
	Remarks             []string        `bun:"remarks,type:jsonb"`
	CreatedAt           time.Time       `bun:"created_at"`
}

// inventoryColumns are the columns inventoryRecord reads; the authorization
// value itself is reduced to a boolean in SQL.
var inventoryColumns = []string{
	"r.uuid", "r.scheme", "r.hostname", "r.port", "r.method", "r.path",
	"r.status_code", "r.has_response", "r.request_content_type",
	"r.response_content_type", "r.parameters", "r.is_authenticated",
	"r.source", "r.remarks", "r.created_at",
}

// inventoryPageQuery is one keyset page of the light-record stream.
func (qb *QueryBuilder) inventoryPageQuery(afterUUID string, n int) *bun.SelectQuery {
	q := qb.db.NewSelect().Model((*HTTPRecord)(nil))
	for _, c := range inventoryColumns {
		q = q.ColumnExpr(c)
	}
	q = q.ColumnExpr("(r.request_authorization IS NOT NULL AND r.request_authorization <> '') AS has_authorization")
	qb.applyFilters(q)
	if afterUUID != "" {
		q = q.Where("r.uuid > ?", afterUUID)
	}
	return q.OrderExpr("r.uuid ASC").Limit(int64(n))
}

// forEachInventoryRecord streams every record the filters match (Limit,
// Offset and sort are ignored: an aggregate describes all of them) and returns
// how many it saw.
func (qb *QueryBuilder) forEachInventoryRecord(ctx context.Context, fn func(*inventoryRecord)) (int64, error) {
	var seen int64
	after := ""
	for {
		var page []inventoryRecord
		if err := qb.inventoryPageQuery(after, inventoryPageSize).Scan(ctx, &page); err != nil {
			return seen, err
		}
		for i := range page {
			fn(&page[i])
		}
		seen += int64(len(page))
		if len(page) < inventoryPageSize {
			return seen, nil
		}
		after = page[len(page)-1].UUID
		if err := ctx.Err(); err != nil {
			return seen, err
		}
	}
}

// EndpointOrigin renders scheme://host[:port], omitting the scheme's default
// port, with the host lower-cased.
func EndpointOrigin(scheme, host string, port int) string {
	scheme = strings.ToLower(scheme)
	host = strings.ToLower(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port == 0 || (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port)
}

// EndpointID is the stable id of an endpoint: the first 12 hex digits of
// sha1(origin + " " + template). It depends on nothing but the two strings, so
// the same endpoint has the same id in every database.
func EndpointID(origin, template string) string {
	sum := sha1.Sum([]byte(origin + " " + template))
	return hex.EncodeToString(sum[:])[:12]
}

// EndpointTemplate is the path's structural template (query stripped).
func EndpointTemplate(path string) (template string, segments []string, kinds []pathshape.SegKind) {
	path = endpointPath(path)
	template, kinds = pathshape.Shape(path)
	return template, pathshape.Segments(path), kinds
}

// endpointShape is EndpointTemplate without the segments, for callers that
// only need the template and kinds.
func endpointShape(path string) (template string, kinds []pathshape.SegKind) {
	return pathshape.Shape(endpointPath(path))
}

// endpointPath strips the query and fragment; an empty path is "/".
func endpointPath(path string) string {
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	if path == "" {
		path = "/"
	}
	return path
}

// endpointOriginKey is the input of EndpointOrigin.
type endpointOriginKey struct {
	scheme, host string
	port         int
}

// originCache memoizes EndpointOrigin: an inventory pass sees many records
// over few origins.
type originCache map[endpointOriginKey]string

func (c originCache) origin(scheme, host string, port int) string {
	k := endpointOriginKey{scheme, host, port}
	o, ok := c[k]
	if !ok {
		o = EndpointOrigin(scheme, host, port)
		c[k] = o
	}
	return o
}

// paramLocation maps a stored EmbeddedParam type to the inventory's location
// vocabulary.
func paramLocation(storedType string) string {
	switch storedType {
	case "url":
		return "query"
	case "body", "json", "xml", "cookie", "multipart", "path", "header":
		return storedType
	default:
		return "other"
	}
}

// pathParamName names a dynamic path segment: its kind placeholder and its
// 0-based segment index, e.g. "{int}@1" in /users/{int}.
func pathParamName(kind pathshape.SegKind, index int) string {
	return kind.Placeholder() + "@" + strconv.Itoa(index)
}

// --- endpoints --------------------------------------------------------------

// EndpointSorts are the accepted EndpointOptions.Sort values.
var EndpointSorts = []string{"records", "findings", "template", "last_seen"}

// EndpointOptions shapes an Endpoints call.
type EndpointOptions struct {
	// MinRecords drops endpoints seen fewer times.
	MinRecords int64
	// Sort is one of EndpointSorts; "" means records.
	Sort string
	// Collapse, when >= 2, merges sibling literal segments that share an
	// identical set of child templates once at least Collapse of them do
	// (/blog/a, /blog/b, … → /blog/{var}). 0 disables it: it can merge real
	// routes, so it is opt-in.
	Collapse int
	// Limit/Offset page the endpoint list; Limit 0 returns every endpoint.
	Limit, Offset int
	// SkipFindings leaves the finding counts out (no findings pass).
	SkipFindings bool
	// MaxEndpoints overrides DefaultMaxEndpoints (0 = default).
	MaxEndpoints int
}

// EndpointAuth counts a endpoint's records with and without credentials.
type EndpointAuth struct {
	Authenticated int64 `json:"authenticated"`
	Anonymous     int64 `json:"anonymous"`
}

// EndpointView is one endpoint: an origin plus a path template, with every
// method seen on it.
type EndpointView struct {
	ID       string   `json:"id"`
	Origin   string   `json:"origin"`
	Host     string   `json:"host"`
	Template string   `json:"template"`
	Methods  []string `json:"methods"`

	Records       int64    `json:"records"`
	DistinctPaths int64    `json:"distinct_paths"`
	PathsCapped   bool     `json:"distinct_paths_capped,omitempty"`
	SamplePaths   []string `json:"sample_paths"`

	// Params lists parameter names by location (query, body, json, cookie,
	// xml, multipart, path), each capped at 50.
	Params     map[string][]string `json:"params"`
	ParamCount int                 `json:"param_count"`

	RequestContentTypes  []string `json:"request_content_types"`
	ResponseContentTypes []string `json:"response_content_types"`

	Status    map[string]int64 `json:"status"`
	TopStatus int              `json:"top_status"`
	Auth      EndpointAuth     `json:"auth"`

	// Sources are the record sources (scanner, deparos, jstangle, ingest-*…);
	// JSOutcomes are the jstangle:* outcome remarks (found, not_found,
	// withheld, …) of JS-derived records, so a route known only from code is
	// visible as such.
	Sources    []string `json:"sources"`
	JSOutcomes []string `json:"js_outcomes,omitempty"`

	// Findings counts live findings (not false_positive / accepted_risk) whose
	// URL maps onto this endpoint.
	Findings           int64            `json:"findings"`
	FindingsBySeverity map[string]int64 `json:"findings_by_severity,omitempty"`
	MaxSeverity        string           `json:"max_severity,omitempty"`

	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// EndpointResult is a bounded endpoint inventory.
type EndpointResult struct {
	// Endpoints is the requested page.
	Endpoints []EndpointView
	// Total counts every endpoint that passed MinRecords, whatever the page.
	Total int64
	// RecordsScanned is how many records the filters matched.
	RecordsScanned int64
	// Capped reports the distinct-endpoint cap was reached; UnbucketedRecords
	// were not attributed to any endpoint.
	Capped            bool
	UnbucketedRecords int64
}

type endpointAcc struct {
	origin, host, template string
	methods                map[string]struct{}
	records                int64
	paths                  map[string]struct{}
	pathsCapped            bool
	samples                []string
	params                 map[string]map[string]struct{}
	reqCT, respCT          map[string]int64
	status                 map[int]int64
	auth                   EndpointAuth
	sources                map[string]struct{}
	js                     map[string]struct{}
	findings               int64
	bySev                  map[string]int64
	first, last            time.Time
}

func newEndpointAcc(origin, host, template string) *endpointAcc {
	return &endpointAcc{
		origin: origin, host: host, template: template,
		methods: map[string]struct{}{}, paths: map[string]struct{}{},
		params: map[string]map[string]struct{}{},
		reqCT:  map[string]int64{}, respCT: map[string]int64{},
		status: map[int]int64{}, sources: map[string]struct{}{},
		js: map[string]struct{}{}, bySev: map[string]int64{},
	}
}

func endpointKey(origin, template string) string { return origin + " " + template }

func addCapped(set map[string]struct{}, v string, limit int) {
	if v == "" {
		return
	}
	if _, ok := set[v]; ok || len(set) < limit {
		set[v] = struct{}{}
	}
}

func (a *endpointAcc) addParam(location, name string) {
	set := a.params[location]
	if set == nil {
		set = map[string]struct{}{}
		a.params[location] = set
	}
	addCapped(set, name, endpointParamNamesCap)
}

func (a *endpointAcc) addPath(path string) {
	if _, ok := a.paths[path]; ok {
		return
	}
	if len(a.paths) >= endpointDistinctPathCap {
		a.pathsCapped = true
		return
	}
	a.paths[path] = struct{}{}
	if len(a.samples) < endpointSamplePaths {
		a.samples = append(a.samples, path)
	}
}

func addCount(m map[string]int64, k string, n int64, limit int) {
	if k == "" {
		return
	}
	if _, ok := m[k]; ok || len(m) < limit {
		m[k] += n
	}
}

func (a *endpointAcc) observe(r *inventoryRecord, kinds []pathshape.SegKind) {
	a.records++
	a.methods[strings.ToUpper(r.Method)] = struct{}{}
	path, _, _ := strings.Cut(r.Path, "?")
	if path == "" {
		path = "/"
	}
	a.addPath(path)
	for _, p := range r.Parameters {
		loc := paramLocation(p.Type)
		if loc == "path" {
			continue // path params come from the template below
		}
		a.addParam(loc, p.Name)
	}
	for i, k := range kinds {
		if k.Dynamic() {
			a.addParam("path", pathParamName(k, i))
		}
	}
	addCount(a.reqCT, compactMediaType(r.RequestContentType), 1, endpointContentTypesHeld)
	if r.HasResponse {
		addCount(a.respCT, compactMediaType(r.ResponseContentType), 1, endpointContentTypesHeld)
		if _, ok := a.status[r.StatusCode]; ok || len(a.status) < endpointStatusCap {
			a.status[r.StatusCode]++
		}
	}
	if r.IsAuthenticated || r.HasAuthorization {
		a.auth.Authenticated++
	} else {
		a.auth.Anonymous++
	}
	addCapped(a.sources, r.Source, endpointSourcesCap)
	for _, rem := range r.Remarks {
		if outcome, ok := jstangleOutcome(rem); ok {
			addCapped(a.js, outcome, endpointJSOutcomesCap)
		}
	}
	if a.first.IsZero() || r.CreatedAt.Before(a.first) {
		a.first = r.CreatedAt
	}
	if r.CreatedAt.After(a.last) {
		a.last = r.CreatedAt
	}
}

// jstangleOutcome extracts the outcome of a "jstangle:<outcome>" remark; the
// keyed remarks (jstangle:src=…, jstangle:reason=…) are provenance, not
// outcomes.
func jstangleOutcome(remark string) (string, bool) {
	rest, ok := strings.CutPrefix(remark, "jstangle:")
	if !ok || rest == "" || strings.Contains(rest, "=") {
		return "", false
	}
	return rest, true
}

func (a *endpointAcc) merge(b *endpointAcc) {
	a.records += b.records
	for m := range b.methods {
		a.methods[m] = struct{}{}
	}
	a.pathsCapped = a.pathsCapped || b.pathsCapped
	for _, s := range b.samples {
		a.addPath(s)
	}
	for p := range b.paths {
		a.addPath(p)
	}
	for loc, names := range b.params {
		for n := range names {
			a.addParam(loc, n)
		}
	}
	for k, n := range b.reqCT {
		addCount(a.reqCT, k, n, endpointContentTypesHeld)
	}
	for k, n := range b.respCT {
		addCount(a.respCT, k, n, endpointContentTypesHeld)
	}
	for k, n := range b.status {
		if _, ok := a.status[k]; ok || len(a.status) < endpointStatusCap {
			a.status[k] += n
		}
	}
	a.auth.Authenticated += b.auth.Authenticated
	a.auth.Anonymous += b.auth.Anonymous
	for s := range b.sources {
		addCapped(a.sources, s, endpointSourcesCap)
	}
	for s := range b.js {
		addCapped(a.js, s, endpointJSOutcomesCap)
	}
	a.findings += b.findings
	for k, n := range b.bySev {
		a.bySev[k] += n
	}
	if a.first.IsZero() || (!b.first.IsZero() && b.first.Before(a.first)) {
		a.first = b.first
	}
	if b.last.After(a.last) {
		a.last = b.last
	}
}

// endpointSeverityRank orders severities for max_severity (the CLI's order).
var endpointSeverityRank = map[string]int{
	"info": 1, "suspect": 2, "low": 3, "medium": 4, "high": 5, "critical": 6,
}

func (a *endpointAcc) view() EndpointView {
	v := EndpointView{
		ID:            EndpointID(a.origin, a.template),
		Origin:        a.origin,
		Host:          a.host,
		Template:      a.template,
		Methods:       sortedSetKeys(a.methods),
		Records:       a.records,
		DistinctPaths: int64(len(a.paths)),
		PathsCapped:   a.pathsCapped,
		SamplePaths:   append([]string{}, a.samples...),
		Params:        map[string][]string{},
		Status:        map[string]int64{},
		Auth:          a.auth,
		Sources:       sortedSetKeys(a.sources),
		Findings:      a.findings,
	}
	for loc, names := range a.params {
		v.Params[loc] = sortedSetKeys(names)
		v.ParamCount += len(names)
	}
	v.RequestContentTypes = keysByCount(a.reqCT, endpointContentTypesOut)
	v.ResponseContentTypes = keysByCount(a.respCT, endpointContentTypesOut)
	var top int64 = -1
	for code, n := range a.status {
		v.Status[strconv.Itoa(code)] = n
		if n > top || (n == top && code < v.TopStatus) {
			top, v.TopStatus = n, code
		}
	}
	if len(a.js) > 0 {
		v.JSOutcomes = sortedSetKeys(a.js)
	}
	if a.findings > 0 {
		v.FindingsBySeverity = map[string]int64{}
		for sev, n := range a.bySev {
			v.FindingsBySeverity[sev] = n
			if endpointSeverityRank[sev] > endpointSeverityRank[v.MaxSeverity] {
				v.MaxSeverity = sev
			}
		}
	}
	if !a.first.IsZero() {
		v.FirstSeen = a.first.UTC().Format(time.RFC3339)
	}
	if !a.last.IsZero() {
		v.LastSeen = a.last.UTC().Format(time.RFC3339)
	}
	return v
}

func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keysByCount returns the keys of counts, most frequent first, ties by key;
// n > 0 keeps only the first n.
func keysByCount[N int | int64](counts map[string]N, n int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// ValidateEndpointSort reports whether s is an accepted sort ("" is).
func ValidateEndpointSort(s string) error {
	if s == "" {
		return nil
	}
	for _, ok := range EndpointSorts {
		if s == ok {
			return nil
		}
	}
	return fmt.Errorf("unknown sort %q; supported: %s", s, strings.Join(EndpointSorts, ", "))
}

// Endpoints aggregates the filtered records into an endpoint inventory.
func (qb *QueryBuilder) Endpoints(ctx context.Context, opts EndpointOptions) (EndpointResult, error) {
	if err := ValidateEndpointSort(opts.Sort); err != nil {
		return EndpointResult{}, err
	}
	maxEndpoints := opts.MaxEndpoints
	if maxEndpoints <= 0 {
		maxEndpoints = DefaultMaxEndpoints
	}
	var res EndpointResult
	accs := map[string]*endpointAcc{}
	origins := originCache{}
	seen, err := qb.forEachInventoryRecord(ctx, func(r *inventoryRecord) {
		origin := origins.origin(r.Scheme, r.Hostname, r.Port)
		template, kinds := endpointShape(r.Path)
		key := endpointKey(origin, template)
		acc := accs[key]
		if acc == nil {
			if len(accs) >= maxEndpoints {
				res.Capped = true
				res.UnbucketedRecords++
				return
			}
			acc = newEndpointAcc(origin, strings.ToLower(r.Hostname), template)
			accs[key] = acc
		}
		acc.observe(r, kinds)
	})
	if err != nil {
		return EndpointResult{}, err
	}
	res.RecordsScanned = seen

	if opts.Collapse >= 2 {
		accs = collapseEndpoints(accs, opts.Collapse)
	}
	if !opts.SkipFindings && len(accs) > 0 {
		if err := qb.attachEndpointFindings(ctx, accs, opts.Collapse >= 2); err != nil {
			return EndpointResult{}, fmt.Errorf("count findings: %w", err)
		}
	}

	views := make([]EndpointView, 0, len(accs))
	for _, a := range accs {
		if a.records < opts.MinRecords {
			continue
		}
		views = append(views, a.view())
	}
	sortEndpointViews(views, opts.Sort)
	res.Total = int64(len(views))
	res.Endpoints = pageSlice(views, opts.Offset, opts.Limit)
	return res, nil
}

func pageSlice[T any](items []T, offset, limit int) []T {
	if offset > 0 {
		if offset >= len(items) {
			return []T{}
		}
		items = items[offset:]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func sortEndpointViews(v []EndpointView, by string) {
	byName := func(i, j int) bool {
		if v[i].Origin != v[j].Origin {
			return v[i].Origin < v[j].Origin
		}
		return v[i].Template < v[j].Template
	}
	sort.SliceStable(v, func(i, j int) bool {
		switch by {
		case "template":
			return byName(i, j)
		case "findings":
			if v[i].Findings != v[j].Findings {
				return v[i].Findings > v[j].Findings
			}
			if ri, rj := endpointSeverityRank[v[i].MaxSeverity], endpointSeverityRank[v[j].MaxSeverity]; ri != rj {
				return ri > rj
			}
		case "last_seen":
			if v[i].LastSeen != v[j].LastSeen {
				return v[i].LastSeen > v[j].LastSeen
			}
		default: // records
			if v[i].Records != v[j].Records {
				return v[i].Records > v[j].Records
			}
		}
		return byName(i, j)
	})
}

// dismissedForInventory are the finding statuses an inventory does not count:
// a finding someone ruled out is not attack surface.
var dismissedForInventory = []string{"false_positive", "accepted_risk"}

// attachEndpointFindings adds live findings to the endpoints their URL maps
// onto. Findings carry a denormalized URL, so this is one keyset pass over the
// project's findings with no junction join.
//
// collapsed says collapseEndpoints ran, so a finding whose concrete template
// has no exact match may belong to a {var} endpoint.
func (qb *QueryBuilder) attachEndpointFindings(ctx context.Context, accs map[string]*endpointAcc, collapsed bool) error {
	var withVar []collapsedCandidate
	if collapsed {
		for _, a := range accs {
			if strings.Contains(a.template, collapseVar) {
				withVar = append(withVar, collapsedCandidate{acc: a, parts: strings.Split(a.template, "/")})
			}
		}
	}
	var lastID int64
	for {
		var page []struct {
			ID       int64  `bun:"id"`
			URL      string `bun:"url"`
			Severity string `bun:"severity"`
		}
		q := qb.db.NewSelect().Model((*Finding)(nil)).
			ColumnExpr("f.id, f.url, f.severity").
			Where("f.id > ?", lastID).
			Where("COALESCE(f.record_kind, 'finding') = 'finding'").
			Where("COALESCE(f.status, 'triaged') NOT IN (?)", bun.List(dismissedForInventory)).
			Where("f.url IS NOT NULL AND f.url <> ''")
		if qb.filters.ProjectUUID != "" {
			q = q.Where("f.project_uuid = ?", qb.filters.ProjectUUID)
		}
		// A finding row has a hostname but no port or scheme column; the
		// endpoint lookup below keys on the full origin, so a finding on
		// another port of the same host attaches to nothing.
		if h := ParseHostFilter(qb.filters.HostPattern); h.Host != "" {
			pred, args := h.predicate("f.hostname", "", "")
			q = q.Where(pred, args...)
		}
		if err := q.OrderExpr("f.id ASC").Limit(inventoryPageSize).Scan(ctx, &page); err != nil {
			return err
		}
		for _, f := range page {
			u, err := url.Parse(f.URL)
			if err != nil || u.Host == "" {
				continue
			}
			port := 0
			if p := u.Port(); p != "" {
				port, _ = strconv.Atoi(p)
			}
			origin := EndpointOrigin(u.Scheme, u.Hostname(), port)
			template, _ := endpointShape(u.EscapedPath())
			acc := accs[endpointKey(origin, template)]
			if acc == nil && len(withVar) > 0 {
				acc = collapsedMatch(withVar, origin, template)
			}
			if acc == nil {
				continue
			}
			acc.findings++
			acc.bySev[strings.ToLower(f.Severity)]++
		}
		if len(page) < inventoryPageSize {
			return nil
		}
		lastID = page[len(page)-1].ID
	}
}

// --- collapse ---------------------------------------------------------------

// collapseVar is the placeholder a collapsed literal segment becomes.
const collapseVar = "{var}"

// collapseEndpoints merges sibling literal segments that share an identical
// set of child templates once at least n of them do, repeating until stable.
// /blog/a, /blog/b and /blog/c (all leaves) become /blog/{var} at n <= 3;
// /api/users/{int} and /api/orders/{int} collapse only if n <= 2.
func collapseEndpoints(accs map[string]*endpointAcc, n int) map[string]*endpointAcc {
	for changed := true; changed; {
		changed = false
		// parent key (origin + template prefix + segment index) → literal → child templates
		type group struct {
			children map[string]map[string]struct{}
		}
		groups := map[string]*group{}
		for _, a := range accs {
			parts := strings.Split(a.template, "/")
			for i, seg := range parts {
				if seg == "" || isTemplatePlaceholder(seg) {
					continue
				}
				pk := a.origin + " " + strings.Join(parts[:i], "/") + " " + strconv.Itoa(i)
				g := groups[pk]
				if g == nil {
					g = &group{children: map[string]map[string]struct{}{}}
					groups[pk] = g
				}
				set := g.children[seg]
				if set == nil {
					set = map[string]struct{}{}
					g.children[seg] = set
				}
				set["/"+strings.Join(parts[i+1:], "/")] = struct{}{}
			}
		}
		// collapse[parent key][literal] = true for every literal in a large-enough
		// sibling class.
		collapse := map[string]map[string]bool{}
		for pk, g := range groups {
			bySig := map[string][]string{}
			for lit, set := range g.children {
				sig := strings.Join(sortedSetKeys(set), "\x00")
				bySig[sig] = append(bySig[sig], lit)
			}
			for _, lits := range bySig {
				if len(lits) < n {
					continue
				}
				if collapse[pk] == nil {
					collapse[pk] = map[string]bool{}
				}
				for _, l := range lits {
					collapse[pk][l] = true
				}
			}
		}
		if len(collapse) == 0 {
			break
		}
		next := make(map[string]*endpointAcc, len(accs))
		for _, a := range accs {
			parts := strings.Split(a.template, "/")
			// Collapse the shallowest qualifying segment per pass; deeper ones are
			// re-evaluated against the merged result on the next pass.
			for i, seg := range parts {
				if seg == "" || isTemplatePlaceholder(seg) {
					continue
				}
				pk := a.origin + " " + strings.Join(parts[:i], "/") + " " + strconv.Itoa(i)
				if collapse[pk][seg] {
					parts[i] = collapseVar
					a.template = strings.Join(parts, "/")
					changed = true
					break
				}
			}
			key := endpointKey(a.origin, a.template)
			if dst := next[key]; dst != nil {
				dst.merge(a)
			} else {
				next[key] = a
			}
		}
		accs = next
	}
	return accs
}

func isTemplatePlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// collapsedCandidate is a collapsed endpoint with its template pre-split, so
// matching a finding against every candidate splits no candidate template.
type collapsedCandidate struct {
	acc   *endpointAcc
	parts []string
}

// collapsedMatch finds the collapsed endpoint a concrete template now belongs
// to: same origin, same segment count, every segment equal or {var}.
func collapsedMatch(candidates []collapsedCandidate, origin, template string) *endpointAcc {
	parts := strings.Split(template, "/")
	for _, c := range candidates {
		if c.acc.origin != origin {
			continue
		}
		ap := c.parts
		if len(ap) != len(parts) {
			continue
		}
		match := true
		for i := range ap {
			if ap[i] != parts[i] && ap[i] != collapseVar {
				match = false
				break
			}
		}
		if match {
			return c.acc
		}
	}
	return nil
}
