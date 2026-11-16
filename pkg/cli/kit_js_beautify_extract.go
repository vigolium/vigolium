package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Fact kinds `kit js-beautify --extract` reports, in output order. These are
// the JSON keys of kitBeautifyResult and the values --kinds accepts, so the
// flag, the counts map and the document cannot disagree about a name.
const (
	kitKindEndpoints = "endpoints"
	kitKindRoutes    = "routes"
	kitKindAssets    = "assets"
	kitKindGraphQL   = "graphql"
	kitKindRealtime  = "realtime"
	kitKindDOMFlows  = "dom_flows"
	kitKindPaths     = "paths"
	// kitKindSecrets is counted like a kind but selected by --secrets, not
	// --kinds: it needs no analysis pass, only the beautified text.
	kitKindSecrets = "secrets"
)

var kitBeautifyKinds = []string{
	kitKindEndpoints, kitKindRoutes, kitKindAssets, kitKindGraphQL,
	kitKindRealtime, kitKindDOMFlows, kitKindPaths,
}

// kitBeautifySummaryLimit bounds how many items of each kind the human-mode
// stderr summary lists; -j always carries every item.
const kitBeautifySummaryLimit = 20

// Path sources: which extractor saw a path. "both" is the agreement signal.
const (
	kitPathSourceJSTangle   = "jstangle"
	kitPathSourceLinkfinder = "linkfinder"
	kitPathSourceBoth       = "both"
)

// kitFactMeta is a fact's provenance, flattened. Every extracted item carries
// it, so a caller can rank any fact the same way without knowing its kind.
// Line and column are 1-based and absent when the extractor did not locate
// the fact (linkfinder never does).
type kitFactMeta struct {
	ID         string `json:"id,omitempty"`
	Confidence string `json:"confidence"`
	Extractor  string `json:"extractor"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	ModulePath string `json:"module_path,omitempty"`
}

func kitMetaFromProvenance(id string, p jstangle.Provenance) kitFactMeta {
	meta := kitFactMeta{ID: id, Confidence: p.Confidence, Extractor: p.Extractor, ModulePath: p.ModulePath}
	if p.Start != nil {
		meta.Line, meta.Column = p.Start.Line, p.Start.Column
	}
	return meta
}

// kitBeautifyEndpoint is the legacy flat request plus the provenance the typed
// fact carries. ExtractedRequest alone cannot say whether a method was resolved
// from the AST or guessed by a regex, which is the difference that decides
// whether a downstream planner should replay it. The typed fields beside it
// keep what the flat strings lose: which query values are variables, which
// headers are credentials, and where the credential comes from.
type kitBeautifyEndpoint struct {
	jstangle.ExtractedRequest
	kitFactMeta
	Client       string             `json:"client,omitempty"`
	Query        []kitTemplateField `json:"query,omitempty"`
	HeaderFields []kitTemplateField `json:"header_fields,omitempty"`
	BodyTemplate *kitBodyTemplate   `json:"body_template,omitempty"`
	Auth         *kitAuth           `json:"auth,omitempty"`
}

// kitTemplateField is one name/value pair of a request template. Static false
// means the value is (or contains) a variable the bundle fills at runtime.
type kitTemplateField struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Static    bool   `json:"static"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

type kitBodyTemplate struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Static      bool   `json:"static"`
	ContentType string `json:"content_type,omitempty"`
}

// kitAuth names where a request's credential comes from, never the credential.
type kitAuth struct {
	Kind       string `json:"kind"`
	Header     string `json:"header,omitempty"`
	Query      string `json:"query,omitempty"`
	Scheme     string `json:"scheme,omitempty"`
	Source     string `json:"source"`
	SourceKind string `json:"source_kind"`
}

// kitRoute is a client-side navigation candidate. FullPath is the absolute
// route with parents joined, when the helper could compute it.
type kitRoute struct {
	kitFactMeta
	Path      string   `json:"path"`
	FullPath  string   `json:"full_path,omitempty"`
	Type      string   `json:"type,omitempty"`
	Guards    []string `json:"guards,omitempty"`
	LazyAsset string   `json:"lazy_asset,omitempty"`
	ParentID  string   `json:"parent_id,omitempty"`
	// Meta is the route record's literal metadata (Vue `meta`, Angular
	// `data`): what a gate checks, e.g. requiresAuth or roles. A value the
	// bundle computes at runtime is null.
	Meta map[string]any `json:"meta,omitempty"`
	// Loader names a React Router data route's loader, or "<inline>".
	Loader string `json:"loader,omitempty"`
}

// kitAsset is a script-referenced asset: lazy chunk, worker, source map, ...
type kitAsset struct {
	kitFactMeta
	URL             string `json:"url"`
	Type            string `json:"type,omitempty"`
	Loader          string `json:"loader,omitempty"`
	Eager           bool   `json:"eager"`
	Inline          bool   `json:"inline,omitempty"`
	ParentSourceURL string `json:"parent_source_url,omitempty"`
	// Alternatives are other renderings of URL; for loader "template-import"
	// they are the concrete URLs enumerated from a literal map.
	Alternatives []string `json:"alternatives,omitempty"`
}

type kitGraphQLVariable struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type kitGraphQLOp struct {
	kitFactMeta
	OperationType      string               `json:"operation_type"`
	OperationName      string               `json:"operation_name,omitempty"`
	Endpoint           string               `json:"endpoint,omitempty"`
	Transport          string               `json:"transport,omitempty"`
	PersistedQueryHash string               `json:"persisted_query_hash,omitempty"`
	Variables          []kitGraphQLVariable `json:"variables,omitempty"`
	Document           string               `json:"document,omitempty"`
}

// kitRealtime is a WebSocket or EventSource endpoint; Protocol says which.
type kitRealtime struct {
	kitFactMeta
	Protocol        string   `json:"protocol"`
	URL             string   `json:"url"`
	Library         string   `json:"library,omitempty"`
	Subprotocols    []string `json:"subprotocols,omitempty"`
	EventNames      []string `json:"event_names,omitempty"`
	WithCredentials bool     `json:"with_credentials,omitempty"`
}

// kitFlow is a traced source→sink flow. FlowClass is "dom" (DOM-XSS taint)
// or "browser_security" (postMessage, storage, redirect, ... flows).
type kitFlow struct {
	kitFactMeta
	FlowClass string `json:"flow_class"`
	FlowType  string `json:"flow_type,omitempty"`
	Source    string `json:"source"`
	Sink      string `json:"sink"`
	Evidence  string `json:"evidence,omitempty"`
}

// kitPath is a path-shaped string from the jstangle pathLiteral pass, the Go
// linkfinder the scan path runs, or both.
type kitPath struct {
	kitFactMeta
	Path   string `json:"path"`
	Source string `json:"source"`
	Reason string `json:"reason,omitempty"`
	Key    string `json:"key,omitempty"`
}

// kitBeautifyKindSet resolves --kinds into the selected set. Empty means all.
// Dashes are accepted for underscores (dom-flows) because flags elsewhere in
// the CLI are dashed.
func kitBeautifyKindSet(requested []string) (map[string]bool, error) {
	set := make(map[string]bool, len(kitBeautifyKinds))
	if len(requested) == 0 {
		for _, kind := range kitBeautifyKinds {
			set[kind] = true
		}
		return set, nil
	}
	for _, raw := range requested {
		kind := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", "_")
		if kind == "" {
			continue
		}
		known := false
		for _, k := range kitBeautifyKinds {
			if k == kind {
				known = true
				break
			}
		}
		if !known {
			return nil, usageErrorf("--kinds: unknown kind %q (want any of: %s)", raw, strings.Join(kitBeautifyKinds, ", "))
		}
		set[kind] = true
	}
	return set, nil
}

// kitBeautifyEndpoints prefers the typed facts (which carry provenance) and
// falls back to the flat legacy list when a backend produced only that.
func kitBeautifyEndpoints(res *jstangle.ScanResult) []kitBeautifyEndpoint {
	if res == nil {
		return nil
	}
	if len(res.RequestFacts) > 0 {
		endpoints := make([]kitBeautifyEndpoint, 0, len(res.RequestFacts))
		for i := range res.RequestFacts {
			endpoints = append(endpoints, kitEndpointFromFact(res.RequestFacts[i]))
		}
		return endpoints
	}
	endpoints := make([]kitBeautifyEndpoint, 0, len(res.Requests))
	for _, request := range res.Requests {
		endpoints = append(endpoints, kitBeautifyEndpoint{ExtractedRequest: request})
	}
	return endpoints
}

func kitEndpointFromFact(fact jstangle.HTTPRequestFact) kitBeautifyEndpoint {
	endpoint := kitBeautifyEndpoint{
		ExtractedRequest: jstangle.LegacyRequestFromFact(fact),
		kitFactMeta:      kitMetaFromProvenance(fact.ID, fact.Provenance),
		Client:           fact.Client,
	}
	for _, field := range fact.Query {
		endpoint.Query = append(endpoint.Query, kitTemplateField{
			Name: field.Name.Rendered, Value: field.Value.Rendered, Static: field.Value.Static,
		})
	}
	for _, header := range fact.Headers {
		endpoint.HeaderFields = append(endpoint.HeaderFields, kitTemplateField{
			Name: header.Name.Rendered, Value: header.Value.Rendered,
			Static: header.Value.Static, Sensitive: header.Sensitive,
		})
	}
	if body := fact.Body; body != nil {
		endpoint.BodyTemplate = &kitBodyTemplate{
			Kind: body.Kind, Value: body.Value.Rendered, Static: body.Value.Static, ContentType: body.ContentType,
		}
	}
	if auth := fact.Auth; auth != nil {
		endpoint.Auth = &kitAuth{
			Kind: auth.Kind, Header: auth.Header, Query: auth.Query, Scheme: auth.Scheme,
			Source: auth.Source, SourceKind: auth.SourceKind,
		}
	}
	return endpoint
}

func kitBeautifyRoutes(res *jstangle.ScanResult) []kitRoute {
	routes := make([]kitRoute, 0, len(res.ClientRoutes))
	for i := range res.ClientRoutes {
		fact := &res.ClientRoutes[i]
		route := kitRoute{
			kitFactMeta: kitMetaFromProvenance(fact.ID, fact.Provenance),
			Path:        fact.Path.Rendered,
			Type:        fact.RouteType,
			Guards:      fact.Guards,
			ParentID:    fact.ParentID,
			Meta:        fact.Meta,
			Loader:      fact.Loader,
		}
		if fact.FullPath != nil {
			route.FullPath = fact.FullPath.Rendered
		}
		if fact.LazyAsset != nil {
			route.LazyAsset = fact.LazyAsset.Rendered
		}
		routes = append(routes, route)
	}
	return routes
}

func kitBeautifyAssets(res *jstangle.ScanResult) []kitAsset {
	assets := make([]kitAsset, 0, len(res.AssetFacts))
	for _, fact := range res.AssetFacts {
		assets = append(assets, kitAsset{
			kitFactMeta:     kitMetaFromProvenance(fact.ID, fact.Provenance),
			URL:             fact.URL.Rendered,
			Type:            fact.AssetType,
			Loader:          fact.Loader,
			Alternatives:    fact.URL.Alternatives,
			Eager:           fact.Eager,
			Inline:          fact.Inline,
			ParentSourceURL: fact.ParentSourceURL,
		})
	}
	return assets
}

func kitBeautifyGraphQL(res *jstangle.ScanResult) []kitGraphQLOp {
	ops := make([]kitGraphQLOp, 0, len(res.GraphQLOperations))
	for _, fact := range res.GraphQLOperations {
		op := kitGraphQLOp{
			kitFactMeta:        kitMetaFromProvenance(fact.ID, fact.Provenance),
			OperationType:      fact.OperationType,
			OperationName:      fact.OperationName,
			Transport:          fact.Transport,
			PersistedQueryHash: fact.PersistedQueryHash,
			Document:           fact.Document,
		}
		if fact.Endpoint != nil {
			op.Endpoint = fact.Endpoint.Rendered
		}
		for _, variable := range fact.Variables {
			op.Variables = append(op.Variables, kitGraphQLVariable{
				Name: variable.Name, Type: variable.Type, Required: variable.Required,
			})
		}
		ops = append(ops, op)
	}
	return ops
}

func kitBeautifyRealtime(res *jstangle.ScanResult) []kitRealtime {
	realtime := make([]kitRealtime, 0, len(res.WebSockets)+len(res.EventSources))
	for _, fact := range res.WebSockets {
		realtime = append(realtime, kitRealtime{
			kitFactMeta:  kitMetaFromProvenance(fact.ID, fact.Provenance),
			Protocol:     "websocket",
			URL:          fact.URL.Rendered,
			Library:      fact.Library,
			Subprotocols: fact.Subprotocols,
			EventNames:   fact.InboundEventNames,
		})
	}
	for _, fact := range res.EventSources {
		realtime = append(realtime, kitRealtime{
			kitFactMeta:     kitMetaFromProvenance(fact.ID, fact.Provenance),
			Protocol:        "sse",
			URL:             fact.URL.Rendered,
			Library:         fact.Library,
			EventNames:      fact.EventNames,
			WithCredentials: fact.WithCredentials,
		})
	}
	return realtime
}

// kitBeautifyFlows merges DOM-XSS taint flows and other browser security
// flows. Like endpoints, it falls back to the legacy flat flows when a backend
// produced no typed ones.
func kitBeautifyFlows(res *jstangle.ScanResult) []kitFlow {
	flows := make([]kitFlow, 0, len(res.DomFlowFacts)+len(res.BrowserFlows))
	for _, fact := range res.DomFlowFacts {
		meta := kitMetaFromProvenance(fact.ID, fact.Provenance)
		if meta.Confidence == "" {
			meta.Confidence = fact.Confidence
		}
		if meta.Line == 0 {
			meta.Line = fact.Line
		}
		flows = append(flows, kitFlow{
			kitFactMeta: meta, FlowClass: "dom", FlowType: fact.FlowType,
			Source: fact.Source, Sink: fact.Sink, Evidence: fact.Snippet,
		})
	}
	if len(res.DomFlowFacts) == 0 {
		for _, flow := range res.DomFlows {
			flows = append(flows, kitFlow{
				kitFactMeta: kitFactMeta{Line: flow.Line}, FlowClass: "dom", FlowType: flow.FlowType,
				Source: flow.Source, Sink: flow.Sink, Evidence: flow.Snippet,
			})
		}
	}
	for _, fact := range res.BrowserFlows {
		meta := kitMetaFromProvenance(fact.ID, fact.Provenance)
		if meta.Confidence == "" {
			meta.Confidence = fact.Confidence
		}
		flows = append(flows, kitFlow{
			kitFactMeta: meta, FlowClass: "browser_security", FlowType: fact.FlowType,
			Source: fact.Source, Sink: fact.Sink, Evidence: fact.Evidence,
		})
	}
	return flows
}

// kitPathKey is the merge key shared by both path extractors. It runs a
// jstangle literal through the same template normalization linkfinder
// applies to its own output (`${id}` → 1), then drops the query, fragment
// and trailing slash, so `/api/users/${id}` and linkfinder's `/api/users/1`
// meet on one key.
func kitPathKey(path string) string {
	key := strings.TrimSpace(path)
	if normalized := linkfinder.NormalizePathTemplates(key); len(normalized) > 0 {
		key = normalized[0]
	}
	if i := strings.IndexAny(key, "?#"); i >= 0 {
		key = key[:i]
	}
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}
	if len(key) > 1 {
		key = strings.TrimRight(key, "/")
		if key == "" {
			key = "/"
		}
	}
	return key
}

// kitBeautifyPaths merges the jstangle pathLiteral facts with the scan path's
// Go linkfinder run over content. jstangle items keep their order, provenance
// and template spelling; a linkfinder hit on the same key upgrades the item's
// source to "both". Linkfinder-only paths follow, sorted, at low confidence.
func kitBeautifyPaths(res *jstangle.ScanResult, content []byte) []kitPath {
	var paths []kitPath
	index := make(map[string]int)
	if res != nil {
		for _, fact := range res.PathLiterals {
			value := fact.Value.Rendered
			if strings.TrimSpace(value) == "" {
				continue
			}
			key := kitPathKey(value)
			if _, dup := index[key]; dup {
				continue
			}
			index[key] = len(paths)
			paths = append(paths, kitPath{
				kitFactMeta: kitMetaFromProvenance(fact.ID, fact.Provenance),
				Path:        value,
				Source:      kitPathSourceJSTangle,
				Reason:      fact.Reason,
				Key:         fact.Key,
			})
		}
	}

	found := discovery.ExtractJSPaths(content)
	sort.Strings(found)
	for _, path := range found {
		if strings.TrimSpace(path) == "" {
			continue
		}
		key := kitPathKey(path)
		if at, seen := index[key]; seen {
			if paths[at].Source == kitPathSourceJSTangle {
				paths[at].Source = kitPathSourceBoth
			}
			continue
		}
		index[key] = len(paths)
		paths = append(paths, kitPath{
			kitFactMeta: kitFactMeta{Confidence: "low", Extractor: "linkfinder"},
			Path:        path,
			Source:      kitPathSourceLinkfinder,
		})
	}
	return paths
}

// kitBeautifyTruncated merges per-kind truncation counts from the completion
// record and the analysis stats; either may be the only one an older helper
// (or the service's own cap detection) filled in.
func kitBeautifyTruncated(res *jstangle.ScanResult) map[string]int {
	if res == nil {
		return nil
	}
	merged := map[string]int{}
	add := func(counts map[string]int) {
		for kind, n := range counts {
			if n > merged[kind] {
				merged[kind] = n
			}
		}
	}
	if res.Completion != nil {
		add(res.Completion.Counts.Truncated)
	}
	if res.Analysis != nil {
		add(res.Analysis.Stats.Truncated)
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// kitBeautifyLinkfinderInput is what the scan path feeds linkfinder: the
// helper's transformed code when it returned some, else the raw input.
func kitBeautifyLinkfinderInput(res *jstangle.ScanResult, raw []byte) []byte {
	if res != nil && res.Code != nil && res.Code.Content != "" {
		return []byte(res.Code.Content)
	}
	return raw
}

// kitPopulateBeautifyFacts fills every selected fact kind and its count.
// Counts are present for each selected kind, zero included, so an absent
// list under --extract means "none found", never "not looked for".
func kitPopulateBeautifyFacts(result *kitBeautifyResult, res *jstangle.ScanResult, raw []byte, kinds map[string]bool) {
	if result.Counts == nil {
		result.Counts = map[string]int{}
	}
	empty := &jstangle.ScanResult{}
	facts := res
	if facts == nil {
		facts = empty
	}
	if kinds[kitKindEndpoints] {
		result.Endpoints = kitBeautifyEndpoints(facts)
		result.Counts[kitKindEndpoints] = len(result.Endpoints)
	}
	if kinds[kitKindRoutes] {
		result.Routes = kitBeautifyRoutes(facts)
		result.Counts[kitKindRoutes] = len(result.Routes)
	}
	if kinds[kitKindAssets] {
		result.Assets = kitBeautifyAssets(facts)
		result.Counts[kitKindAssets] = len(result.Assets)
	}
	if kinds[kitKindGraphQL] {
		result.GraphQL = kitBeautifyGraphQL(facts)
		result.Counts[kitKindGraphQL] = len(result.GraphQL)
	}
	if kinds[kitKindRealtime] {
		result.Realtime = kitBeautifyRealtime(facts)
		result.Counts[kitKindRealtime] = len(result.Realtime)
	}
	if kinds[kitKindDOMFlows] {
		result.DOMFlows = kitBeautifyFlows(facts)
		result.Counts[kitKindDOMFlows] = len(result.DOMFlows)
	}
	if kinds[kitKindPaths] {
		result.Paths = kitBeautifyPaths(res, kitBeautifyLinkfinderInput(res, raw))
		result.Counts[kitKindPaths] = len(result.Paths)
	}
	result.Truncated = kitBeautifyTruncated(res)
}

// kitBeautifySecrets runs the embedded secret catalog over the beautified
// text: per recovered module when the bundle splits (so file and line point
// into the module), else over the whole document. When beautification
// changed nothing the document is the raw input, so raw is covered without a
// second pass reporting the same secret at shifted offsets. Matches are
// deduped by rule and value, first occurrence kept, and the value is redacted
// unless reveal is set.
func kitBeautifySecrets(detector *secretscan.Detector, res *jstangle.ScanResult, label, content string, reveal bool) []kitSecretMatch {
	type unit struct{ file, content string }
	var units []unit
	if res != nil && res.HasBeautified() {
		for _, module := range res.Beautified.Modules() {
			units = append(units, unit{file: module.Path, content: module.Content})
		}
	}
	if len(units) == 0 {
		units = []unit{{file: label, content: content}}
	}

	matches := []kitSecretMatch{}
	seen := make(map[string]bool)
	for _, u := range units {
		data := []byte(u.content)
		for _, m := range detector.Detect(data) {
			sum := sha256.Sum256([]byte(m.RuleID + "\x00" + m.Secret))
			hash := hex.EncodeToString(sum[:])
			if seen[hash] {
				continue
			}
			seen[hash] = true
			secret := m.Secret
			if !reveal {
				secret = redactSecret(secret)
			}
			matches = append(matches, kitSecretMatch{
				RuleID:     m.RuleID,
				RuleName:   m.RuleName,
				Confidence: m.Confidence,
				Secret:     secret,
				Entropy:    m.Entropy,
				File:       u.file,
				Line:       lineOfOffset(data, m.Start),
				Start:      m.Start,
				End:        m.End,
			})
		}
	}
	return matches
}

// kitPrintBeautifySummary writes the human-mode per-kind summary: a count
// line for every reported kind, then the first kitBeautifySummaryLimit items
// of each non-empty one. It goes to stderr; stdout carries only the source.
func kitPrintBeautifySummary(w io.Writer, result *kitBeautifyResult) {
	if len(result.Counts) == 0 {
		return
	}
	order := append(append([]string{}, kitBeautifyKinds...), kitKindSecrets)
	var parts []string
	for _, kind := range order {
		if n, ok := result.Counts[kind]; ok {
			parts = append(parts, fmt.Sprintf("%d %s", n, kind))
		}
	}
	_, _ = fmt.Fprintf(w, "\n%s extracted: %s\n", terminal.InfoSymbol(), strings.Join(parts, ", "))
	truncatedKinds := make([]string, 0, len(result.Truncated))
	for kind := range result.Truncated {
		truncatedKinds = append(truncatedKinds, kind)
	}
	sort.Strings(truncatedKinds)
	for _, kind := range truncatedKinds {
		_, _ = fmt.Fprintf(w, "%s %s capped: %d record(s) dropped by the analyzer\n",
			terminal.WarningSymbol(), kind, result.Truncated[kind])
	}

	section := func(kind string, lines []string) {
		if len(lines) == 0 {
			return
		}
		_, _ = fmt.Fprintf(w, "\n%s (%d):\n", kind, len(lines))
		for i, line := range lines {
			if i == kitBeautifySummaryLimit {
				_, _ = fmt.Fprintf(w, "  … %d more (use -j for all)\n", len(lines)-i)
				break
			}
			_, _ = fmt.Fprintln(w, "  "+line)
		}
	}
	suffix := func(meta kitFactMeta) string {
		out := ""
		if meta.ModulePath != "" {
			out += "  (" + meta.ModulePath + ")"
		}
		if meta.Confidence != "" {
			out += "  [" + meta.Confidence + "]"
		}
		return out
	}

	var lines []string
	for _, e := range result.Endpoints {
		method := e.Method
		if method == "" {
			method = "?" // unresolved, not a guess
		}
		line := fmt.Sprintf("%-6s %s", method, e.URL)
		if e.Auth != nil {
			line += "  auth=" + e.Auth.Kind + ":" + e.Auth.Source
		}
		lines = append(lines, line+suffix(e.kitFactMeta))
	}
	section(kitKindEndpoints, lines)

	lines = nil
	for _, r := range result.Routes {
		path := r.Path
		if r.FullPath != "" {
			path = r.FullPath
		}
		line := path
		if r.Type != "" {
			line += "  <" + r.Type + ">"
		}
		lines = append(lines, line+suffix(r.kitFactMeta))
	}
	section(kitKindRoutes, lines)

	lines = nil
	for _, a := range result.Assets {
		line := a.URL
		if a.Type != "" {
			line += "  <" + a.Type + ">"
		}
		if a.Loader != "" {
			line += "  loader=" + a.Loader
		}
		lines = append(lines, line+suffix(a.kitFactMeta))
	}
	section(kitKindAssets, lines)

	lines = nil
	for _, g := range result.GraphQL {
		line := g.OperationType
		if g.OperationName != "" {
			line += " " + g.OperationName
		}
		if g.Endpoint != "" {
			line += "  → " + g.Endpoint
		}
		lines = append(lines, line+suffix(g.kitFactMeta))
	}
	section(kitKindGraphQL, lines)

	lines = nil
	for _, r := range result.Realtime {
		lines = append(lines, fmt.Sprintf("%-9s %s", r.Protocol, r.URL)+suffix(r.kitFactMeta))
	}
	section(kitKindRealtime, lines)

	lines = nil
	for _, f := range result.DOMFlows {
		lines = append(lines, fmt.Sprintf("%s → %s  <%s>", f.Source, f.Sink, f.FlowClass)+suffix(f.kitFactMeta))
	}
	section(kitKindDOMFlows, lines)

	lines = nil
	for _, p := range result.Paths {
		lines = append(lines, p.Path+"  {"+p.Source+"}"+suffix(p.kitFactMeta))
	}
	section(kitKindPaths, lines)

	lines = nil
	for _, s := range result.Secrets {
		lines = append(lines, fmt.Sprintf("[%s] %s  %s  (%s:%d)", s.Confidence, s.RuleName, s.Secret, s.File, s.Line))
	}
	section(kitKindSecrets, lines)
}
