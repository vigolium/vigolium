package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

const (
	maxSourceMapBytes        = 8 * 1024 * 1024
	maxSourceMapSources      = 512
	maxSourceContentBytes    = 2 * 1024 * 1024
	maxAggregateSourceBytes  = 8 * 1024 * 1024
	maxIndexedSourceMapDepth = 4
)

var sourceMapCommentPattern = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)`)

type OriginalSource struct {
	Path               string
	Content            []byte
	ContentSHA256      string
	Language           string
	GeneratedSourceURL string
}

type sourceMapDocument struct {
	Version        int                `json:"version"`
	SourceRoot     string             `json:"sourceRoot"`
	Sources        []string           `json:"sources"`
	SourcesContent []*string          `json:"sourcesContent"`
	Mappings       string             `json:"mappings"`
	Sections       []sourceMapSection `json:"sections"`
}

type sourceMapSection struct {
	Map json.RawMessage `json:"map"`
}

type sourceMapBudget struct {
	sources int
	bytes   int
}

func ExtractSourceMapReference(source []byte) (reference string, inline []byte, ok bool) {
	matches := sourceMapCommentPattern.FindAllSubmatch(source, -1)
	if len(matches) == 0 {
		return "", nil, false
	}
	reference = strings.Trim(string(matches[len(matches)-1][1]), `"'`)
	if !strings.HasPrefix(reference, "data:") {
		return reference, nil, true
	}
	decoded, err := decodeSourceMapDataURL(reference)
	if err != nil {
		return "", nil, false
	}
	return "inline:source-map", decoded, true
}

func decodeSourceMapDataURL(value string) ([]byte, error) {
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil, fmt.Errorf("malformed source-map data URL")
	}
	metadata, payload := value[:comma], value[comma+1:]
	var decoded []byte
	var err error
	if strings.Contains(strings.ToLower(metadata), ";base64") {
		decoded, err = base64.StdEncoding.DecodeString(payload)
	} else {
		var unescaped string
		unescaped, err = url.PathUnescape(payload)
		decoded = []byte(unescaped)
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) > maxSourceMapBytes {
		return nil, fmt.Errorf("inline source map exceeds %d bytes", maxSourceMapBytes)
	}
	return decoded, nil
}

func ParseSourceMap(content []byte, generatedSourceURL string) ([]OriginalSource, error) {
	if len(content) == 0 || len(content) > maxSourceMapBytes {
		return nil, fmt.Errorf("source map size %d outside allowed range", len(content))
	}
	budget := &sourceMapBudget{}
	seen := make(map[string]struct{})
	sources, err := parseSourceMapDocument(content, generatedSourceURL, 0, budget, seen)
	if err != nil {
		return nil, err
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	return sources, nil
}

func parseSourceMapDocument(content []byte, generatedURL string, depth int, budget *sourceMapBudget, seen map[string]struct{}) ([]OriginalSource, error) {
	if depth > maxIndexedSourceMapDepth {
		return nil, fmt.Errorf("indexed source map nesting exceeds %d", maxIndexedSourceMapDepth)
	}
	var document sourceMapDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("decode source map: %w", err)
	}
	if document.Version != 3 {
		return nil, fmt.Errorf("unsupported source map version %d", document.Version)
	}
	if len(document.Mappings) > maxSourceMapBytes {
		return nil, fmt.Errorf("source map mappings exceed limit")
	}
	var result []OriginalSource
	for _, section := range document.Sections {
		if len(section.Map) == 0 {
			continue
		}
		sectionSources, err := parseSourceMapDocument(section.Map, generatedURL, depth+1, budget, seen)
		if err != nil {
			return nil, err
		}
		result = append(result, sectionSources...)
	}
	for index, rawPath := range document.Sources {
		budget.sources++
		if budget.sources > maxSourceMapSources {
			return nil, fmt.Errorf("source map source count exceeds %d", maxSourceMapSources)
		}
		if index >= len(document.SourcesContent) || document.SourcesContent[index] == nil {
			continue
		}
		content := []byte(*document.SourcesContent[index])
		if len(content) > maxSourceContentBytes {
			continue
		}
		budget.bytes += len(content)
		if budget.bytes > maxAggregateSourceBytes {
			return nil, fmt.Errorf("source map aggregate sourcesContent exceeds %d", maxAggregateSourceBytes)
		}
		safePath := normalizeSourcePath(document.SourceRoot, rawPath)
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		key := safePath + "\x00" + digest
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, OriginalSource{
			Path: safePath, Content: content, ContentSHA256: digest,
			Language: sourceLanguage(safePath), GeneratedSourceURL: generatedURL,
		})
	}
	return result, nil
}

func normalizeSourcePath(sourceRoot, source string) string {
	value := strings.ReplaceAll(strings.TrimSpace(source), "\\", "/")
	for _, prefix := range []string{"webpack://", "vite://", "file://"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	root := strings.ReplaceAll(strings.TrimSpace(sourceRoot), "\\", "/")
	value = path.Clean("/" + path.Join(root, value))
	value = strings.TrimLeft(value, "/")
	if value == "" || value == "." {
		value = "source.js"
	}
	if len(value) > 512 {
		value = value[len(value)-512:]
	}
	return value
}

func sourceLanguage(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".ts":
		return "ts"
	case ".tsx":
		return "tsx"
	case ".jsx":
		return "jsx"
	default:
		return "js"
	}
}

func annotateSourceMapProvenance(provenance *jstangle.Provenance, source OriginalSource) {
	if provenance == nil {
		return
	}
	provenance.ModulePath = source.Path
	for _, step := range provenance.ResolutionSteps {
		if step.Kind == "source-map" && step.Name == source.Path && step.Value == source.GeneratedSourceURL {
			return
		}
	}
	provenance.ResolutionSteps = append(provenance.ResolutionSteps, jstangle.ResolutionStep{
		Kind: "source-map", Name: source.Path, Value: source.GeneratedSourceURL,
	})
}

// annotateSourceMappedResult applies the original/generated source relationship
// uniformly to every typed record family before any fact is queued or persisted.
// Source locations already refer to the recovered original source; the bounded
// resolution step links those locations back to the generated bundle.
func annotateSourceMappedResult(result *jstangle.ScanResult, source OriginalSource) {
	if result == nil {
		return
	}
	for i := range result.RequestFacts {
		annotateSourceMapProvenance(&result.RequestFacts[i].Provenance, source)
	}
	for i := range result.DomFlowFacts {
		annotateSourceMapProvenance(&result.DomFlowFacts[i].Provenance, source)
	}
	for i := range result.AssetFacts {
		annotateSourceMapProvenance(&result.AssetFacts[i].Provenance, source)
	}
	for i := range result.GraphQLOperations {
		annotateSourceMapProvenance(&result.GraphQLOperations[i].Provenance, source)
	}
	for i := range result.WebSockets {
		annotateSourceMapProvenance(&result.WebSockets[i].Provenance, source)
	}
	for i := range result.EventSources {
		annotateSourceMapProvenance(&result.EventSources[i].Provenance, source)
	}
	for i := range result.ClientRoutes {
		annotateSourceMapProvenance(&result.ClientRoutes[i].Provenance, source)
	}
	for i := range result.BrowserFlows {
		annotateSourceMapProvenance(&result.BrowserFlows[i].Provenance, source)
	}
}

func (e *Engine) processAssetFacts(ctx context.Context, parentURL string, source []byte, facts []jstangle.AssetReferenceFact) {
	if len(facts) == 0 {
		return
	}
	graph := e.assetGraph()
	graph.AddRoot(parentURL, AssetScript)
	queued := make([]*url.URL, 0, len(facts))
	for _, fact := range facts {
		if fact.AssetType == string(AssetSourceMap) && !e.config.JSTangle.SourceMaps {
			continue
		}
		if fact.AssetType != string(AssetSourceMap) && !e.config.JSTangle.AssetGraph {
			continue
		}
		if fact.AssetType == string(AssetSourceMap) && fact.Inline {
			_, inline, ok := ExtractSourceMapReference(source)
			if ok && len(inline) > 0 {
				e.processSourceMapContent(ctx, parentURL, inline)
			}
			continue
		}
		resolved, added, reason := graph.Add(parentURL, fact.URL.Rendered, AssetKind(fact.AssetType))
		if !added {
			if reason != "duplicate-url" && reason != "" {
				logger.Debug("JS asset graph rejected reference", zap.String("parent", parentURL), zap.String("asset", fact.URL.Rendered), zap.String("reason", reason))
			}
			continue
		}
		if resolved == nil || e.spiderScope == nil || !e.spiderScope.IsInScope(resolved) {
			continue
		}
		if fact.AssetType != string(AssetWASM) {
			queued = append(queued, resolved)
		}
	}
	if len(queued) > 0 {
		e.queueJSFetch(queued, 0)
	}
}

func (e *Engine) processSourceMapResponse(ctx context.Context, mapURL *url.URL, content []byte) {
	if !e.config.JSTangle.SourceMaps || mapURL == nil || len(content) == 0 {
		return
	}
	parents := e.assetGraph().Parents(mapURL.String())
	if len(parents) == 0 {
		parents = []string{strings.TrimSuffix(mapURL.String(), ".map")}
	}
	for _, generatedURL := range parents {
		e.processSourceMapContent(ctx, generatedURL, content)
	}
}

func (e *Engine) processSourceMapContent(ctx context.Context, generatedURL string, content []byte) {
	if !e.config.JSTangle.SourceMaps {
		return
	}
	sources, err := ParseSourceMap(content, generatedURL)
	if err != nil {
		logger.Debug("Rejected source map", zap.String("generated_url", generatedURL), zap.Error(err))
		return
	}
	for _, source := range sources {
		if ctx.Err() != nil {
			return
		}
		virtualURL := generatedURL + "#source=" + url.QueryEscape(source.Path)
		if e.storage != nil {
			if repo := e.storage.Extractions(); repo != nil {
				var sourceNodeID int64
				if generated, parseErr := url.Parse(generatedURL); parseErr == nil {
					sourceNodeID = e.getNodeIDForURL(generated)
				}
				if storeErr := repo.StoreJSTangleSourceArtifact(&storage.JSTangleSourceArtifactModel{
					SourceNodeID: sourceNodeID, SessionID: e.storage.SessionDBID(),
					GeneratedURL: generatedURL, VirtualURL: virtualURL, SourcePath: source.Path,
					Language: source.Language, ContentSHA256: source.ContentSHA256, Content: string(source.Content),
				}); storeErr != nil {
					logger.Debug("Failed to store source-map artifact", zap.String("source", source.Path), zap.Error(storeErr))
				}
			}
		}
		if e.jstangleService == nil {
			continue
		}
		options := e.jsTangleOptions(jstangle.ProfileDiscovery, virtualURL)
		options.Filename = source.Path
		options.MediaType = "application/javascript"
		result, scanErr := e.jstangleService.ScanWithOptions(ctx, source.Content, options)
		if scanErr != nil || result == nil {
			continue
		}
		annotateSourceMappedResult(result, source)
		for i := range result.RequestFacts {
			e.AddRequestFact(virtualURL, result.RequestFacts[i])
		}
		e.processAssetFacts(ctx, virtualURL, source.Content, result.AssetFacts)
		e.processJSTangleCapabilityFacts(virtualURL, result)
		if generated, parseErr := url.Parse(generatedURL); parseErr == nil {
			e.storeJSTangleFactsAtSource(generated, virtualURL, result.RequestFacts)
		}
	}
}
