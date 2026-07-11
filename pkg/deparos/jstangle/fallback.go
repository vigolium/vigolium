package jstangle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	maxFallbackAssets    = 256
	maxFallbackURLLength = 2048
)

var (
	fallbackSourceMapRE     = regexp.MustCompile(`(?m)//[@#]\s*sourceMappingURL=([^\s]+)`)
	fallbackImportRE        = regexp.MustCompile(`\bimport\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)
	fallbackWorkerRE        = regexp.MustCompile(`\bnew\s+(Worker|SharedWorker)\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)
	fallbackServiceRE       = regexp.MustCompile(`\bserviceWorker\.register\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)
	fallbackImportScriptsRE = regexp.MustCompile(`\bimportScripts\s*\(([^)]{1,1000})\)`)
	fallbackQuotedRE        = regexp.MustCompile(`["'\x60]([^"'\x60]+)["'\x60]`)
	fallbackFetchAssetRE    = regexp.MustCompile(`\bfetch\s*\(\s*["'\x60]([^"'\x60]+\.(?:wasm|json))(?:\?[^"'\x60]*)?["'\x60]`)
	fallbackEndpointRE      = regexp.MustCompile(`["'\x60]((?:(?:https?:)?//[^"'\x60\s]+)?/(?:api(?:/|\b)|graphql(?:/|\b)|v[0-9]+/)[^"'\x60\s]{0,1000})["'\x60]`)
	fallbackTemplateVarRE   = regexp.MustCompile(`\$\{([^}]+)\}`)
)

// cheapFallbackAnalysis avoids Babel for very large inputs while preserving
// bounded asset-graph and high-signal endpoint-hint coverage. Endpoint facts
// are deliberately low confidence, so discovery never replays them directly.
func cheapFallbackAnalysis(content []byte, options ScanOptions, toolSourceHash string) *ScanResult {
	return cheapFallbackAnalysisWithReason(
		content, options, toolSourceHash,
		"ast_analysis_skipped_very_large",
		fmt.Sprintf("input %d bytes exceeded the AST soft limit; used bounded string and manifest extraction", len(content)),
	)
}

func cheapFallbackAnalysisWithReason(content []byte, options ScanOptions, toolSourceHash, reasonCode, reasonMessage string) *ScanResult {
	started := time.Now()
	source := string(content)
	contentDigest := sha256.Sum256(content)
	contentSHA := hex.EncodeToString(contentDigest[:])
	diagnostic := Diagnostic{
		Type: "diagnostic", Severity: "warning", Stage: "admission",
		Code:        reasonCode,
		Message:     reasonMessage,
		Recoverable: true,
	}
	result := &ScanResult{Requests: []ExtractedRequest{}, Diagnostics: []Diagnostic{diagnostic}, BytesScanned: len(content)}

	wantsEndpoints := options.Profile != ProfileDOMSecurity && options.Profile != ProfileBeautify
	wantsAssets := options.Profile == ProfileDiscovery || options.Profile == ProfileDiscoveryLite ||
		options.Profile == ProfileFull || options.Profile == ProfileInspect
	if wantsEndpoints {
		seen := make(map[string]struct{})
		for _, match := range fallbackEndpointRE.FindAllStringSubmatch(source, options.MaxRequests+1) {
			if len(result.RequestFacts) >= options.MaxRequests || len(match) < 2 {
				break
			}
			rawURL := strings.TrimSpace(match[1])
			if rawURL == "" || len(rawURL) > maxFallbackURLLength {
				continue
			}
			if _, exists := seen[rawURL]; exists {
				continue
			}
			seen[rawURL] = struct{}{}
			id := fallbackID("http-fallback", rawURL)
			fact := HTTPRequestFact{
				Kind: "httpRequest", ID: id, URL: fallbackValueTemplate(rawURL),
				Method: ValueTemplate{Rendered: "GET", Static: true}, Client: "generic",
				Provenance: Provenance{Extractor: "large-input-string-fallback", Confidence: "low", Evidence: truncateFallbackEvidence(rawURL)},
			}
			result.RequestFacts = append(result.RequestFacts, fact)
			result.Requests = append(result.Requests, legacyRequestFromFact(fact))
		}
	}
	if wantsAssets {
		seen := make(map[string]struct{})
		add := func(assetType, rawURL, extractor string, inline bool) {
			if len(result.AssetFacts) >= maxFallbackAssets {
				return
			}
			rawURL = strings.TrimSpace(rawURL)
			if rawURL == "" || len(rawURL) > maxFallbackURLLength {
				return
			}
			key := assetType + "\x00" + rawURL
			if _, exists := seen[key]; exists {
				return
			}
			seen[key] = struct{}{}
			result.AssetFacts = append(result.AssetFacts, AssetReferenceFact{
				Kind: "assetReference", ID: fallbackID("asset-fallback", key), AssetType: assetType,
				URL: fallbackValueTemplate(rawURL), ParentSourceURL: options.SourceURL,
				Eager: assetType == "script", Inline: inline,
				Provenance: Provenance{Extractor: extractor, Confidence: "medium", Evidence: truncateFallbackEvidence(rawURL)},
			})
		}
		for _, match := range fallbackSourceMapRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(match) > 1 {
				add("source-map", match[1], "source-map-comment-fallback", strings.HasPrefix(match[1], "data:"))
			}
		}
		for _, match := range fallbackImportRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(match) > 1 {
				add("dynamic-import", match[1], "dynamic-import-fallback", false)
			}
		}
		for _, match := range fallbackWorkerRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(match) > 2 {
				kind := "worker"
				if match[1] == "SharedWorker" {
					kind = "shared-worker"
				}
				add(kind, match[2], "worker-constructor-fallback", false)
			}
		}
		for _, match := range fallbackServiceRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(match) > 1 {
				add("service-worker", match[1], "service-worker-fallback", false)
			}
		}
		for _, call := range fallbackImportScriptsRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(call) < 2 {
				continue
			}
			for _, match := range fallbackQuotedRE.FindAllStringSubmatch(call[1], maxFallbackAssets+1) {
				if len(match) > 1 {
					add("script", match[1], "import-scripts-fallback", false)
				}
			}
		}
		for _, match := range fallbackFetchAssetRE.FindAllStringSubmatch(source, maxFallbackAssets+1) {
			if len(match) > 1 {
				kind := "config"
				if strings.Contains(strings.ToLower(match[1]), ".wasm") {
					kind = "wasm"
				}
				add(kind, match[1], "fetch-asset-fallback", false)
			}
		}
	}

	records := make([]json.RawMessage, 0, len(result.RequestFacts)+len(result.AssetFacts))
	for i := range result.RequestFacts {
		if encoded, err := json.Marshal(&result.RequestFacts[i]); err == nil {
			records = append(records, encoded)
		}
	}
	for i := range result.AssetFacts {
		if encoded, err := json.Marshal(&result.AssetFacts[i]); err == nil {
			records = append(records, encoded)
		}
	}
	analysis := &AnalysisResultV2{
		Type: "analysisResult", SchemaVersion: 2, JobID: "fallback-" + contentSHA[:20], Profile: options.Profile,
		Source:      SourceDescriptor{URL: options.SourceURL, Filename: options.Filename, MediaType: options.MediaType, ContentSHA256: contentSHA, ByteLength: int64(len(content))},
		Diagnostics: []Diagnostic{diagnostic}, Records: records,
	}
	analysis.Tool.SourceHash = toolSourceHash
	analysis.Stats.Status = "partial"
	analysis.Stats.InputBytes = int64(len(content))
	analysis.Stats.RecordCounts = map[string]int{"httpRequest": len(result.RequestFacts), "assetReference": len(result.AssetFacts)}
	result.Analysis = analysis
	completion := &ScanCompletion{Type: "scanCompleted", ProtocolVersion: ProtocolVersion, SchemaVersion: 2, ScanID: analysis.JobID, Profile: options.Profile, Status: "partial", ReasonCode: diagnostic.Code}
	completion.Counts.Requests = len(result.RequestFacts)
	completion.Counts.Diagnostics = 1
	result.Completion = completion
	result.ScanDuration = time.Since(started)
	return result
}

func fallbackID(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + "-" + hex.EncodeToString(digest[:10])
}

func fallbackValueTemplate(rendered string) ValueTemplate {
	matches := fallbackTemplateVarRE.FindAllStringSubmatch(rendered, 16)
	variables := make([]TemplateVariable, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		placeholder := "${" + match[1] + "}"
		if _, exists := seen[placeholder]; exists {
			continue
		}
		seen[placeholder] = struct{}{}
		variables = append(variables, TemplateVariable{Name: match[1], Placeholder: placeholder})
	}
	return ValueTemplate{Rendered: rendered, Static: len(variables) == 0, Variables: variables}
}

func truncateFallbackEvidence(value string) string {
	if len(value) <= 512 {
		return value
	}
	return value[:512]
}
