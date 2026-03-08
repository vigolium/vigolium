package spider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExtractorFactory(t *testing.T) {
	resolver := NewURLResolver()

	factory := NewExtractorFactory(resolver)

	require.NotNil(t, factory)
	assert.Equal(t, resolver, factory.urlResolver)
}

func TestExtractorFactory_CreateCoordinator(t *testing.T) {
	resolver := NewURLResolver()

	factory := NewExtractorFactory(resolver)
	coordinator := factory.CreateCoordinator()

	require.NotNil(t, coordinator, "coordinator should not be nil")

	// Verify all components are initialized
	assert.NotNil(t, coordinator.inlineScanner, "inline scanner should be initialized")
	assert.NotNil(t, coordinator.httpHeaders, "HTTP headers extractor should be initialized")
	assert.NotNil(t, coordinator.htmlAttrs, "HTML attributes extractor should be initialized")
	assert.NotNil(t, coordinator.comments, "comments extractor should be initialized")
	assert.NotNil(t, coordinator.robotsParser, "robots parser should be initialized")
	assert.NotNil(t, coordinator.jsExtractor, "JS extractor should be initialized")
	assert.NotNil(t, coordinator.eventHandlers, "event handlers extractor should be initialized")
	assert.NotNil(t, coordinator.metaRefresh, "meta refresh extractor should be initialized")
	assert.NotNil(t, coordinator.scriptContent, "script content extractor should be initialized")
}

func TestExtractorFactory_ComponentSharing(t *testing.T) {
	resolver := NewURLResolver()

	factory := NewExtractorFactory(resolver)
	coordinator := factory.CreateCoordinator()

	// Verify inline scanner is shared
	assert.NotNil(t, coordinator.inlineScanner)
	assert.Equal(t, resolver, coordinator.inlineScanner.urlResolver)

	// Verify HTML extractor is shared
	assert.NotNil(t, coordinator.htmlAttrs)
	assert.Equal(t, resolver, coordinator.htmlAttrs.urlResolver)

	// Verify JS extractor is shared
	assert.NotNil(t, coordinator.jsExtractor)
	assert.NotNil(t, coordinator.jsExtractor.inlineScanner)
	assert.NotNil(t, coordinator.jsExtractor.htmlExtractor)

	// Verify event handlers depends on inlineScanner and jsExtractor
	assert.NotNil(t, coordinator.eventHandlers)
	assert.NotNil(t, coordinator.eventHandlers.inlineScanner)
	assert.NotNil(t, coordinator.eventHandlers.jsExtractor)

	// Verify meta refresh depends on inlineScanner
	assert.NotNil(t, coordinator.metaRefresh)
	assert.NotNil(t, coordinator.metaRefresh.inlineScanner)

	// Verify script content depends on inlineScanner and jsExtractor
	assert.NotNil(t, coordinator.scriptContent)
	assert.NotNil(t, coordinator.scriptContent.inlineScanner)
	assert.NotNil(t, coordinator.scriptContent.jsExtractor)

	// Verify comments depends on inlineScanner
	assert.NotNil(t, coordinator.comments)
	assert.NotNil(t, coordinator.comments.inlineScanner)

	// Verify robots parser
	assert.NotNil(t, coordinator.robotsParser)
	assert.Equal(t, resolver, coordinator.robotsParser.urlResolver)

	// Verify HTTP headers extractor
	assert.NotNil(t, coordinator.httpHeaders)
	assert.Equal(t, resolver, coordinator.httpHeaders.urlResolver)
}

func TestExtractorFactory_AllComponentsInitialized(t *testing.T) {
	resolver := NewURLResolver()

	factory := NewExtractorFactory(resolver)
	coordinator := factory.CreateCoordinator()

	// All components should be present
	componentCount := 0
	if coordinator.inlineScanner != nil {
		componentCount++
	}
	if coordinator.httpHeaders != nil {
		componentCount++
	}
	if coordinator.htmlAttrs != nil {
		componentCount++
	}
	if coordinator.comments != nil {
		componentCount++
	}
	if coordinator.robotsParser != nil {
		componentCount++
	}
	if coordinator.jsExtractor != nil {
		componentCount++
	}
	if coordinator.eventHandlers != nil {
		componentCount++
	}
	if coordinator.metaRefresh != nil {
		componentCount++
	}
	if coordinator.scriptContent != nil {
		componentCount++
	}

	// We expect 9 extractors
	assert.Equal(t, 9, componentCount, "all 9 extractors should be initialized")
}
