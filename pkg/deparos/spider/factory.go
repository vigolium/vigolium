package spider

// ExtractorFactory creates and wires spider components with dependency injection.
//
// The factory pattern ensures correct component assembly and dependency sharing:
//   - Shared components (InlineURLScanner, HTMLAttributeExtractor, JavaScriptStringExtractor)
//     are created once and injected into multiple extractors
//   - Each extractor receives properly configured dependencies
//   - The coordinator receives all extractors in the correct execution order
type ExtractorFactory struct {
	urlResolver *URLResolver
}

// NewExtractorFactory creates a factory with core dependencies.
func NewExtractorFactory(urlResolver *URLResolver) *ExtractorFactory {
	return &ExtractorFactory{
		urlResolver: urlResolver,
	}
}

// CreateCoordinator assembles all spider components and returns a configured coordinator.
//
// Component creation order:
//  1. Create shared InlineURLScanner (used by 5 extractors)
//  2. Create shared HTMLAttributeExtractor (used by JavaScriptStringExtractor)
//  3. Create shared JavaScriptStringExtractor (used by 2 extractors)
//  4. Create remaining extractors with their dependencies
//  5. Wire coordinator with all extractors in execution order
//
// Returns configured ExtractionCoordinator ready for use.
func (f *ExtractorFactory) CreateCoordinator() *ExtractionCoordinator {
	// Step 1: Create shared InlineURLScanner
	// This component is injected into 5 extractors:
	// - JavaScriptStringExtractor, EventHandlersExtractor, MetaRefreshExtractor,
	//   ScriptContentExtractor, CommentsExtractor
	inlineScanner := NewInlineURLScanner(f.urlResolver)

	// Step 2: Create shared HTMLAttributeExtractor
	// This is injected into JavaScriptStringExtractor
	// Note: HTMLAttributeExtractor does NOT check scope - caller handles scope filtering
	htmlExtractor := NewHTMLAttributeExtractor(f.urlResolver)

	// Step 3: Create shared JavaScriptStringExtractor
	// This is injected into EventHandlersExtractor and ScriptContentExtractor
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)

	// Step 4: Create extractors with dependencies
	eventHandlers := NewEventHandlersExtractor(inlineScanner, jsExtractor)
	metaRefresh := NewMetaRefreshExtractor(inlineScanner)
	scriptContent := NewScriptContentExtractor(inlineScanner, jsExtractor)
	comments := NewCommentsExtractor(inlineScanner)
	robotsParser := NewRobotsTxtParser(f.urlResolver)
	httpHeaders := NewHTTPHeaderExtractor(f.urlResolver)

	// FormExtractor: Extracts actionable form submissions from HTML
	formExtractor := NewFormExtractor(f.urlResolver)

	// Step 5: Assemble coordinator with all extractors
	// The coordinator orchestrates extraction in the correct order
	return NewExtractionCoordinator(
		inlineScanner,
		httpHeaders,
		htmlExtractor,
		comments,
		robotsParser,
		jsExtractor,
		eventHandlers,
		metaRefresh,
		scriptContent,
		formExtractor,
	)
}
