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
// Component creation follows Burp's exact dependency injection pattern:
//  1. Create shared InlineURLScanner (used by 5 extractors)
//  2. Create shared HTMLAttributeExtractor (used by JavaScriptStringExtractor)
//  3. Create shared JavaScriptStringExtractor (used by 2 extractors)
//  4. Create remaining extractors with their dependencies
//  5. Wire coordinator with all extractors in execution order
//
// Burp mapping: vs.java constructor lines 11-30
//
// Burp component mapping:
//   - Line 12: uc var4 = new uc(var2)                     → InlineURLScanner
//   - Line 14: g88 var5 = new g88(var2)                   → HTMLAttributeExtractor
//   - Line 15: c13 var6 = new c13(var4, var5)             → JavaScriptStringExtractor
//   - Line 17: hjn var7 = new hjn(var4, var6)             → EventHandlersExtractor
//   - Line 18: bb9 var8 = new bb9(var4)                   → MetaRefreshExtractor
//   - Line 20: r6 var9 = new r6(var4, var6)               → ScriptContentExtractor
//   - Line 22: this.a = new c0c(var2)                     → RobotsTxtParser
//   - Line 23: this.e = new on(var5, var7, var9, var8)    → (Composite extractor - not implemented)
//   - Line 26: this.b = new dkx(var2)                     → HTTPHeaderExtractor
//
// Returns configured ExtractionCoordinator ready for use.
func (f *ExtractorFactory) CreateCoordinator() *ExtractionCoordinator {
	// Step 1: Create shared InlineURLScanner
	// This component is injected into 5 extractors:
	// - JavaScriptStringExtractor, EventHandlersExtractor, MetaRefreshExtractor,
	//   ScriptContentExtractor, CommentsExtractor
	// Burp mapping: vs.java line 12
	inlineScanner := NewInlineURLScanner(f.urlResolver)

	// Step 2: Create shared HTMLAttributeExtractor
	// This is injected into JavaScriptStringExtractor
	// Note: HTMLAttributeExtractor does NOT check scope - caller handles scope filtering
	// Burp mapping: vs.java line 14
	htmlExtractor := NewHTMLAttributeExtractor(f.urlResolver)

	// Step 3: Create shared JavaScriptStringExtractor
	// This is injected into EventHandlersExtractor and ScriptContentExtractor
	// Burp mapping: vs.java line 15
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)

	// Step 4: Create extractors with dependencies
	// Burp mapping: vs.java lines 17-20, 22, 26

	// EventHandlersExtractor: Extracts from onclick, onload, etc.
	// Burp mapping: vs.java line 17: hjn var7 = new hjn(var4, var6)
	eventHandlers := NewEventHandlersExtractor(inlineScanner, jsExtractor)

	// MetaRefreshExtractor: Extracts from <meta http-equiv="refresh">
	// Burp mapping: vs.java line 18: bb9 var8 = new bb9(var4)
	metaRefresh := NewMetaRefreshExtractor(inlineScanner)

	// ScriptContentExtractor: Extracts from <script> tag content
	// Burp mapping: vs.java line 20: r6 var9 = new r6(var4, var6)
	scriptContent := NewScriptContentExtractor(inlineScanner, jsExtractor)

	// CommentsExtractor: Extracts from HTML comments
	// Burp mapping: vs.java line 24 (part of composite)
	comments := NewCommentsExtractor(inlineScanner)

	// RobotsTxtParser: Parses robots.txt files
	// Burp mapping: vs.java line 22: this.a = new c0c(var2)
	robotsParser := NewRobotsTxtParser(f.urlResolver)

	// HTTPHeaderExtractor: Extracts from HTTP headers
	// Burp mapping: vs.java line 26: this.b = new dkx(var2)
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
