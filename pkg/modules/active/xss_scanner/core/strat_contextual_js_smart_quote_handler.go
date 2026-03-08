package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSmartQuoteHandlerStrategy implements the ContextualXSSTechnique interface.
// Original Java class: at6
type JavaScriptSmartQuoteHandlerStrategy struct {
	contentTypeProfile *ContentTypeProfile // Corresponds to 'private final def a;'
}

// NewJavaScriptSmartQuoteHandlerStrategy creates a new concrete instance of At6, to be wrapped or used by a NewJavaScriptSmartQuoteHandlerStrategy that returns ContextualXSSTechnique.
// Original Java constructor: at6(def var1)
// The public NewJavaScriptSmartQuoteHandlerStrategy in stubs.go returns ContextualXSSTechnique for interface satisfaction.
// This internal one helps in creating the actual struct if needed elsewhere or during full porting.
func NewJavaScriptSmartQuoteHandlerStrategy(
	contentType *ContentTypeProfile,
) *JavaScriptSmartQuoteHandlerStrategy {
	return &JavaScriptSmartQuoteHandlerStrategy{
		contentTypeProfile: contentType,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class At6.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptSmartQuoteHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// byte var7 = eba.b(var6, var5.a().f, var5.a().c);
	coreReflectionInfo := reflection.CoreInfo() // Corresponds to var5.a()
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	// return new esm()
	//    .a((byte)0, new ch8("\"", this.a, true))
	//    .a((byte)1, new ch8("'", this.a, true))
	//    .a((byte)2, new hfu())
	//    .a() // Returns Hyt
	//    .a(var7, var1.a(1024), var2, var3, var4, var5, var6);

	mappedStrategyBuilder := NewMappedStrategyBuilder()
	jsStringDoubleQuoteStrategy := NewJavaScriptStringBreakoutStrategy(
		"\"",
		receiver.contentTypeProfile,
		true,
	)
	jsStringSingleQuoteStrategy := NewJavaScriptStringBreakoutStrategy(
		"'",
		receiver.contentTypeProfile,
		true,
	)
	jsStatementStrategy := NewJavaScriptStatementCompositeStrategy()

	// Chained calls for Esm builder
	// .a((byte)0, ch8DoubleQuote)
	// .a((byte)1, ch8SingleQuote)
	// .a((byte)2, hfuInstance)
	// .a() -> Build()
	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), jsStringDoubleQuoteStrategy).
		AddStrategy(byte(1), jsStringSingleQuoteStrategy).
		AddStrategy(byte(2), jsStatementStrategy).
		Build() // This .Build() corresponds to the .a() that returns Hyt

	// var1.a(1024) -> probeBuilder.AVal(1024)
	// The final .a(...) is called on the Hyt object
	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder.WithAdditionalScanFlags(1024),
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
