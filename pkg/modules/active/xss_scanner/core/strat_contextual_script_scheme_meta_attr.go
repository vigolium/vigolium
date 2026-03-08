package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// ScriptSchemeInAttributeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fcq
type ScriptSchemeInAttributeStrategy struct {
	contentTypeProfile *ContentTypeProfile // Corresponds to 'private final def a;'
}

// isJavaScriptScheme is the Go equivalent of the static Java lambda lambda$exec$0
// private static boolean lambda$exec$0(eqx var0)
func isJavaScriptScheme(reflection ReflectionOccurrenceDetail) bool {
	// fcp var1 = (fcp)var0;
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection) // Type assertion to Fcp
	if !isCorrectType ||
		attributeReflection == nil { // Ensure fcpVal is not nil after assertion for safety, though Java might throw ClassCastException earlier
		return false // Or handle error appropriately
	}
	// return var1.e.startsWith("javascript:");
	return strings.HasPrefix(attributeReflection.attributeValue, "javascript:")
}

// javaScriptSchemeMatcher implements the ReflectionMatcher interface for lambdaExec0Fcq.
type javaScriptSchemeMatcher struct{}

func (w *javaScriptSchemeMatcher) Matches(
	reflection ReflectionOccurrenceDetail,
) bool { // Implements ReflectionMatcher.A
	return isJavaScriptScheme(reflection)
}

func (w *javaScriptSchemeMatcher) IsReflectionMatchCriterion() {} // To satisfy ReflectionMatcher interface if it has marker methods

// NewScriptSchemeInAttributeStrategy creates a new instance of Fcq.
// Original Java constructor: fcq(def var1)
func NewScriptSchemeInAttributeStrategy(
	contentType *ContentTypeProfile,
) *ScriptSchemeInAttributeStrategy {
	return &ScriptSchemeInAttributeStrategy{
		contentTypeProfile: contentType,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fcq.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *ScriptSchemeInAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// fcp var7 = (fcp)var5;
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)

	// if (var7 == null) { net.portswigger.qe.a(false, net.portswigger.rg.e); return null; }
	if !isCorrectType ||
		attributeReflection == nil { // Combined Java null check and Go type assertion check
		// net.portswigger.qe.a call is for logging/assertion, we just return nil as per Java logic
		return nil
	}

	// else if (!var7.e.startsWith("javascript:")) { return null; }
	if !strings.HasPrefix(attributeReflection.attributeValue, "javascript:") {
		return nil
	}

	// else { ... }
	// byte var8 = eba.b(var6, var7.a().f, var7.a().c);
	coreReflectionInfo := attributeReflection.CoreInfo() // fcpVal is Fcp, which embeds DetectedReflection, so it has A() returning Hpo
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	// return new esm()
	//    .a((byte)0, new ch8("\"", this.a, true))
	//    .a((byte)1, new ch8("'", this.a, true))
	//    .a((byte)2, new hfu())
	//    .a() // returns Hyt
	//    .a(var8, var1, var2.a(fcq::lambda$exec$0), var3, var4, var5, var6);

	mappedStrategyBuilder := NewMappedStrategyBuilder()
	jsStringDoubleQuoteStrategy := NewJavaScriptStringBreakoutStrategy("\"", strategy.contentTypeProfile, true)
	jsStringSingleQuoteStrategy := NewJavaScriptStringBreakoutStrategy("'", strategy.contentTypeProfile, true)
	jsStatementStrategy := NewJavaScriptStatementCompositeStrategy()

	// var2.a(fcq::lambda$exec$0)
	// Create an ReflectionMatcher filter instance from the lambda wrapper
	schemeFilter := &javaScriptSchemeMatcher{}
	profileWithFilter := profile.WithAdditionalMatchCriterion(schemeFilter)

	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), jsStringDoubleQuoteStrategy).
		AddStrategy(byte(1), jsStringSingleQuoteStrategy).
		AddStrategy(byte(2), jsStatementStrategy).
		Build()

	// Call Hyt.A method
	// Note: Java passes var1 (hgm) directly, not var1.a(1024) as in at6.
	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder,
		profileWithFilter,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
