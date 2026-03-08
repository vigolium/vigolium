package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// TagAttributeUnquotedCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: h9c
type TagAttributeUnquotedCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewTagAttributeUnquotedCompositeStrategy creates a new instance of H9c.
// The field 'a' in Java is initialized directly.
func NewTagAttributeUnquotedCompositeStrategy() *TagAttributeUnquotedCompositeStrategy {
	// Original Java logic for field 'a':
	// new gfw(new epq(">", false),
	//         new aa7(),
	//         new h4z(new gfw(new gu9((byte)34),
	//                           new gu9((byte)39),
	//                           new gu9((byte)96)
	//                          )
	//                  )
	//        );

	greaterThanBreakoutStrategy := NewGenericBreakoutCompositeStrategy(">", false)
	simpleAttributeStrategy := NewSimpleAttributeInjectionStrategy()

	doubleQuotedAttrStrategy := NewQuotedAttributeContextStrategy(
		byte(34),
	)
	singleQuotedAttrStrategy := NewQuotedAttributeContextStrategy(
		byte(39),
	)
	backtickQuotedAttrStrategy := NewQuotedAttributeContextStrategy(byte(96))

	quotedAttrIteratorStrategy := NewFirstSuccessMetaStrategy(
		doubleQuotedAttrStrategy,
		singleQuotedAttrStrategy,
		backtickQuotedAttrStrategy,
	)
	conditionalMetaStrategy := NewConditionalExecutionMetaStrategy(
		quotedAttrIteratorStrategy,
	)

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		greaterThanBreakoutStrategy,
		simpleAttributeStrategy,
		conditionalMetaStrategy,
	)

	return &TagAttributeUnquotedCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class H9c.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *TagAttributeUnquotedCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
