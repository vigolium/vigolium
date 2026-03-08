package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// HTMLCommentBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: g7f
type HTMLCommentBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private ContextualXSSTechnique a;', initialized at declaration.
}

// NewHTMLCommentBreakoutCompositeStrategy creates a new instance of G7f.
// The field 'a' in Java is initialized directly: new c0b(new bh9(), new epq("-->", false))
func NewHTMLCommentBreakoutCompositeStrategy() *HTMLCommentBreakoutCompositeStrategy {
	// new bh9()
	commentCloserStrategy := NewHTMLCommentCloserStrategy() // Ported

	// new epq("-->", false)
	genericBreakoutStrategy := NewGenericBreakoutCompositeStrategy("-->", false) // Ported

	// new c0b(bh9Instance, epqInstance)
	finalCombinedStrategy := NewSequentialMetaStrategy(commentCloserStrategy, genericBreakoutStrategy) // Ported

	return &HTMLCommentBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class G7f.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *HTMLCommentBreakoutCompositeStrategy) GeneratePayload(
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
