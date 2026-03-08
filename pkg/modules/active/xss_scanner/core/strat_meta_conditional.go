package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ConditionalExecutionMetaStrategy implements the ContextualXSSTechnique interface.
// Original Java class: h4z
type ConditionalExecutionMetaStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewConditionalExecutionMetaStrategy creates a new instance of H4z.
// Original Java constructor: public h4z(ContextualXSSTechnique var1)
func NewConditionalExecutionMetaStrategy(
	delegateStrategy ContextualAttackPayloadGenerator,
) *ConditionalExecutionMetaStrategy {
	return &ConditionalExecutionMetaStrategy{
		delegateStrategy: delegateStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class H4z.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *ConditionalExecutionMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var4 == 7 && var3 != 1 ? this.a.a(var1, var2, var3, var4, var5, var6) : null;
	if contextType == ReflectionContextHTMLAttributeValueUnquotedBreakout && tactic != 1 {
		return receiver.delegateStrategy.GeneratePayload(
			probeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)
	}
	return nil
}
