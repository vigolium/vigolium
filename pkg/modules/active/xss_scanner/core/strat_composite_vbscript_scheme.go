package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// VBScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
type VBScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewVBScriptSchemeCompositeStrategy creates a new instance.
func NewVBScriptSchemeCompositeStrategy(dirVar1 SchemeDefinition) *VBScriptSchemeCompositeStrategy {

	schemeRandomAdvancedStrategy := NewSchemeWithRandomStringAdvancedStrategy(dirVar1)
	schemeMsgboxStrategy := NewSchemeMsgboxPayloadStrategy(dirVar1)
	finalCombinedStrategy := NewSequentialMetaStrategy(schemeRandomAdvancedStrategy, schemeMsgboxStrategy)
	return &VBScriptSchemeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *VBScriptSchemeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
