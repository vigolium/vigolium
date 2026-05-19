package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SingleCharacterInjectionStrategy implements the ContextualXSSTechnique interface.
type SingleCharacterInjectionStrategy struct {
	characterToInject             byte
	attributeEventHandlerStrategy *AttributeEventHandlerCompositeStrategy
}

// NewSingleCharacterInjectionStrategy creates a new instance.
func NewSingleCharacterInjectionStrategy(charToInject byte) *SingleCharacterInjectionStrategy {
	prefixForEventHandler := ""
	charAsString := utils.BytesToString([]byte{charToInject})

	if charToInject == charSpace { // space character
		charAsString = ""
		prefixForEventHandler = " "
	}

	eventHandlerStrategy := NewAttributeEventHandlerCompositeStrategy(
		charAsString,
		charAsString,
		prefixForEventHandler,
		charAsString,
		false,
	)

	return &SingleCharacterInjectionStrategy{
		characterToInject:             charToInject,
		attributeEventHandlerStrategy: eventHandlerStrategy,
	}
}

func (receiver *SingleCharacterInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	if receiver.characterToInject == 0xFF {
		return nil
	}
	return receiver.attributeEventHandlerStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
