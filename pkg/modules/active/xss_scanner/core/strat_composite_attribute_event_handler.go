package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// AttributeEventHandlerCompositeStrategy implements the ContextualXSSTechnique interface.
type AttributeEventHandlerCompositeStrategy struct {
	prefix                   string
	primaryRandomComponent   string
	attributeSpacing         string
	secondaryRandomComponent string
	isReflectionPresent      bool
}

// NewAttributeEventHandlerCompositeStrategy creates a new instance.
func NewAttributeEventHandlerCompositeStrategy(
	prefix, primaryRnd, attrSpacing, secondaryRnd string,
	reflectionIsPresent bool,
) *AttributeEventHandlerCompositeStrategy {
	return &AttributeEventHandlerCompositeStrategy{
		prefix:                   prefix,
		primaryRandomComponent:   primaryRnd,
		attributeSpacing:         attrSpacing,
		secondaryRandomComponent: secondaryRnd,
		isReflectionPresent:      reflectionIsPresent,
	}
}

// --- Private helper methods ---

func (receiver *AttributeEventHandlerCompositeStrategy) isTargetingHiddenInput(
	reflection ReflectionOccurrenceDetail,
	responseBody []byte,
) bool {

	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)
	if !isCorrectType {
		return false
	}

	tagDetails := attributeReflection.htmlTagDetails
	if tagDetails != nil && tagDetails.Name == "input" {
		attributes := tagDetails.Attributes
		for _, currentAttribute := range attributes {
			if currentAttribute.Name == "type" && currentAttribute.Value == "hidden" {
				bodyStartIndex := 0
				attributeNameAbsoluteStart := bodyStartIndex + currentAttribute.NameStart
				if attributeNameAbsoluteStart > reflection.CoreInfo().endIndexInInput {
					return true
				}

			}
		}
		return false
	}
	return false
}

func (receiver *AttributeEventHandlerCompositeStrategy) getReflectionTagNameSet(
	reflection ReflectionOccurrenceDetail,
) map[string]struct{} {
	tagNameSet := make(map[string]struct{})
	attributeReflection, ok := reflection.(*HTMLAttributeReflection)
	if !ok {
		return tagNameSet
	}
	tagName := attributeReflection.tagName
	if tagName != "" {
		tagNameSet[strings.ToLower(tagName)] = struct{}{}
	}
	return tagNameSet
}

func (receiver *AttributeEventHandlerCompositeStrategy) selectSubStrategyBasedOnHiddenInput(
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) ContextualAttackPayloadGenerator {
	if receiver.isTargetingHiddenInput(reflection, transaction.GetResponseBody()) {
		inputAutofocusStrategy := NewInputTextAutofocusOnfocusStrategy(
			receiver.prefix,
			receiver.primaryRandomComponent,
			receiver.attributeSpacing,
			receiver.secondaryRandomComponent,
			receiver.isReflectionPresent,
		)
		return inputAutofocusStrategy
	}
	return NewAccessKeyOnclickStrategy(
		receiver.prefix,
		receiver.primaryRandomComponent,
		receiver.attributeSpacing,
		receiver.secondaryRandomComponent,
		receiver.isReflectionPresent,
	)
}

// --- ContextualAttackPayloadGenerator interface ---

func (receiver *AttributeEventHandlerCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	reflectedTagNames := receiver.getReflectionTagNameSet(reflection)

	eventHandlerValidator := NewEventHandlerEligibilityLogic()

	onloadStrategy := NewOnloadEventHandlerStrategy(
		eventHandlerValidator,
		reflectedTagNames,
		receiver.prefix,
		receiver.primaryRandomComponent,
		receiver.attributeSpacing,
		receiver.secondaryRandomComponent,
		receiver.isReflectionPresent,
	)
	inputOnfocusStrategy := NewInputOnfocusStrategy(
		reflectedTagNames,
		receiver.prefix,
		receiver.primaryRandomComponent,
		receiver.attributeSpacing,
		receiver.secondaryRandomComponent,
		receiver.isReflectionPresent,
	)
	onmouseoverStrategy := NewOnmouseoverEventHandlerStrategy(
		eventHandlerValidator,
		reflectedTagNames,
		receiver.prefix,
		receiver.primaryRandomComponent,
		receiver.attributeSpacing,
		receiver.secondaryRandomComponent,
		receiver.isReflectionPresent,
	)
	selectedSubStrategy := receiver.selectSubStrategyBasedOnHiddenInput(reflection, transaction)

	iteratorStrategy := NewFirstSuccessMetaStrategy(
		onloadStrategy,
		inputOnfocusStrategy,
		onmouseoverStrategy,
		selectedSubStrategy,
	)

	return iteratorStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
