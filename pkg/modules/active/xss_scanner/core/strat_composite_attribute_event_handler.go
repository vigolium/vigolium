package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// AttributeEventHandlerCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fi0
type AttributeEventHandlerCompositeStrategy struct {
	prefix                   string // Corresponds to 'd' (constructor var1)
	primaryRandomComponent   string // Corresponds to 'a' (constructor var2)
	attributeSpacing         string // Corresponds to 'e' (constructor var3)
	secondaryRandomComponent string // Corresponds to 'c' (constructor var4)
	isReflectionPresent      bool   // Corresponds to 'b' (constructor var5)
}

// NewAttributeEventHandlerCompositeStrategy creates a new instance of Fi0.
// Original Java constructor: fi0(String var1, String var2, String var3, String var4, boolean var5)
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

// --- Private helper methods for Fi0 ---

// isTargetingHiddenInput corresponds to Java: private boolean b(eqx var1, byte[] var2)
func (receiver *AttributeEventHandlerCompositeStrategy) isTargetingHiddenInput(
	reflection ReflectionOccurrenceDetail,
	responseBody []byte,
) bool {

	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection) // type cast
	if !isCorrectType {
		return false
	}

	tagDetails := attributeReflection.htmlTagDetails     // fcp.a -> Dr2
	if tagDetails != nil && tagDetails.Name == "input" { // dr2.a4()
		attributes := tagDetails.Attributes // dr2.a5()
		for _, currentAttribute := range attributes {
			if currentAttribute.Name == "type" && currentAttribute.Value == "hidden" {
				bodyStartIndex := 0 // body start index
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

// getReflectionTagNameSet corresponds to Java: private Set<String> a(eqx var1)
func (receiver *AttributeEventHandlerCompositeStrategy) getReflectionTagNameSet(
	reflection ReflectionOccurrenceDetail,
) map[string]struct{} {
	tagNameSet := make(map[string]struct{})
	attributeReflection, ok := reflection.(*HTMLAttributeReflection)
	if !ok {
		return tagNameSet // Return empty set if not Fcp
	}
	// String var4 = var3.d; // fcp.d (String)
	tagName := attributeReflection.tagName
	if tagName != "" { // Java String can be null, Go string is empty or not. Check for non-empty.
		tagNameSet[strings.ToLower(tagName)] = struct{}{}
	}
	return tagNameSet
}

// selectSubStrategyBasedOnHiddenInput corresponds to Java: private d3b a(eqx var1, byte[] var2)
func (receiver *AttributeEventHandlerCompositeStrategy) selectSubStrategyBasedOnHiddenInput(
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) ContextualAttackPayloadGenerator {
	// return (d3b)(this.b(var1, var2) ? new cb4(...) : new aic(...));
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

// --- D3b Interface Method A ---

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fi0.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *AttributeEventHandlerCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Set var7 = this.a(var5); // Calls private method a(eqx)
	reflectedTagNames := receiver.getReflectionTagNameSet(reflection)

	// g1r var8 = new g1r();
	eventHandlerValidator := NewEventHandlerEligibilityLogic() // Uses stubbed NewG1r

	// component d3b instances for gfw
	// NewB8, NewX2, NewF00 are constructors for ported/stubbed D3b types
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

	// return new gfw(...).a(var1, var2, var3, var4, var5, var6);
	iteratorStrategy := NewFirstSuccessMetaStrategy(
		onloadStrategy,
		inputOnfocusStrategy,
		onmouseoverStrategy,
		selectedSubStrategy,
	) // NewGfw is a stub from stubs.go

	return iteratorStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
