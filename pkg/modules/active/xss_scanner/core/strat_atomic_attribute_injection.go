package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
type SimpleAttributeInjectionStrategy struct {
	// This field is initialized in the constructor using a private method and other ContextualXSSTechnique implementations.
	combinedStrategy ContextualAttackPayloadGenerator
}

func createSimpleAttributePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(2), "#{random_string_5} a=b#{random_string_5b}", profile)
}

// simpleAttributeLambdaWrapper is a helper struct to implement ContextualXSSTechnique for the lambda.
type simpleAttributeLambdaWrapper struct{}

// GeneratePayload is the implementation of ContextualXSSTechnique for AttributeInjectionLambdaWrapper.
func (l *simpleAttributeLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createSimpleAttributePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

func (receiver *SimpleAttributeInjectionStrategy) getPayloadStrategy() ContextualAttackPayloadGenerator {
	return &simpleAttributeLambdaWrapper{}
}

// NewSimpleAttributeInjectionStrategy creates a new instance.
func NewSimpleAttributeInjectionStrategy() *SimpleAttributeInjectionStrategy {
	receiver := &SimpleAttributeInjectionStrategy{}
	receiver.combinedStrategy = NewSequentialMetaStrategy(
		receiver.getPayloadStrategy(),
		NewSingleCharacterInjectionStrategy(charSpace),
	)
	return receiver
}

func (receiver *SimpleAttributeInjectionStrategy) GeneratePayload(
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
