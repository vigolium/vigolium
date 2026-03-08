package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: aa7
type SimpleAttributeInjectionStrategy struct {
	// Corresponds to 'private final ContextualXSSTechnique a' in Java
	// This field is initialized in the constructor using a private method and other ContextualXSSTechnique implementations.
	combinedStrategy ContextualAttackPayloadGenerator
}

// createSimpleAttributePayload is the Go equivalent of the static Java lambda lambda$createInjection$0
// private static PreliminaryXSSFinding lambda$createInjection$0(hgm var0, hnx var1, byte var2, byte var3, DetectedReflection var4, byte[] var5)
func createSimpleAttributePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var0.c().a((byte)2, "#{random_string_5} a=b#{random_string_5b}", var1);
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(2), "#{random_string_5} a=b#{random_string_5b}", profile)
}

// simpleAttributeLambdaWrapper is a helper struct to implement ContextualXSSTechnique for the lambda.
// This is one way to handle Java lambda that implements an interface.
// The lambda aa7::lambda$createInjection$0 is static, so the wrapper doesn't need fields.
type simpleAttributeLambdaWrapper struct{}

// GeneratePayload is the implementation of ContextualXSSTechnique for aa7LambdaWrapper.
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

// getPayloadStrategy is the Go equivalent of the private Java method a()
// private ContextualXSSTechnique a()
func (receiver *SimpleAttributeInjectionStrategy) getPayloadStrategy() ContextualAttackPayloadGenerator {
	// Original Java logic: return aa7::lambda$createInjection$0;
	// In Go, we return an instance of the wrapper struct that calls the lambda function.
	return &simpleAttributeLambdaWrapper{}
}

// NewSimpleAttributeInjectionStrategy creates a new instance of Aa7.
// Original Java constructor: (implicit) initializes field 'a'
//
//	public class aa7 implements ContextualXSSTechnique {
//	   private final ContextualXSSTechnique a = new c0b(this.a(), new d1v((byte)32));
//
// ...
// }
func NewSimpleAttributeInjectionStrategy() *SimpleAttributeInjectionStrategy {
	receiver := &SimpleAttributeInjectionStrategy{}
	// Initialize ValA as done in Java
	// this.a() in Java becomes receiver.aInternal() in Go.
	// new d1v((byte)32) becomes NewD1v(byte(32))
	// new c0b(...) becomes NewC0b(...)
	receiver.combinedStrategy = NewSequentialMetaStrategy(
		receiver.getPayloadStrategy(),
		NewSingleCharacterInjectionStrategy(byte(32)),
	)
	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Aa7.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SimpleAttributeInjectionStrategy) GeneratePayload(
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
