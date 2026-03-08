package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// DataURISchemeCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: eb (renamed to DataURISchemeCompositeStrategy for Go convention)
type DataURISchemeCompositeStrategy struct {
	randomProvider      *utils.RandomGenerator           // Corresponds to 'private final net.portswigger.ou c;'
	dataSchemeDirective SchemeDefinition                 // Corresponds to 'private final dir a;'
	combinedStrategy    ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique b;'
}

// createDataURISubStrategy is the Go equivalent of the private Java method a(String var1, String var2)
func (receiver *DataURISchemeCompositeStrategy) createDataURISubStrategy(
	prefix string,
	suffix string,
) ContextualAttackPayloadGenerator {
	// return new c0b(new fxo(var1, this.a, var2), new e2b(this.c, var1, var2));
	prefixSuffixRandomStrategy := NewSchemePrefixSuffixRandomPayloadStrategy(
		prefix,
		receiver.dataSchemeDirective,
		suffix,
	) // NewFxo is a stub
	base64ScriptStrategy := NewDataURIBase64ScriptStrategy(
		receiver.randomProvider,
		prefix,
		suffix,
	) // NewE2b is the ported constructor
	return NewSequentialMetaStrategy(
		prefixSuffixRandomStrategy,
		base64ScriptStrategy,
	) // NewC0b is the ported constructor
}

// NewDataURISchemeCompositeStrategy creates a new instance of Eb.
// Original Java constructor: public eb(net.portswigger.ou var1, dir var2)
func NewDataURISchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	dataScheme SchemeDefinition,
) *DataURISchemeCompositeStrategy {
	receiver := &DataURISchemeCompositeStrategy{
		randomProvider:      randomProvider,
		dataSchemeDirective: dataScheme,
		// ValD3bB is initialized below
	}

	// int var10000 = epq.b();

	// String[] var4 = new String[]{"", "\t", "\n", "\r", ":", "\u0000"};
	suffixVariations := []string{
		"",
		"\t",
		"\n",
		"\r",
		":",
		"\x00",
	} // Java \u0000 is \x00 in Go string literal

	// int var3 = var10000; // Loop control variable

	// String[] var5 = new String[]{ ..., "\u001f" };
	prefixVariations := []string{
		"", " ", "\t", "\n", "\r", "\f", "\b",
		"\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
		"\x0b", "\x0e", "\x0f", "\x10", "\x11", "\x12", "\x13",
		"\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1a",
		"\x1b", "\x1c", "\x1d", "\x1e", "\x1f",
	}

	// ContextualXSSTechnique[] var6 = new ContextualXSSTechnique[var4.length + var5.length];
	subStrategies := make(
		[]ContextualAttackPayloadGenerator,
		0,
		len(prefixVariations)+len(suffixVariations),
	)

	// First loop for arrVar4
	for _, currentSuffix := range suffixVariations {
		subStrategies = append(subStrategies, receiver.createDataURISubStrategy("", currentSuffix))

	}

	// Second loop for arrVar5
	for _, currentPrefix := range prefixVariations {
		subStrategies = append(subStrategies, receiver.createDataURISubStrategy(currentPrefix, ""))

	}

	// this.b = new gfw(var6);
	receiver.combinedStrategy = NewFirstSuccessMetaStrategy(subStrategies...)

	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Eb.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *DataURISchemeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.b.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
