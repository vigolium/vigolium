package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SingleCharacterInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: d1v
type SingleCharacterInjectionStrategy struct {
	characterToInject             byte                                    // Corresponds to 'private final byte a;'
	attributeEventHandlerStrategy *AttributeEventHandlerCompositeStrategy // Corresponds to 'private fi0 b;' - In Java, fi0 is a class that implements ContextualXSSTechnique.
	// In Go, Fi0 is an interface (stubbed for now).
}

// NewSingleCharacterInjectionStrategy creates a new instance of D1v.
// Original Java constructor: public d1v(byte var1)
func NewSingleCharacterInjectionStrategy(charToInject byte) *SingleCharacterInjectionStrategy {
	// String var2 = "";
	prefixForEventHandler := ""
	// this.a = var1;
	// Convert the byte to a string
	// In Go, byte is uint8. Java byte is signed.
	// However, h9.a seems to work with the direct byte value for character conversion.
	charAsString := utils.BytesToString([]byte{charToInject})

	// if (this.a == 32) { // 32 is space character
	//    var3 = "";
	//    var2 = " ";
	// }
	if charToInject == 32 {
		charAsString = ""
		prefixForEventHandler = " "
	}

	// this.b = new fi0(var3, var3, var2, var3, false); // new fi0(...)
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

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class D1v.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SingleCharacterInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// return this.a == -1 ? null : this.b.a(var1, var2, var3, var4, var5, var6);
	// Java byte is signed, so -1 is 0xFF for an unsigned byte in Go.
	if receiver.characterToInject == 0xFF { // Check for -1 as a Java byte
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
