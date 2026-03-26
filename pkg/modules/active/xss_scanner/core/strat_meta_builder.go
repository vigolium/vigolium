package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// MappedStrategyBuilder is the Go equivalent of the Java esm builder class.
// It does not implement ContextualXSSTechnique itself.
type MappedStrategyBuilder struct {
	// Corresponds to 'private final Map<Byte, ContextualXSSTechnique> a = new HashMap<>();'
	strategyMap map[byte]ContextualAttackPayloadGenerator
}

// NewMappedStrategyBuilder creates a new, initialized instance of Esm.
func NewMappedStrategyBuilder() *MappedStrategyBuilder {
	return &MappedStrategyBuilder{
		strategyMap: make(map[byte]ContextualAttackPayloadGenerator),
	}
}

// AddStrategy corresponds to 'public esm a(byte var1, ContextualXSSTechnique var2)'
// It adds a ContextualXSSTechnique strategy to the map and returns the Esm instance for chaining.
func (builder *MappedStrategyBuilder) AddStrategy(
	code byte,
	strategy ContextualAttackPayloadGenerator,
) *MappedStrategyBuilder {
	builder.strategyMap[code] = strategy
	return builder
}

// Build corresponds to 'public hyt a()' which returns a new hyt instance.
// The stub for Esm interface has this as Build() Hyt.
// If Hyt interface is removed from stubs, this should return *Hyt_Impl
func (builder *MappedStrategyBuilder) Build() *MappedStrategyExecutor {
	// Create an unmodifiable-like map for Hyt if Go had a direct equivalent.
	// For now, pass a copy or the direct map.
	// Java uses Collections.unmodifiableMap(this.a).
	// We need to pass the collected ContextualXSSTechnique strategies to Hyt.
	// The Hyt constructor in Java is hyt(esm, Map<Byte, ContextualXSSTechnique>)
	// Our NewHyt_Concrete will take this map.

	// To maintain order from Java HashMap (though not guaranteed), sort keys first if necessary.
	// However, typical usage might be direct lookup by byte key in Hyt.a.
	// Let's create a copy of the map to pass to Hyt to mimic unmodifiability to some extent.
	strategyMapCopy := make(map[byte]ContextualAttackPayloadGenerator)
	for k, v := range builder.strategyMap {
		strategyMapCopy[k] = v
	}
	return NewMappedStrategyExecutor(strategyMapCopy)
}

// --- Hyt related structures (normally in hyt.go, but defined here as esm depends on them) ---
// This is a simplified Hyt for now. The full Hyt porting would be separate.

// Hyt is the Go equivalent of the Java hyt class.
type MappedStrategyExecutor struct { // Renamed to Hyt_Impl to avoid conflict if Hyt interface exists in stubs
	strategyMap map[byte]ContextualAttackPayloadGenerator
}

// NewHyt_Concrete creates an Hyt instance.
// func NewHyt_Concrete(strats map[byte]ContextualXSSTechnique) *Hyt_Impl { // Keep this as _Concrete if Hyt interface is still in stubs
// For now, assume Hyt interface is gone from stubs and Hyt_Impl is the main one.
func NewMappedStrategyExecutor(
	strategies map[byte]ContextualAttackPayloadGenerator,
) *MappedStrategyExecutor {
	return &MappedStrategyExecutor{strategyMap: strategies}
}

// ExecuteStrategyByCode is the primary method of Hyt, corresponding to Java's hyt.a(...).
// public PreliminaryXSSFinding a(byte var1, hgm var2, hnx var3, byte var4, byte var5, DetectedReflection var6, byte[] var7)
func (executor *MappedStrategyExecutor) ExecuteStrategyByCode(
	strategyCode byte,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// if (!this.a.containsKey(var1)) {
	//    return null;
	// }
	selectedStrategy, isStrategyFound := executor.strategyMap[strategyCode]
	if !isStrategyFound ||
		selectedStrategy == nil { // Combined Java's containsKey and implicit null check from get
		// No matching strategy found
		return nil
	}

	// TODO: check original
	// else {
	//    PreliminaryXSSFinding var10000 = this.a.get(var1).a(var2, var3, var4, var5, var6, var7);
	//    if (!agd.e()) {
	//       dir.b(!var8);
	//    }
	//    return var10000;
	// }

	// Parameters for ContextualXSSTechnique.A: hgm, hnx, byte, byte, DetectedReflection, byte[]
	// Java: this.a.get(var1).a(var2,     var3,   var4,     var5,     var6,      var7)
	// Go:   strategy.A(        hgmVal,   hnxVal, byteVal4, byteVal5, eqxVal,    bytesVal7)
	findingResult := selectedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)

	return findingResult
}

// Ensure Hyt_Impl satisfies Hyt interface if defined in stubs
func (h *MappedStrategyExecutor) IsMappedStrategyExecutor() {} // Assuming Hyt interface in stubs.go has IsHyt()
