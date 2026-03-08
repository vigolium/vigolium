package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// PrioritizedIteratingMetaStrategy implements the ContextualXSSTechnique interface.
// Original Java class: og
type PrioritizedIteratingMetaStrategy struct {
	childStrategies []ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique[] a;'
}

// NewPrioritizedIteratingMetaStrategy creates a new instance of Og.
// Original Java constructor: public og(ContextualXSSTechnique... var1)
func NewPrioritizedIteratingMetaStrategy(
	childStrategies ...ContextualAttackPayloadGenerator,
) *PrioritizedIteratingMetaStrategy {
	return &PrioritizedIteratingMetaStrategy{
		childStrategies: childStrategies,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Og.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *PrioritizedIteratingMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	var firstSuccessfulFinding PotentialXSSFinding = nil // Java: PreliminaryXSSFinding var8 = null;

	strategiesToTry := strategy.childStrategies
	strategyCount := len(strategiesToTry)

	for currentIndex := 0; currentIndex < strategyCount; currentIndex++ {
		currentChildStrategy := strategiesToTry[currentIndex]
		if currentChildStrategy == nil {

			continue
		}

		currentFinding := currentChildStrategy.GeneratePayload(
			probeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)

		if currentFinding != nil {
			// CENTRALIZED: Automatically infer and set severity/technique
			if xssFinding, ok := currentFinding.(*XSSScanFinding); ok {
				// Directly infer and set - no backward compatibility checks
				xssFinding.SetSeverity(InferSeverityFromStrategy(currentChildStrategy))
				xssFinding.SetTechniqueName(InferTechniqueNameFromStrategy(currentChildStrategy))
			}

			// if ((var13.f() & 4) > 0)
			if (currentFinding.ScanFlags() & 4) > 0 { // Check bit 2 (0x04) of PreliminaryXSSFinding.F() result
				return currentFinding
			}
			if firstSuccessfulFinding == nil {
				firstSuccessfulFinding = currentFinding
			}
		}

	}
	return firstSuccessfulFinding
}
