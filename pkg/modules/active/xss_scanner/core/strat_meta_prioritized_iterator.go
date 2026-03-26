package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// PrioritizedIteratingMetaStrategy implements the ContextualXSSTechnique interface.
type PrioritizedIteratingMetaStrategy struct {
	childStrategies []ContextualAttackPayloadGenerator
}

// NewPrioritizedIteratingMetaStrategy creates a new instance.
func NewPrioritizedIteratingMetaStrategy(
	childStrategies ...ContextualAttackPayloadGenerator,
) *PrioritizedIteratingMetaStrategy {
	return &PrioritizedIteratingMetaStrategy{
		childStrategies: childStrategies,
	}
}

func (strategy *PrioritizedIteratingMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	var firstSuccessfulFinding PotentialXSSFinding = nil

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

			if (currentFinding.ScanFlags() & 4) > 0 { // High-priority flag (bit 2)
				return currentFinding
			}
			if firstSuccessfulFinding == nil {
				firstSuccessfulFinding = currentFinding
			}
		}

	}
	return firstSuccessfulFinding
}
