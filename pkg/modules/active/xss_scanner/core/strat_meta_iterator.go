package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// FirstSuccessMetaStrategy implements the ContextualXSSTechnique interface.
// Original Java class: gfw
type FirstSuccessMetaStrategy struct {
	childStrategies []ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique[] c;'
}

// NewFirstSuccessMetaStrategy creates a new instance of Gfw.
// Original Java constructor: public gfw(ContextualXSSTechnique... var1)
func NewFirstSuccessMetaStrategy(
	childStrategies ...ContextualAttackPayloadGenerator,
) *FirstSuccessMetaStrategy {
	return &FirstSuccessMetaStrategy{
		childStrategies: childStrategies,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Gfw.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
//
// MODIFIED: Now tracks which alternatives were tried for better debugging and chain reporting.
// Returns first successful finding, but can optionally wrap in chain to show attempted strategies.
func (strategy *FirstSuccessMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	strategiesToTry := strategy.childStrategies
	strategyCount := len(strategiesToTry)

	// Track attempted strategies for debugging/chain reporting
	var attemptedSteps []*FindingStep
	trackAttempts := false // Set to true to enable attempt tracking

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

			// SUCCESS: Extract metadata if tracking attempts
			if trackAttempts {
				severity := FindingSeverityUnknown
				techniqueName := "Unknown"
				evidence := ""

				if xssFinding, ok := currentFinding.(*XSSScanFinding); ok {
					severity = xssFinding.Severity()
					techniqueName = xssFinding.TechniqueName()
					evidence = xssFinding.InjectionEvidence()
				} else if chainedFinding, ok := currentFinding.(*ChainedXSSFinding); ok {
					severity = chainedFinding.MaxSeverityReached
					techniqueName = "Composite Strategy Chain"
				}

				attemptedSteps = append(attemptedSteps, &FindingStep{
					Index:         currentIndex,
					Success:       true,
					Severity:      severity,
					TechniqueName: techniqueName,
					Evidence:      evidence,
				})

				if xssFinding, ok := currentFinding.(*XSSScanFinding); ok {
					attemptedSteps[len(attemptedSteps)-1].Finding = xssFinding
				}
			}

			// Return first success immediately (original behavior)
			return currentFinding
		} else if trackAttempts {
			// FAILURE: Record attempt
			attemptedSteps = append(attemptedSteps, &FindingStep{
				Index:         currentIndex,
				Success:       false,
				StrategyName:  GetStrategyName(currentChildStrategy),
				FailureReason: "Strategy returned nil",
			})
		}
	}

	// All strategies failed - optionally return chain showing what was tried
	// For now, just return nil (original behavior)
	return nil
}
