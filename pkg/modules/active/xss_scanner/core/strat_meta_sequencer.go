package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SequentialMetaStrategy implements the ContextualXSSTechnique interface.
type SequentialMetaStrategy struct {
	childStrategies []ContextualAttackPayloadGenerator
}

// NewSequentialMetaStrategy creates a new SequentialMetaStrategy instance.
func NewSequentialMetaStrategy(
	childStrategies ...ContextualAttackPayloadGenerator,
) *SequentialMetaStrategy {
	return &SequentialMetaStrategy{
		childStrategies: childStrategies,
	}
}

//
// MODIFIED: Now builds a ChainedXSSFinding to track all successful steps,
// even when later steps fail. This prevents losing valuable intermediate findings.
func (strategy *SequentialMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	var accumulatedFinding PotentialXSSFinding = nil
	var chainedSteps []*FindingStep
	var maxSeverity = FindingSeverityUnknown
	var stoppedAt = 0

	strategiesToExecute := strategy.childStrategies
	strategyCount := len(strategiesToExecute)
	currentIndex := 0

	for currentIndex < strategyCount {
		currentChildStrategy := strategiesToExecute[currentIndex]

		probeBuilderAdjustmentFlags := 0
		if accumulatedFinding != nil {
			probeBuilderAdjustmentFlags = accumulatedFinding.ScanFlags()
		}

		adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(probeBuilderAdjustmentFlags)
		currentStepFinding := currentChildStrategy.GeneratePayload(
			adjustedProbeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)

		if currentStepFinding == nil {
			// CHAIN REPORTING: Record this failure step
			chainedSteps = append(chainedSteps, &FindingStep{
				Index:         currentIndex,
				Success:       false,
				StrategyName:  GetStrategyName(currentChildStrategy),
				FailureReason: "Strategy returned nil (no reflection or validation failed)",
			})
			stoppedAt = currentIndex
			break
		}

		// CENTRALIZED: Automatically infer severity and technique from strategy type
		severity := FindingSeverityUnknown
		techniqueName := "Unknown Technique"
		evidence := ""

		if xssFinding, ok := currentStepFinding.(*XSSScanFinding); ok {
			// Directly infer and set severity from strategy - no backward compatibility
			severity = InferSeverityFromStrategy(currentChildStrategy)
			techniqueName = InferTechniqueNameFromStrategy(currentChildStrategy)

			xssFinding.SetSeverity(severity)
			xssFinding.SetTechniqueName(techniqueName)
			xssFinding.SetChainPosition(currentIndex)

			evidence = xssFinding.InjectionEvidence()

			// Update max severity
			if severity > maxSeverity {
				maxSeverity = severity
			}
		} else if chainedFinding, ok := currentStepFinding.(*ChainedXSSFinding); ok {
			// If child already returned a chain, use its max severity
			severity = chainedFinding.MaxSeverityReached
			techniqueName = "Composite Strategy Chain"
			if severity > maxSeverity {
				maxSeverity = severity
			}
		}

		// CHAIN REPORTING: Record this successful step
		chainedSteps = append(chainedSteps, &FindingStep{
			Index:         currentIndex,
			Success:       true,
			Severity:      severity,
			TechniqueName: techniqueName,
			Evidence:      evidence,
		})

		// Store XSS finding in step for later access
		if xssFinding, ok := currentStepFinding.(*XSSScanFinding); ok {
			chainedSteps[len(chainedSteps)-1].Finding = xssFinding
		}

		accumulatedFinding = currentStepFinding
		currentIndex++
	}

	// CHAIN REPORTING: If we have multiple steps OR any successful steps with failures,
	// wrap them in a ChainedXSSFinding
	if len(chainedSteps) > 1 || (len(chainedSteps) > 0 && stoppedAt > 0) {
		successCount := 0
		for _, step := range chainedSteps {
			if step.Success {
				successCount++
			}
		}

		// Only build chain if we have at least one successful step
		if successCount > 0 {
			chainedFinding := BuildChainedFinding(chainedSteps, contextType, tactic)
			if chainedFinding != nil {
				return chainedFinding
			}
		}
	}

	// Single step or no chain needed - return the accumulated finding
	return accumulatedFinding
}
