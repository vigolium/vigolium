package core

import "github.com/vigolium/vigolium/pkg/httpmsg"

// IteratingAttackStepExecutor implements the XSSAttackStepExecutor interface.
type IteratingAttackStepExecutor struct {
	childExecutors []AttackStepRunner
}

// NewIteratingAttackStepExecutor creates a new instance.
func NewIteratingAttackStepExecutor(
	childExecutors ...AttackStepRunner,
) *IteratingAttackStepExecutor {
	return &IteratingAttackStepExecutor{childExecutors: childExecutors}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (executor *IteratingAttackStepExecutor) IsAttackStepRunner() {}

func (executor *IteratingAttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint,
	scanFlags int,
	payload string,
	tactic ReflectionTacticType,
	contextCode byte,
	techniqueClassifier AttackTechniqueClassifier,
	useSecondaryCanary bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	for _, childRunner := range executor.childExecutors {
		if childRunner != nil { // Check if the XSSAttackStepExecutor instance itself is nil
			finding := childRunner.RunAttackStep(
				injectionPoint,
				scanFlags,
				payload,
				tactic,
				contextCode,
				techniqueClassifier,
				useSecondaryCanary,
				profile,
			)
			if finding != nil {
				return finding
			}
		}
	}
	return nil
}
