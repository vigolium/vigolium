package core

import "github.com/vigolium/vigolium/pkg/httpmsg"

// EncodingMode1AttackStepExecutor implements the XSSAttackStepExecutor interface.
type EncodingMode1AttackStepExecutor struct {
	delegateExecutor AttackStepRunner
}

// NewEncodingMode1AttackStepExecutor creates a new instance.
func NewEncodingMode1AttackStepExecutor(
	delegateExecutor AttackStepRunner,
) *EncodingMode1AttackStepExecutor {
	return &EncodingMode1AttackStepExecutor{delegateExecutor: delegateExecutor}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (executor *EncodingMode1AttackStepExecutor) IsAttackStepRunner() {}

func (executor *EncodingMode1AttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint,
	scanFlags int,
	payload string,
	tactic ReflectionTacticType,
	contextCode byte,
	techniqueClassifier AttackTechniqueClassifier,
	useSecondaryCanary bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	encodedPayload := EncodeStringWithMode(payload, 1)
	if executor.delegateExecutor != nil {
		return executor.delegateExecutor.RunAttackStep(
			injectionPoint,
			scanFlags|1,
			encodedPayload,
			tactic,
			contextCode,
			techniqueClassifier,
			useSecondaryCanary,
			profile,
		)
	}

	return nil
}
