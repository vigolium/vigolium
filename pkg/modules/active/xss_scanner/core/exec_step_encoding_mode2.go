package core

import "github.com/vigolium/vigolium/pkg/httpmsg"

// EncodingMode2AttackStepExecutor implements the XSSAttackStepExecutor interface.
type EncodingMode2AttackStepExecutor struct {
	delegateExecutor AttackStepRunner
}

// NewEncodingMode2AttackStepExecutor creates a new instance.
func NewEncodingMode2AttackStepExecutor(
	delegateExecutor AttackStepRunner,
) *EncodingMode2AttackStepExecutor {
	return &EncodingMode2AttackStepExecutor{delegateExecutor: delegateExecutor}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (h *EncodingMode2AttackStepExecutor) IsAttackStepRunner() {}

func (h *EncodingMode2AttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint,
	scanFlags int,
	payload string,
	tactic ReflectionTacticType,
	contextCode byte,
	techniqueClassifier AttackTechniqueClassifier,
	useSecondaryCanary bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	encodedPayload := EncodeStringWithMode(payload, 2)

	if h.delegateExecutor != nil {
		return h.delegateExecutor.RunAttackStep(
			injectionPoint,
			scanFlags|2,
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
