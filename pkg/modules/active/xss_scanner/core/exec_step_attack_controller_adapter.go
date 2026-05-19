package core

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// AttackControllerAdapterExecutor implements the AttackStepRunner interface.
type AttackControllerAdapterExecutor struct {
	scanManager ScanExecutionManager
}

// NewAttackControllerAdapterExecutor creates a new AttackControllerAdapterExecutor.
func NewAttackControllerAdapterExecutor(
	scanManager ScanExecutionManager,
) *AttackControllerAdapterExecutor {
	return &AttackControllerAdapterExecutor{scanManager: scanManager}
}

// IsAttackStepRunner marker method for the AttackStepRunner interface.
func (adapter *AttackControllerAdapterExecutor) IsAttackStepRunner() {}

func (adapter *AttackControllerAdapterExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint,
	scanFlags int,
	payload string,
	tactic ReflectionTacticType,
	contextCode byte,
	techniqueClassifier AttackTechniqueClassifier,
	useSecondaryCanary bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {

	payloadAsBytes := utils.StringToBytes(payload)

	return adapter.scanManager.Scan(
		injectionPoint,
		scanFlags,
		payloadAsBytes,
		tactic,
		ReflectionContext(contextCode), //TODO
		nil,                            // TODO: check this
		useSecondaryCanary,             // TODO: check this

		profile,
	)
}
