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

	// Argument mapping onto ScanExecutionManager.Scan (see stubs.go):
	//   - contextCode is the raw reflection-context byte; widen it to the
	//     ReflectionContext type the manager expects.
	//   - detector is nil: this adapter runs an isolated attack step and holds
	//     no pre-built reflection detector, so the manager issues its own
	//     request and analyzes the response itself.
	//   - useSecondaryCanary maps to needsFollowUpRequest: observing a secondary
	//     canary requires a follow-up request.
	return adapter.scanManager.Scan(
		injectionPoint,
		scanFlags,
		payloadAsBytes,
		tactic,
		ReflectionContext(contextCode),
		nil,
		useSecondaryCanary,
		profile,
	)
}
