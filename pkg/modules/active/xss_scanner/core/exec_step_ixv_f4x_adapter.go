package core

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// AttackControllerAdapterExecutor implements the I2j interface.
// Original Java class: ixv
type AttackControllerAdapterExecutor struct {
	scanManager ScanExecutionManager // Corresponds to private final f4x a;
}

// NewAttackControllerAdapterExecutor creates a new instance of Ixv.
// Original Java constructor: public ixv(f4x var1)
func NewAttackControllerAdapterExecutor(
	scanManager ScanExecutionManager,
) *AttackControllerAdapterExecutor {
	return &AttackControllerAdapterExecutor{scanManager: scanManager}
}

// IsAttackStepRunner marker method for the I2j interface.
func (adapter *AttackControllerAdapterExecutor) IsAttackStepRunner() {}

// RunAttackStep is the Go equivalent of the 'a' method from the i2j interface for class Ixv.
// Original Java method: public bgf a(bno var1, int var2, String var3, ll var4, byte var5, cgv var6, boolean var7, hnx var8)
func (adapter *AttackControllerAdapterExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint, // var1
	scanFlags int, // var2
	payload string, // var3 (String in Java)
	tactic ReflectionTacticType, // var4
	contextCode byte, // var5
	techniqueClassifier AttackTechniqueClassifier, // var6
	useSecondaryCanary bool, // var7
	profile *ScanExecutionProfile, // var8
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
