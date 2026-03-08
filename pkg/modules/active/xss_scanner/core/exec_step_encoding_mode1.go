package core

import "github.com/vigolium/vigolium/pkg/httpmsg"

// EncodingMode1AttackStepExecutor implements the XSSAttackStepExecutor interface.
// Original Java class: frz
type EncodingMode1AttackStepExecutor struct {
	delegateExecutor AttackStepRunner // Corresponds to private final XSSAttackStepExecutor a;
}

// NewEncodingMode1AttackStepExecutor creates a new instance of Frz.
// Original Java constructor: public frz(XSSAttackStepExecutor var1)
func NewEncodingMode1AttackStepExecutor(
	delegateExecutor AttackStepRunner,
) *EncodingMode1AttackStepExecutor {
	return &EncodingMode1AttackStepExecutor{delegateExecutor: delegateExecutor}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (executor *EncodingMode1AttackStepExecutor) IsAttackStepRunner() {}

// RunAttackStep is the Go equivalent of the 'a' method from the XSSAttackStepExecutor interface for class Frz.
// Original Java method: public PreliminaryXSSFinding a(*mutate.FuzzHTTPRequestParam var1, int var2, String var3, ll var4, byte var5, cgv var6, boolean var7, hnx var8)
// This is a simplified stub. The full Java logic involves string transformation via c6w.a
// and bitwise ORing the intCVal (var2) with 1.
func (executor *EncodingMode1AttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint, // var1
	scanFlags int, // var2
	payload string, // var3
	tactic ReflectionTacticType, // var4
	contextCode byte, // var5
	techniqueClassifier AttackTechniqueClassifier, // var6
	useSecondaryCanary bool, // var7
	profile *ScanExecutionProfile, // var8
) PotentialXSSFinding {
	// String var9 = ihj.b(); // Static call, not directly used in this simplified delegated call but affects original Java control flow
	encodedPayload := EncodeStringWithMode(payload, 1) // String transformation logic missing in stub
	// For this stub, we pass the original formattedPayload and apply the bitwise OR to intCVal.
	if executor.delegateExecutor != nil {
		// In a full port, var10 (transformed payload) would be passed instead of formattedPayload.
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
