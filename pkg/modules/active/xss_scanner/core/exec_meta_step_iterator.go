package core

import "github.com/vigolium/vigolium/pkg/httpmsg"

// IteratingAttackStepExecutor implements the XSSAttackStepExecutor interface.
// Original Java class: gg3
type IteratingAttackStepExecutor struct {
	childExecutors []AttackStepRunner // Corresponds to private final XSSAttackStepExecutor[] a;
}

// NewIteratingAttackStepExecutor creates a new instance of Gg3.
// Original Java constructor: public gg3(XSSAttackStepExecutor... var1)
func NewIteratingAttackStepExecutor(
	childExecutors ...AttackStepRunner,
) *IteratingAttackStepExecutor {
	// Defensive copy if needed, though Java varargs directly assign the array reference.
	// For Go, if i2js is nil, this will be an empty slice, which is fine.
	return &IteratingAttackStepExecutor{childExecutors: childExecutors}
}

// IsAttackStepRunner marker method for the XSSAttackStepExecutor interface.
func (executor *IteratingAttackStepExecutor) IsAttackStepRunner() {}

// RunAttackStep is the Go equivalent of the 'a' method from the XSSAttackStepExecutor interface for class Gg3.
// Original Java method: public PreliminaryXSSFinding a(*mutate.FuzzHTTPRequestParam var1, int var2, String var3, ll var4, byte var5, cgv var6, boolean var7, hnx var8)
func (executor *IteratingAttackStepExecutor) RunAttackStep(
	injectionPoint httpmsg.InsertionPoint, // var1
	scanFlags int, // var2
	payload string, // var3
	tactic ReflectionTacticType, // var4
	contextCode byte, // var5
	techniqueClassifier AttackTechniqueClassifier, // var6
	useSecondaryCanary bool, // var7
	profile *ScanExecutionProfile, // var8
) PotentialXSSFinding {
	// String var9 = ihj.b(); // Static call in Java, translates to IhjB() if it was a static field getter
	// In this context, this variable `var9` in Java (from `ihj.b()`) is used as a loop control for an optimization
	// that is not present in the simpler Gg3 loop. The direct port of Gg3 does not use this.

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
		// Original Java: if (var9 != null) { break; }
		// If IhjB() or its equivalent was a static flag that could change and intended to break early, that logic would go here.
		// Based on current analysis of ihj.java and gg3.java, this break is likely tied to obfuscation or specific runtime states
		// not directly translated in a 1:1 port of Gg3's primary loop logic.
		// The provided stub for IhjB simply returns a string, not affecting loop control here.
	}
	return nil
}
