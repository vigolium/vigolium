package mab

import (
	"math"
	"testing"
)

// TestNewMABExp3Policy tests policy initialization.
// RLCRAWLER PARITY: Verify G_thr and eta_r formulas match Python
func TestNewMABExp3Policy(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	if policy.K != K {
		t.Errorf("K = %d, want %d", policy.K, K)
	}

	if policy.r != 0 {
		t.Errorf("r = %d, want 0", policy.r)
	}

	if !policy.firstCall {
		t.Error("firstCall should be true initially")
	}

	// Verify G_thr formula: ((K*ln(K))/(e-1))*(4^r) where r=0
	// K=3: (3*ln(3))/(e-1) * 1 = 3*1.0986/1.7183 ≈ 1.9178
	expectedGThr := (float64(K) * math.Log(float64(K)) / (math.E - 1)) * 1.0
	if math.Abs(policy.G_thr-expectedGThr) > 0.0001 {
		t.Errorf("G_thr = %f, want %f", policy.G_thr, expectedGThr)
	}

	// Verify eta_r formula: min(1, sqrt((K*ln(K))/((e-1)*G_thr)))
	expectedEta := math.Min(1, math.Sqrt((float64(K)*math.Log(float64(K)))/((math.E-1)*expectedGThr)))
	if math.Abs(policy.eta_r-expectedEta) > 0.0001 {
		t.Errorf("eta_r = %f, want %f", policy.eta_r, expectedEta)
	}
}

// TestAddStateAndAction tests state and action registration.
func TestAddStateAndAction(t *testing.T) {
	policy := NewMABExp3Policy(3)

	policy.AddState("state1")

	if _, exists := policy.statesActionsMap["state1"]; !exists {
		t.Error("state1 should exist after AddState")
	}

	policy.AddAction("state1", "action1")
	policy.AddAction("state1", "action2")

	stats1 := policy.statesActionsMap["state1"]["action1"]
	if stats1.R != 0 || stats1.W != 1 || stats1.P != 0 {
		t.Errorf("action1 stats = {R:%f, W:%f, P:%f}, want {R:0, W:1, P:0}", stats1.R, stats1.W, stats1.P)
	}

	// Adding same action again should not change stats
	policy.AddAction("state1", "action1")
	if stats1.W != 1 {
		t.Error("Adding same action should not reset stats")
	}
}

// TestGetProbability tests probability calculation.
// RLCRAWLER PARITY: probs = (1-eta_r)*(weights/sum(weights)) + eta_r/K
func TestGetProbability(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "BF")
	policy.AddAction("state1", "DF")
	policy.AddAction("state1", "RAND")

	// First call should calculate probabilities
	prob := policy.GetProbability("state1", "BF")

	// With all weights = 1, each action should have same probability
	// prob = (1-eta_r)*(1/3) + eta_r/K
	// With K=3 and initial eta_r ≈ 1.0, prob should be approximately 1/3
	if prob <= 0 || prob >= 1 {
		t.Errorf("prob = %f, should be between 0 and 1", prob)
	}

	// All actions should have same probability initially
	probBF := policy.GetProbability("state1", "BF")
	probDF := policy.GetProbability("state1", "DF")
	probRAND := policy.GetProbability("state1", "RAND")

	if math.Abs(probBF-probDF) > 0.0001 || math.Abs(probDF-probRAND) > 0.0001 {
		t.Errorf("All probs should be equal initially: BF=%f, DF=%f, RAND=%f", probBF, probDF, probRAND)
	}

	// Sum should be close to 1
	sumProbs := probBF + probDF + probRAND
	if math.Abs(sumProbs-1.0) > 0.0001 {
		t.Errorf("Sum of probs = %f, want 1.0", sumProbs)
	}
}

// TestUpdate tests the weight update mechanism.
// RLCRAWLER PARITY: Tests effective_reward and weight update formulas
func TestUpdate(t *testing.T) {
	// Use K=100 to avoid immediate round reset (threshold will be positive)
	K := 100
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "action1")
	policy.AddAction("state1", "action2")
	policy.AddAction("state1", "action3")

	// Calculate initial probabilities
	_ = policy.GetProbability("state1", "action1")

	// Store eta_r before update (it won't change without reset)
	etaBefore := policy.GetEta()

	// Get initial stats
	initialR, initialW, initialP, _ := policy.GetActionStats("state1", "action1")

	if initialP <= 0 {
		t.Fatalf("Initial probability should be > 0, got %f", initialP)
	}

	// Update with small reward that won't trigger reset
	reward := 0.01
	reset := policy.Update("state1", "action1", reward)

	newR, newW, _, _ := policy.GetActionStats("state1", "action1")

	// Calculate expected values using the formulas
	// effective_reward = reward / P
	effectiveReward := reward / initialP
	// w *= exp(eta_r * effective_reward / K)
	expectedW := initialW * math.Exp(etaBefore*effectiveReward/float64(K))
	// r += effective_reward
	expectedR := initialR + effectiveReward

	t.Logf("K=%d, eta_r=%f", K, etaBefore)
	t.Logf("initialP=%f, reward=%f, effectiveReward=%f", initialP, reward, effectiveReward)
	t.Logf("initialW=%f, expectedW=%f, newW=%f", initialW, expectedW, newW)
	t.Logf("initialR=%f, expectedR=%f, newR=%f", initialR, expectedR, newR)
	t.Logf("G_thr=%f, threshold=%f, reset=%v", policy.G_thr, policy.G_thr-float64(K)/etaBefore, reset)

	// Weight should increase after positive reward
	if math.Abs(newW-expectedW) > 0.0001 {
		t.Errorf("Weight = %f, want %f", newW, expectedW)
	}

	// Cumulative reward should increase
	if math.Abs(newR-expectedR) > 0.0001 {
		t.Errorf("Cumulative reward R = %f, want %f", newR, expectedR)
	}
}

// TestUpdateWithSmallK tests that with small K, rounds reset quickly.
// This is expected Exp3.1 behavior - threshold = G_thr - K/eta_r can be negative.
func TestUpdateWithSmallK(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "BF")
	policy.AddAction("state1", "DF")
	policy.AddAction("state1", "RAND")

	// Calculate initial probabilities
	_ = policy.GetProbability("state1", "BF")

	initialRound := policy.GetRound()
	initialGThr := policy.G_thr

	// With K=3, threshold = G_thr - K/eta ≈ 1.92 - 3 = -1.08
	// Any positive R will trigger reset
	threshold := initialGThr - float64(K)/policy.GetEta()
	t.Logf("K=%d, G_thr=%f, eta=%f, threshold=%f", K, initialGThr, policy.GetEta(), threshold)

	// Update with positive reward
	reset := policy.Update("state1", "BF", 0.5)

	// With small K, reset should occur
	if threshold < 0 && !reset {
		t.Errorf("Expected reset with negative threshold (%f)", threshold)
	}

	if reset {
		// After reset, round should increment
		if policy.GetRound() != initialRound+1 {
			t.Errorf("Round = %d, want %d", policy.GetRound(), initialRound+1)
		}
		// G_thr should increase by factor of 4
		expectedGThr := initialGThr * 4
		if math.Abs(policy.G_thr-expectedGThr) > 0.0001 {
			t.Errorf("G_thr = %f, want %f", policy.G_thr, expectedGThr)
		}
	}
}

// TestSelectAction tests action selection by probability.
func TestSelectAction(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "BF")
	policy.AddAction("state1", "DF")
	policy.AddAction("state1", "RAND")

	// Calculate probabilities
	_ = policy.GetProbability("state1", "BF")

	// Run selection multiple times
	selections := make(map[string]int)
	n := 1000
	for i := 0; i < n; i++ {
		selected := policy.SelectAction("state1", []string{"BF", "DF", "RAND"})
		selections[selected]++
	}

	// Each action should be selected roughly 1/3 of the time
	for _, action := range []string{"BF", "DF", "RAND"} {
		ratio := float64(selections[action]) / float64(n)
		if ratio < 0.2 || ratio > 0.5 {
			t.Errorf("Action %s selected %d times (%.2f), expected roughly 1/3", action, selections[action], ratio)
		}
	}
}

// TestSelectActionWithUnbalancedWeights tests that higher weights lead to higher selection probability.
func TestSelectActionWithUnbalancedWeights(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "BF")
	policy.AddAction("state1", "DF")
	policy.AddAction("state1", "RAND")

	// Calculate initial probabilities
	_ = policy.GetProbability("state1", "BF")

	// Give BF multiple high rewards to increase its weight
	for i := 0; i < 10; i++ {
		policy.Update("state1", "BF", 1.0)
	}

	// Run selection multiple times
	selections := make(map[string]int)
	n := 1000
	for i := 0; i < n; i++ {
		selected := policy.SelectAction("state1", []string{"BF", "DF", "RAND"})
		selections[selected]++
	}

	// BF should be selected more often than others
	if selections["BF"] <= selections["DF"] || selections["BF"] <= selections["RAND"] {
		t.Errorf("BF should be selected most often: BF=%d, DF=%d, RAND=%d",
			selections["BF"], selections["DF"], selections["RAND"])
	}
}

// TestRoundReset tests the round reset mechanism.
// RLCRAWLER PARITY: Tests G_thr update and weight reset
func TestRoundReset(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	policy.AddState("state1")
	policy.AddAction("state1", "BF")

	// Calculate initial probabilities
	_ = policy.GetProbability("state1", "BF")

	initialRound := policy.GetRound()
	initialGThr := policy.G_thr
	initialEta := policy.GetEta()

	// Force reset by giving very high rewards
	// Round ends when R > G_thr - K/eta_r
	reset := false
	for i := 0; i < 100 && !reset; i++ {
		reset = policy.Update("state1", "BF", 10.0)
	}

	if !reset {
		t.Error("Expected reset to occur after high rewards")
	}

	newRound := policy.GetRound()
	if newRound != initialRound+1 {
		t.Errorf("Round = %d, want %d", newRound, initialRound+1)
	}

	// G_thr should increase (4^r factor)
	if policy.G_thr <= initialGThr {
		t.Errorf("G_thr should increase after reset: %f -> %f", initialGThr, policy.G_thr)
	}

	// eta_r should decrease (as G_thr increases)
	if policy.GetEta() >= initialEta {
		t.Errorf("eta_r should decrease after reset: %f -> %f", initialEta, policy.GetEta())
	}

	// Weight should be reset to 1
	_, w, _, _ := policy.GetActionStats("state1", "BF")
	if w != 1 {
		t.Errorf("Weight should be reset to 1, got %f", w)
	}
}

// TestTransformReward tests the reward transformer.
// RLCRAWLER PARITY: return 1-math.exp(-reward_env)
func TestTransformReward(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{0, 0},                  // 1 - e^0 = 0
		{1, 1 - math.Exp(-1)},   // ≈ 0.632
		{2, 1 - math.Exp(-2)},   // ≈ 0.865
		{10, 1 - math.Exp(-10)}, // ≈ 0.99995
		{-1, 1 - math.Exp(1)},   // negative input (edge case)
	}

	for _, tc := range tests {
		result := TransformReward(tc.input)
		if math.Abs(result-tc.expected) > 0.0001 {
			t.Errorf("TransformReward(%f) = %f, want %f", tc.input, result, tc.expected)
		}
	}
}

// TestEmptyState tests behavior with empty/missing state.
func TestEmptyState(t *testing.T) {
	policy := NewMABExp3Policy(3)

	// GetProbability on non-existent state should return 0
	prob := policy.GetProbability("nonexistent", "action")
	if prob != 0 {
		t.Errorf("GetProbability on non-existent state = %f, want 0", prob)
	}

	// Update on non-existent state should return false
	reset := policy.Update("nonexistent", "action", 1.0)
	if reset {
		t.Error("Update on non-existent state should return false")
	}

	// SelectAction on non-existent state should return empty string
	selected := policy.SelectAction("nonexistent", []string{"action"})
	if selected != "" {
		t.Errorf("SelectAction on non-existent state = %s, want empty", selected)
	}
}

// TestConcurrentAccess tests thread safety.
func TestConcurrentAccess(t *testing.T) {
	policy := NewMABExp3Policy(3)
	policy.AddState("state1")
	policy.AddAction("state1", "BF")
	policy.AddAction("state1", "DF")
	policy.AddAction("state1", "RAND")

	// Calculate initial probabilities
	_ = policy.GetProbability("state1", "BF")

	done := make(chan bool)

	// Concurrent updates
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				policy.Update("state1", "BF", 0.1)
			}
			done <- true
		}()
	}

	// Concurrent selections
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				policy.SelectAction("state1", []string{"BF", "DF", "RAND"})
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not panic or deadlock
}

// TestMultipleStatesProbabilityCalculation tests that new states get probabilities calculated.
// This tests the fix for the firstCall bug where new states had zero probabilities.
func TestMultipleStatesProbabilityCalculation(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	// Add first state and calculate probabilities
	policy.AddState("state1")
	policy.AddAction("state1", "action1")
	policy.AddAction("state1", "action2")
	policy.AddAction("state1", "action3")

	// Get probability triggers calculation for state1
	prob1 := policy.GetProbability("state1", "action1")
	if prob1 <= 0 {
		t.Errorf("state1 action1 probability should be > 0, got %f", prob1)
	}

	// Now add a NEW state AFTER firstCall has been set to false
	policy.AddState("state2")
	policy.AddAction("state2", "actionA")
	policy.AddAction("state2", "actionB")

	// BUG FIX: This should calculate probabilities for state2 even though
	// firstCall is already false (because state2 is new and has P=0)
	prob2 := policy.GetProbability("state2", "actionA")
	if prob2 <= 0 {
		t.Errorf("state2 actionA probability should be > 0 after fix, got %f", prob2)
	}

	// Verify all state2 actions have non-zero probabilities
	prob2B := policy.GetProbability("state2", "actionB")
	if prob2B <= 0 {
		t.Errorf("state2 actionB probability should be > 0, got %f", prob2B)
	}

	// Note: Sum of probabilities may not be exactly 1 because the Exp3.1 formula
	// uses global K, not per-state action count. This is expected behavior matching
	// RLcrawler. SelectAction normalizes before sampling.
	sumProbs := prob2 + prob2B
	t.Logf("state2 probs sum = %f (K=%d, num_actions=2)", sumProbs, K)

	// Add third state dynamically
	policy.AddState("state3")
	policy.AddAction("state3", "x")
	policy.AddAction("state3", "y")
	policy.AddAction("state3", "z")
	policy.AddAction("state3", "w")

	// state3 should also get probabilities calculated
	prob3X := policy.GetProbability("state3", "x")
	prob3Y := policy.GetProbability("state3", "y")
	prob3Z := policy.GetProbability("state3", "z")
	prob3W := policy.GetProbability("state3", "w")

	if prob3X <= 0 || prob3Y <= 0 || prob3Z <= 0 || prob3W <= 0 {
		t.Errorf("state3 probabilities should all be > 0: x=%f, y=%f, z=%f, w=%f",
			prob3X, prob3Y, prob3Z, prob3W)
	}

	sumProbs3 := prob3X + prob3Y + prob3Z + prob3W
	t.Logf("state3 probs sum = %f (K=%d, num_actions=4)", sumProbs3, K)
}

// TestSelectActionOnNewState verifies SelectAction works on newly added states.
func TestSelectActionOnNewState(t *testing.T) {
	K := 3
	policy := NewMABExp3Policy(K)

	// Initialize first state
	policy.AddState("state1")
	policy.AddAction("state1", "a1")
	policy.AddAction("state1", "a2")
	_ = policy.GetProbability("state1", "a1")

	// Add new state dynamically (simulating crawler discovering new DOM state)
	policy.AddState("newState")
	policy.AddAction("newState", "click1")
	policy.AddAction("newState", "click2")
	policy.AddAction("newState", "click3")

	// SelectAction should work on new state without any prior GetProbability call
	// because SelectAction internally calls getProbabilityLocked which triggers calculation
	selections := make(map[string]int)
	n := 300
	for i := 0; i < n; i++ {
		selected := policy.SelectAction("newState", []string{"click1", "click2", "click3"})
		if selected == "" {
			t.Fatal("SelectAction should not return empty string for valid state")
		}
		selections[selected]++
	}

	// Verify all actions were selected at least once (probabilistic, but should pass with n=300)
	for _, action := range []string{"click1", "click2", "click3"} {
		if selections[action] == 0 {
			t.Errorf("Action %s was never selected in %d trials", action, n)
		}
	}
}
