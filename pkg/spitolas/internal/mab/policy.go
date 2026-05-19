// Package mab implements Multi-Armed Bandit algorithms for crawl action prioritization.
package mab

import (
	"math"
	"math/rand"
	"sync"
)

// DefaultK is the default number of arms for MAB policy.
// K=100 provides a good balance:
// - Large enough for positive threshold (G_thr - K/eta > 0)
// - Small enough to be memory efficient
// - Suitable for typical web crawling scenarios
const DefaultK = 100

// ActionStats matches Python {"r": 0, "w": 1, "p": 0}
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py line 24
type ActionStats struct {
	R float64 // Cumulative reward (effective_reward)
	W float64 // Weight (initialized to 1.0)
	P float64 // Probability (initialized to 0.0)
}

// MABExp3Policy implements Exp3.1 Multi-Armed Bandit policy.
//
// Key insight: K is GLOBAL, not per-state.
// This is critical for correct Exp3.1 algorithm behavior.
//
// ADAPTATION FOR MULTI-STATE ARCHITECTURE:
// RLcrawler uses single state where same actions can be executed multiple times,
// allowing per-action R to accumulate and trigger round reset.
// Spitolas uses multiple states with click-once semantics (each action executed once).
// To compensate, we track GLOBAL cumulative R across ALL actions in ALL states,
// which triggers round reset based on total learning progress.
type MABExp3Policy struct {
	K                int                                // GLOBAL K (number of arms)
	statesActionsMap map[string]map[string]*ActionStats // state_id -> action_id -> stats
	firstCall        bool                               // first probability calculation flag
	r                int                                // GLOBAL round counter
	G_thr            float64                            // GLOBAL gain threshold
	eta_r            float64                            // GLOBAL learning rate
	globalR          float64                            // GLOBAL cumulative effective reward (for round reset)
	mu               sync.RWMutex
}

// NewMABExp3Policy creates a new policy with GLOBAL K.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py __init__(self, K) lines 10-16
//
// Python:
//
//	self.K = K
//	self.states_actions_map = {}
//	self.first_call = True
//	self.r = 0
//	self.G_thr = ((K*math.log(K))/(math.e-1))*(4**self.r)
//	self.eta_r = min(1, math.sqrt((K*math.log(K))/((math.e-1)*self.G_thr)))
func NewMABExp3Policy(K int) *MABExp3Policy {
	// G_thr = ((K*ln(K))/(e-1))*(4^r) where r=0 initially
	// 4^0 = 1
	G_thr := (float64(K) * math.Log(float64(K)) / (math.E - 1)) * 1.0

	// eta_r = min(1, sqrt((K*ln(K))/((e-1)*G_thr)))
	eta_r := math.Min(1, math.Sqrt((float64(K)*math.Log(float64(K)))/((math.E-1)*G_thr)))

	return &MABExp3Policy{
		K:                K,
		statesActionsMap: make(map[string]map[string]*ActionStats),
		firstCall:        true,
		r:                0,
		G_thr:            G_thr,
		eta_r:            eta_r,
		globalR:          0,
	}
}

// AddState adds a new state to the policy.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py add_state() lines 18-20
//
// Python:
//
//	def add_state(self, state: Abs_State):
//	    if state.get_id() not in self.states_actions_map.keys():
//	        self.states_actions_map[state.get_id()] = {}
func (p *MABExp3Policy) AddState(stateID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.statesActionsMap[stateID]; !exists {
		p.statesActionsMap[stateID] = make(map[string]*ActionStats)
	}
}

// AddAction adds a new action to a state.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py add_action() lines 22-24
//
// Python:
//
//	def add_action(self, state: Abs_State, action: Abs_Action):
//	    if action.get_id() not in self.states_actions_map[state.get_id()].keys():
//	        self.states_actions_map[state.get_id()][action.get_id()] = {"r":0, "w":1, "p":0}
func (p *MABExp3Policy) AddAction(stateID, actionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Ensure state exists first
	if _, exists := p.statesActionsMap[stateID]; !exists {
		p.statesActionsMap[stateID] = make(map[string]*ActionStats)
	}

	if _, exists := p.statesActionsMap[stateID][actionID]; !exists {
		p.statesActionsMap[stateID][actionID] = &ActionStats{R: 0, W: 1, P: 0}

		// Spitolas ADAPTATION: If state already has actions with calculated probabilities,
		// recalculate to include the new action. This handles re-added actions (retry after failure).
		if !p.stateNeedsProbabilityCalculation(stateID) {
			p.recalculateProbabilitiesLocked(stateID)
		}
	}
}

// RemoveAction removes an action from a state after it has been executed.
// Spitolas ADAPTATION: In click-once semantics, executed actions are removed from
// the candidate cache. We need to sync MAB state to match, otherwise probability
// calculations will be based on stale action counts.
func (p *MABExp3Policy) RemoveAction(stateID, actionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	stateActions, exists := p.statesActionsMap[stateID]
	if !exists {
		return
	}

	delete(stateActions, actionID)

	// Recalculate probabilities for remaining actions
	if len(stateActions) > 0 {
		p.recalculateProbabilitiesLocked(stateID)
	}
}

// GetProbability returns the probability for an action in a state.
// On first call for a state, calculates probabilities from weights.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py __call__() lines 26-35
//
// Python:
//
//	def __call__(self, state: Abs_State, action: Abs_Action):
//	    if self.first_call:
//	        weights = []
//	        for memo_action in self.states_actions_map[state.get_id()].keys():
//	            weights.append(self.states_actions_map[state.get_id()][memo_action]["w"])
//	        probs = (1-self.eta_r)*(np.array(weights)/sum(weights)) + self.eta_r/self.K
//	        for count, memo_action in enumerate(self.states_actions_map[state.get_id()].keys()):
//	            self.states_actions_map[state.get_id()][memo_action]["p"] = probs[count]
//	        self.first_call = False
//	    return self.states_actions_map[state.get_id()][action.get_id()]["p"]
func (p *MABExp3Policy) GetProbability(stateID, actionID string) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.getProbabilityLocked(stateID, actionID)
}

// getProbabilityLocked is the internal version that requires lock to be held.
// NOTE: Unlike RLcrawler which uses single state (Stateless_RL), spitolas uses
// multiple DOM states. We need to calculate probabilities for EACH state when
// it's first queried, not just globally on firstCall.
func (p *MABExp3Policy) getProbabilityLocked(stateID, actionID string) float64 {
	stateActions, exists := p.statesActionsMap[stateID]
	if !exists {
		return 0
	}

	// Check if THIS state needs probability calculation
	// A state needs calculation if all its actions have P=0 (initial state)
	needsCalculation := p.stateNeedsProbabilityCalculation(stateID)
	if needsCalculation {
		p.recalculateProbabilitiesLocked(stateID)
		p.firstCall = false // Keep for compatibility
	}

	if stats, exists := stateActions[actionID]; exists {
		return stats.P
	}
	return 0
}

// stateNeedsProbabilityCalculation checks if a state's probabilities need to be calculated.
// Returns true if all actions have P=0 (meaning probabilities were never calculated).
func (p *MABExp3Policy) stateNeedsProbabilityCalculation(stateID string) bool {
	stateActions, exists := p.statesActionsMap[stateID]
	if !exists || len(stateActions) == 0 {
		return false
	}

	// If any action has P > 0, probabilities have already been calculated
	for _, stats := range stateActions {
		if stats.P > 0 {
			return false
		}
	}
	return true
}

// recalculateProbabilitiesLocked recalculates probabilities for all actions in a state.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py lines 59-64
//
// Python:
//
//	weights = []
//	for memo_action in self.states_actions_map[state.get_id()].keys():
//	    weights.append(self.states_actions_map[state.get_id()][memo_action]["w"])
//	probs = (1-self.eta_r)*(np.array(weights)/sum(weights)) + self.eta_r/self.K
//	for count, memo_action in enumerate(self.states_actions_map[state.get_id()].keys()):
//	    self.states_actions_map[state.get_id()][memo_action]["p"] = probs[count]
func (p *MABExp3Policy) recalculateProbabilitiesLocked(stateID string) {
	stateActions := p.statesActionsMap[stateID]
	if len(stateActions) == 0 {
		return
	}

	// Collect weights
	weights := make([]float64, 0, len(stateActions))
	actionIDs := make([]string, 0, len(stateActions))
	for aid, stats := range stateActions {
		weights = append(weights, stats.W)
		actionIDs = append(actionIDs, aid)
	}

	// Sum weights
	sumWeights := 0.0
	for _, w := range weights {
		sumWeights += w
	}

	// probs = (1-eta_r)*(weights/sum(weights)) + eta_r/K
	for i, aid := range actionIDs {
		prob := (1-p.eta_r)*(weights[i]/sumWeights) + p.eta_r/float64(p.K)
		p.statesActionsMap[stateID][aid].P = prob
	}
}

// Update updates the policy after an action is executed.
// RLCRAWLER PARITY: MAB_Exp3_31_policy.py update() lines 37-69
//
// Python:
//
//	def update(self, state: Abs_State, action: Abs_Action, new_state: Abs_State, new_actions, reward: float):
//	    #update weight
//	    effective_reward = reward/self.states_actions_map[state.get_id()][action.get_id()]["p"]
//	    self.states_actions_map[state.get_id()][action.get_id()]["w"] *= math.exp(self.eta_r*effective_reward/self.K)
//
//	    self.states_actions_map[state.get_id()][action.get_id()]["r"] += effective_reward
//
//	    #reset
//	    reset = False
//	    end_round = False
//	    for memo_action in self.states_actions_map[state.get_id()].keys():
//	        if self.states_actions_map[state.get_id()][action.get_id()]["r"] > self.G_thr - self.K/self.eta_r:
//	            end_round = True
//	    if end_round:
//	        reset = True
//	        self.r += 1
//	        self.G_thr = ((self.K*math.log(self.K))/(math.e-1))*(4**self.r)
//	        self.eta_r = min(1, math.sqrt((self.K*math.log(self.K))/((math.e-1)*self.G_thr)))
//	        for memo_action in self.states_actions_map[state.get_id()].keys():
//	            self.states_actions_map[state.get_id()][memo_action]["w"] = 1
//
//	    weights = []
//	    for memo_action in self.states_actions_map[state.get_id()].keys():
//	        weights.append(self.states_actions_map[state.get_id()][memo_action]["w"])
//	    probs = (1-self.eta_r)*(np.array(weights)/sum(weights)) + self.eta_r/self.K
//	    for count, memo_action in enumerate(self.states_actions_map[state.get_id()].keys()):
//	        self.states_actions_map[state.get_id()][memo_action]["p"] = probs[count]
//
//	    return return_values, reset
func (p *MABExp3Policy) Update(stateID, actionID string, reward float64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	stateActions, exists := p.statesActionsMap[stateID]
	if !exists {
		return false
	}

	stats, exists := stateActions[actionID]
	if !exists {
		return false
	}

	// Prevent division by zero
	if stats.P <= 0 {
		return false
	}

	// Step 1: Calculate effective reward (importance sampling)
	// effective_reward = reward/self.states_actions_map[state.get_id()][action.get_id()]["p"]
	effectiveReward := reward / stats.P

	// Step 2: Update weight (multiplicative)
	// self.states_actions_map[...]["w"] *= math.exp(self.eta_r*effective_reward/self.K)
	stats.W *= math.Exp(p.eta_r * effectiveReward / float64(p.K))

	// Step 3: Accumulate effective reward (per-action for logging)
	// self.states_actions_map[...]["r"] += effective_reward
	stats.R += effectiveReward

	// Step 3b: Accumulate GLOBAL effective reward (for round reset in multi-state architecture)
	// ADAPTATION: In RLcrawler, same action can be executed multiple times, allowing per-action R
	// to accumulate. In spitolas with click-once, we track globalR across all actions.
	p.globalR += effectiveReward

	// Step 4: Check round end condition using GLOBAL R
	// RLCRAWLER PARITY (adapted): Original checks per-action R, but with click-once semantics
	// we need to check global cumulative R to trigger round reset at appropriate intervals.
	// This ensures eta_r decreases over time, making weights more influential.
	reset := false
	threshold := p.G_thr - float64(p.K)/p.eta_r
	endRound := p.globalR > threshold

	// Step 5: Reset if round ended
	if endRound {
		reset = true
		p.r++
		// self.G_thr = ((self.K*math.log(self.K))/(math.e-1))*(4**self.r)
		p.G_thr = (float64(p.K) * math.Log(float64(p.K)) / (math.E - 1)) * math.Pow(4, float64(p.r))
		// self.eta_r = min(1, math.sqrt((self.K*math.log(self.K))/((math.e-1)*self.G_thr)))
		p.eta_r = math.Min(1, math.Sqrt((float64(p.K)*math.Log(float64(p.K)))/((math.E-1)*p.G_thr)))

		// ADAPTATION: Reset weights and recalculate probabilities for ALL states
		// since we use global round tracking and eta_r affects ALL probability calculations
		for sid, actions := range p.statesActionsMap {
			for _, s := range actions {
				s.W = 1
			}
			// Recalculate probabilities for this state with new eta_r
			p.recalculateProbabilitiesLocked(sid)
		}

		// Reset globalR for the new round
		p.globalR = 0
	} else {
		// Step 6: Recalculate probabilities only for current state (no round reset)
		p.recalculateProbabilitiesLocked(stateID)
	}

	return reset
}

// SelectAction selects an action based on probabilities.
// RLCRAWLER PARITY: Stateless_RL_algorithm.py choose_action() lines 36-43
//
// Python:
//
//	def choose_action(self, state: Abs_State, valid_actions: Sequence[Abs_Action], episode_step: int, step: int) -> Abs_Action | None:
//	    probabilities = [self.policy(state, action) for action in valid_actions]
//	    probabilities = [a for a in probabilities if a is not None]
//	    if len(probabilities) > 0:
//	        return np.random.choice(np.array(valid_actions), p=probabilities)
//	    else:
//	        return None
func (p *MABExp3Policy) SelectAction(stateID string, availableActionIDs []string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(availableActionIDs) == 0 {
		return ""
	}

	stateActions := p.statesActionsMap[stateID]
	if stateActions == nil {
		return ""
	}

	// Get probabilities for available actions
	// probabilities = [self.policy(state, action) for action in valid_actions]
	// NOTE: We call getProbabilityLocked to ensure probabilities are calculated
	// for new states (matching Python's self.policy(state, action) call behavior)
	probs := make([]float64, len(availableActionIDs))
	for i, aid := range availableActionIDs {
		probs[i] = p.getProbabilityLocked(stateID, aid)
	}

	// Filter out zero probabilities
	// probabilities = [a for a in probabilities if a is not None]
	validProbs := make([]float64, 0, len(probs))
	validIDs := make([]string, 0, len(probs))
	for i, prob := range probs {
		if prob > 0 {
			validProbs = append(validProbs, prob)
			validIDs = append(validIDs, availableActionIDs[i])
		}
	}

	if len(validProbs) == 0 {
		return ""
	}

	// Normalize probabilities to sum to 1
	sum := 0.0
	for _, prob := range validProbs {
		sum += prob
	}
	if sum > 0 {
		for i := range validProbs {
			validProbs[i] /= sum
		}
	}

	// Sample action by probability (numpy.random.choice equivalent)
	// return np.random.choice(np.array(valid_actions), p=probabilities)
	r := rand.Float64()
	cumProb := 0.0
	for i, prob := range validProbs {
		cumProb += prob
		if r <= cumProb {
			return validIDs[i]
		}
	}

	// Fallback to last valid action
	return validIDs[len(validIDs)-1]
}

// GetRound returns the current round number.
func (p *MABExp3Policy) GetRound() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.r
}

// GetEta returns the current learning rate.
func (p *MABExp3Policy) GetEta() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.eta_r
}

// GetK returns the number of arms.
func (p *MABExp3Policy) GetK() int {
	return p.K
}

// GetActionStats returns stats for an action (for debugging/logging).
func (p *MABExp3Policy) GetActionStats(stateID, actionID string) (r, w, prob float64, exists bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if stateActions, ok := p.statesActionsMap[stateID]; ok {
		if stats, ok := stateActions[actionID]; ok {
			return stats.R, stats.W, stats.P, true
		}
	}
	return 0, 0, 0, false
}

// GetStateCount returns the number of states tracked by MAB.
func (p *MABExp3Policy) GetStateCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.statesActionsMap)
}

// GetActionCount returns the total number of actions across all states.
func (p *MABExp3Policy) GetActionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, actions := range p.statesActionsMap {
		total += len(actions)
	}
	return total
}

// GetStateActionCount returns the number of actions for a specific state.
func (p *MABExp3Policy) GetStateActionCount(stateID string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if actions, exists := p.statesActionsMap[stateID]; exists {
		return len(actions)
	}
	return 0
}

// DumpStats returns a summary of all states and actions for debugging.
func (p *MABExp3Policy) DumpStats() map[string][]ActionStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[string][]ActionStats)
	for stateID, actions := range p.statesActionsMap {
		stats := make([]ActionStats, 0, len(actions))
		for _, s := range actions {
			stats = append(stats, *s)
		}
		result[stateID] = stats
	}
	return result
}

// GetGlobalParams returns global MAB parameters for debugging.
func (p *MABExp3Policy) GetGlobalParams() (k int, r int, gThr, eta, globalR float64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.K, p.r, p.G_thr, p.eta_r, p.globalR
}
