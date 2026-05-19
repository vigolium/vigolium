// Package mab implements Multi-Armed Bandit algorithms for crawl action prioritization.
package mab

import "math"

// TransformReward transforms raw environment reward to RL reward.
// RLCRAWLER PARITY: Stateless_RL_components.py Reward_Transformer.__call__() lines 27-28
//
// Python:
//
//	def __call__(self, reward_env: float, step: int, **kwargs) -> float:
//	    return 1-math.exp(-reward_env)
//
// This exponential transformation:
// - Maps reward_env=0 to 0
// - Maps large positive rewards asymptotically to 1
// - Compresses high rewards to prevent weight explosion
func TransformReward(rewardEnv float64) float64 {
	return 1 - math.Exp(-rewardEnv)
}
