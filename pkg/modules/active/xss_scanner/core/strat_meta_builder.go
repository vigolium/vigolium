package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// It does not implement ContextualXSSTechnique itself.
type MappedStrategyBuilder struct {
	strategyMap map[byte]ContextualAttackPayloadGenerator
}

// NewMappedStrategyBuilder creates a new, initialized MappedStrategyBuilder.
func NewMappedStrategyBuilder() *MappedStrategyBuilder {
	return &MappedStrategyBuilder{
		strategyMap: make(map[byte]ContextualAttackPayloadGenerator),
	}
}

// AddStrategy adds a ContextualXSSTechnique strategy to the map and returns the builder for chaining.
func (builder *MappedStrategyBuilder) AddStrategy(
	code byte,
	strategy ContextualAttackPayloadGenerator,
) *MappedStrategyBuilder {
	builder.strategyMap[code] = strategy
	return builder
}

// Build returns a new MappedStrategyExecutor containing a copy of the collected strategies.
func (builder *MappedStrategyBuilder) Build() *MappedStrategyExecutor {
	strategyMapCopy := make(map[byte]ContextualAttackPayloadGenerator)
	for k, v := range builder.strategyMap {
		strategyMapCopy[k] = v
	}
	return NewMappedStrategyExecutor(strategyMapCopy)
}

// MappedStrategyExecutor holds a map of strategies keyed by byte code
// and executes the matching strategy for a given code.
type MappedStrategyExecutor struct {
	strategyMap map[byte]ContextualAttackPayloadGenerator
}

// NewMappedStrategyExecutor creates a MappedStrategyExecutor instance.
func NewMappedStrategyExecutor(
	strategies map[byte]ContextualAttackPayloadGenerator,
) *MappedStrategyExecutor {
	return &MappedStrategyExecutor{strategyMap: strategies}
}

func (executor *MappedStrategyExecutor) ExecuteStrategyByCode(
	strategyCode byte,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	selectedStrategy, isStrategyFound := executor.strategyMap[strategyCode]
	if !isStrategyFound ||
		selectedStrategy == nil {
		// No matching strategy found
		return nil
	}

	findingResult := selectedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)

	return findingResult
}

func (h *MappedStrategyExecutor) IsMappedStrategyExecutor() {} // Marker method
