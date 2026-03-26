package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BytePayloadModifier defines the interface for payload transformation.
type BytePayloadModifier interface {
	Modify(payload []byte) []byte
}

// PayloadModificationContext stores context data for payload transformation.
type PayloadModificationContext struct {
	primaryData []byte
	prefixData []byte
	dataWithBreakoutSequence []byte
	breakoutSequenceBytes []byte
}

// NewPayloadModificationContextWithPrefix creates a new PayloadModificationContext with a prefix and main data.
func NewPayloadModificationContextWithPrefix(
	prefix []byte,
	mainData []byte,
	randomProvider *utils.RandomGenerator,
) *PayloadModificationContext {
	context := &PayloadModificationContext{}
	context.primaryData = mainData
	context.prefixData = prefix

	randomComponent := ""
	if randomProvider != nil {
		randomComponent = randomProvider.GeneratePrefixedAlphanumeric(5)
	}
	breakoutSequenceString := randomComponent + "'/\"<" + randomComponent // Escaped the double quote
	context.breakoutSequenceBytes = utils.StringToBytes(breakoutSequenceString)

	// Combine prefix, mainData, and breakout payload
	context.dataWithBreakoutSequence = utils.CombineByteSlices(
		prefix,
		mainData,
		context.breakoutSequenceBytes,
	)

	return context
}

// NewPayloadModificationContext creates a new PayloadModificationContext with an empty prefix.
func NewPayloadModificationContext(
	mainData []byte,
	randomProvider *utils.RandomGenerator,
) *PayloadModificationContext {
	return NewPayloadModificationContextWithPrefix([]byte{}, mainData, randomProvider)
}

// GetPrefixedPrimaryData returns the primary data with the prefix prepended.
func (tc *PayloadModificationContext) GetPrefixedPrimaryData() []byte {
	// Combine prefix and primary data
	return utils.CombineByteSlices(tc.prefixData, tc.primaryData)
}

// HasPrefix returns whether the context has a non-empty prefix.
func (tc *PayloadModificationContext) HasPrefix() bool {
	return len(tc.prefixData) > 0
}

// PrefixingPayloadModifier implements BytePayloadModifier, applying transformations based on a PayloadModificationContext.
type PrefixingPayloadModifier struct {
	context *PayloadModificationContext
}

// NewPrefixingPayloadModifier creates a new PrefixingPayloadModifier instance.
func NewPrefixingPayloadModifier(
	context *PayloadModificationContext,
) *PrefixingPayloadModifier {
	return &PrefixingPayloadModifier{
		context: context,
	}
}

// Modify combines the context's prefixed data with the input payload.
func (ct *PrefixingPayloadModifier) Modify(payload []byte) []byte {
	if ct.context == nil {
		return payload
	}

	inputPayloadCopy := make([]byte, len(payload))
	copy(inputPayloadCopy, payload)

	contextPrefixedData := ct.context.GetPrefixedPrimaryData()
	return utils.CombineByteSlices(contextPrefixedData, inputPayloadCopy)
}

// NoOpPayloadModifier implements BytePayloadModifier, returning the input payload unchanged.
type NoOpPayloadModifier struct{}

func NewNoOpPayloadModifier() BytePayloadModifier {
	return &NoOpPayloadModifier{}
}

// Modify returns the input payload unchanged.
func (pt *NoOpPayloadModifier) Modify(payload []byte) []byte {
	return payload
}
