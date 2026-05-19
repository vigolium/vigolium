package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ContextualPrefixPayloadTransformer implements the BytePayloadModifier interface.
type ContextualPrefixPayloadTransformer struct {
	transformContext *PayloadModificationContext
}

// NewContextualPrefixPayloadTransformer creates a new instance.
func NewContextualPrefixPayloadTransformer(
	context *PayloadModificationContext,
) *ContextualPrefixPayloadTransformer {
	return &ContextualPrefixPayloadTransformer{
		transformContext: context,
	}
}

// Modify implements the BytePayloadModifier interface.
func (el6 *ContextualPrefixPayloadTransformer) Modify(payload []byte) []byte {
	if el6.transformContext == nil {
		return payload
	}
	inputPayloadCopy := make([]byte, len(payload))
	copy(inputPayloadCopy, payload)

	contextPrefixAndMainData := el6.transformContext.GetPrefixedPrimaryData()
	return utils.CombineByteSlices(contextPrefixAndMainData, inputPayloadCopy)
}
