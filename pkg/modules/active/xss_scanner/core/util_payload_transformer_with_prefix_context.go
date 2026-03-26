package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ContextualPrefixPayloadTransformer implements the C5s interface.
// Original Java class: el6
type ContextualPrefixPayloadTransformer struct {
	// private final d2 a;
	transformContext *PayloadModificationContext
}

// NewContextualPrefixPayloadTransformer creates a new instance of El6.
// Original Java constructor: el6(d2 var1)
func NewContextualPrefixPayloadTransformer(
	context *PayloadModificationContext,
) *ContextualPrefixPayloadTransformer {
	return &ContextualPrefixPayloadTransformer{
		transformContext: context,
	}
}

// Modify implements the C5s interface.
// Corresponds to public byte[] a(byte[] var1)
func (el6 *ContextualPrefixPayloadTransformer) Modify(payload []byte) []byte {
	if el6.transformContext == nil {
		// Handle nil d2 instance, perhaps return payloadInput unmodified or an error
		return payload
	}
	// byte[] var2 = Arrays.copyOf(var1, var1.length);
	// For strictness with Arrays.copyOf, we create a copy:
	inputPayloadCopy := make([]byte, len(payload))
	copy(inputPayloadCopy, payload)

	contextPrefixAndMainData := el6.transformContext.GetPrefixedPrimaryData()
	return utils.CombineByteSlices(contextPrefixAndMainData, inputPayloadCopy)
}
