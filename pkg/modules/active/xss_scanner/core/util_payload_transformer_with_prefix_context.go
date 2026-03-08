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
	// In Go, if we want to ensure the original payloadInput isn't modified by NetPortswiggerNkCombine
	// (if NetPortswiggerNkCombine modifies its arguments, which it shouldn't for a combine function),
	// we make a copy. Otherwise, direct use is fine.
	// Assuming NetPortswiggerNkCombine doesn't modify its input slices.
	// For strictness with Arrays.copyOf, we create a copy:
	inputPayloadCopy := make([]byte, len(payload))
	copy(inputPayloadCopy, payload)

	// return net.portswigger.nk.a(this.a.b(), var2);
	contextPrefixAndMainData := el6.transformContext.GetPrefixedPrimaryData()
	return utils.NetPortswiggerNkCombine(contextPrefixAndMainData, inputPayloadCopy)
}
