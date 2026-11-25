package cli

import (
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/requesttransform"
)

// --request-transform installs a declared request transform (signing, nonce,
// body encryption - pkg/requesttransform) that every request this process
// sends through the requester passes, on its final bytes, when the request's
// host and path match. The transform cannot change where a request goes; its
// keys are credential references resolved from VIGOLIUM_TRANSFORM_KEY_<NAME>
// first and then from --request-transform-keys, never from the transform file.

var (
	globalRequestTransform     string
	globalRequestTransformKeys string
)

func registerRequestTransformFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.StringVar(&globalRequestTransform, "request-transform", "",
		"Apply a declared request transform (JSON: one transform or an array) to every matching request's final bytes: hmac-header, set-header, set-query, nonce, timestamp, hash, truncate, encrypt-body. It never changes scheme, host or port")
	pf.StringVar(&globalRequestTransformKeys, "request-transform-keys", "",
		"JSON object (mode 0600) of credential name to key value for --request-transform; VIGOLIUM_TRANSFORM_KEY_<NAME> wins over it")
}

// applyRequestTransform loads and activates --request-transform, refusing
// the invocation (exit 2) when the file or any transform in it is refused.
func applyRequestTransform() error {
	if globalRequestTransform == "" {
		if globalRequestTransformKeys != "" {
			return usageErrorf("--request-transform-keys needs --request-transform")
		}
		requesttransform.Activate(nil)
		return nil
	}
	set, err := requesttransform.Load(globalRequestTransform, globalRequestTransformKeys)
	if err != nil {
		return usageErrorf("--request-transform %s: %v", globalRequestTransform, err)
	}
	requesttransform.Activate(set)
	return nil
}
