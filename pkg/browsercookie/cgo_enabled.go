//go:build cgo

package browsercookie

// CGOEnabled reports whether this binary was built with cgo.
//
// It is not a curiosity. On macOS the upstream reader has two keychain paths
// selected by exactly this tag: with cgo it calls the Keychain API in-process,
// so macOS attributes the request to the vigolium binary; without cgo it shells
// out to /usr/bin/security, so the request is that Apple-signed binary's. Which
// one a release was built with decides whose access list a standing "Always
// Allow" grant would widen, which is why every hint asks for a one-time
// "Allow" instead, and `doctor` names the path.
const CGOEnabled = true
