//go:build !cgo

package browsercookie

// CGOEnabled reports whether this binary was built with cgo. See the cgo build
// of this constant for why it matters to a keychain approval's lifetime.
const CGOEnabled = false
