//go:build !(linux && amd64) && !(darwin && arm64) && !(windows && amd64)

package deparos

var JSScanBinary []byte

const JSScanBinaryName = ""
