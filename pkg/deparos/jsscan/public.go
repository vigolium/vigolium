package jsscan

import deparospresets "github.com/vigolium/vigolium/internal/resources/deparos"

var embeddedBinary = deparospresets.JSScanBinary
var binaryName = deparospresets.JSScanBinaryName

// isEmbeddedBinaryValid returns true only when the embedded binary is a real
// executable. It rejects both empty slices (unsupported platform) and tiny
// payloads (< 1024 bytes) which are Git LFS pointer files rather than real
// binaries.
func isEmbeddedBinaryValid() bool {
	return len(embeddedBinary) > 1024
}
