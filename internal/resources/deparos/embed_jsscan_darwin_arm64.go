//go:build darwin && arm64

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-darwin-arm64
var JSScanBinary []byte

const JSScanBinaryName = "jsscan"
