//go:build darwin && arm64 && !jsscan_stub

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-darwin-arm64
var JSScanBinary []byte

const JSScanBinaryName = "jsscan"
