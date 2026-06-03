//go:build linux && arm64 && !jsscan_stub

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-linux-arm64
var JSScanBinary []byte

const JSScanBinaryName = "jsscan"
