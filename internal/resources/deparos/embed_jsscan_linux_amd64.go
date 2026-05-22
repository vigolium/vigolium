//go:build linux && amd64 && !jsscan_stub

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-linux-amd64
var JSScanBinary []byte

const JSScanBinaryName = "jsscan"
