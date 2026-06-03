//go:build darwin && amd64 && !jsscan_stub

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-darwin-amd64
var JSScanBinary []byte

const JSScanBinaryName = "jsscan"
