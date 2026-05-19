//go:build windows && amd64

package deparos

import (
	_ "embed"
)

//go:embed jsscan/jsscan-windows-amd64.exe
var JSScanBinary []byte

const JSScanBinaryName = "jsscan.exe"
