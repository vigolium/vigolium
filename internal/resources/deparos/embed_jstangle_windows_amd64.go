//go:build windows && amd64 && !jstangle_stub

package deparos

import (
	_ "embed"
)

//go:embed jstangle/jstangle-windows-amd64.exe
var JSTangleBinary []byte

const JSTangleBinaryName = "jstangle.exe"
