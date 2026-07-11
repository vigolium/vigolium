//go:build linux && arm64 && !jstangle_stub

package deparos

import (
	_ "embed"
)

//go:embed jstangle/jstangle-linux-arm64
var JSTangleBinary []byte

const JSTangleBinaryName = "jstangle"
