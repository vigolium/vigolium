//go:build darwin && arm64 && !jstangle_stub

package deparos

import (
	_ "embed"
)

//go:embed jstangle/jstangle-darwin-arm64
var JSTangleBinary []byte

const JSTangleBinaryName = "jstangle"
