//go:build darwin && amd64 && !jstangle_stub

package deparos

import (
	_ "embed"
)

//go:embed jstangle/jstangle-darwin-amd64
var JSTangleBinary []byte

const JSTangleBinaryName = "jstangle"
