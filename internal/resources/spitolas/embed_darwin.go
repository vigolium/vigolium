//go:build darwin && embed_chromium

package spitolas

import _ "embed"

// chromiumVersion is the embedded Chromium version for macOS ARM.
// Downloaded from https://download-chromium.appspot.com/dl/Mac_Arm?type=snapshots
const chromiumVersion = "snapshot-arm"

// chromiumBinaryPath is the path to the executable within the extracted zip
const chromiumBinaryPath = "chrome-mac/Chromium.app/Contents/MacOS/Chromium"

// chromiumZip contains the embedded Chromium browser for macOS (ARM)
//
//go:embed chromium/chromium-mac-arm.zip
var chromiumZip []byte
