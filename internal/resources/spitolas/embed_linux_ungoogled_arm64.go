//go:build linux && arm64 && embed_chromium

package spitolas

import _ "embed"

// ungoogledVersion is the embedded Ungoogled-Chromium version for Linux arm64
const ungoogledVersion = "145.0.7632.75-1"

// ungoogledBinaryPath is the path to the executable within the extracted tar.xz
const ungoogledBinaryPath = "ungoogled-chromium-145.0.7632.75-1-arm64_linux/chrome"

// ungoogledChromiumTarXz contains the embedded Ungoogled-Chromium browser for Linux (arm64)
//
//go:embed chromium/ungoogled-chromium-145.0.7632.75-1-arm64_linux.tar.xz
var ungoogledChromiumTarXz []byte
