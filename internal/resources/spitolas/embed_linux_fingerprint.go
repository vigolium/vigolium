//go:build linux && amd64 && embed_chromium

package spitolas

import _ "embed"

// fingerprintVersion is the embedded Fingerprint-Chromium version for Linux x86_64
const fingerprintVersion = "142.0.7444.175"

// fingerprintBinaryPath is the path to the executable within the extracted tar.xz
const fingerprintBinaryPath = "ungoogled-chromium-142.0.7444.175-1-x86_64_linux/chrome"

// fingerprintArchive contains the embedded Fingerprint-Chromium browser for Linux (x86_64)
//
//go:embed chromium/fingerprint-chromium-142.0.7444.175-1-x86_64_linux.tar.xz
var fingerprintArchive []byte
