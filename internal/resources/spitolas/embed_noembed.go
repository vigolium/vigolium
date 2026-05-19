//go:build !embed_chromium

package spitolas

// chromiumVersion is empty when Chromium is not embedded in the build.
// Use 'go build -tags=embed_chromium' to embed Chromium (requires 'make deps-chrome' first).
const chromiumVersion = ""

// chromiumBinaryPath is empty when Chromium is not embedded.
const chromiumBinaryPath = ""

// chromiumZip is nil when Chromium is not embedded.
var chromiumZip []byte = nil
