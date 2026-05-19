//go:build linux && embed_chromium

package spitolas

// chromiumVersion is empty — no standard Chromium archive for Linux.
// Use EngineUngoogled or EngineFingerprint instead, or rod will auto-download.
const chromiumVersion = ""

// chromiumBinaryPath is empty — no standard Chromium archive for Linux.
const chromiumBinaryPath = ""

// chromiumZip is nil — no standard Chromium archive for Linux.
var chromiumZip []byte = nil
