//go:build windows && embed_chromium

package spitolas

// chromiumVersion is empty — no standard Chromium archive for Windows.
// Rod will auto-download a browser at runtime.
const chromiumVersion = ""

// chromiumBinaryPath is empty — no standard Chromium archive for Windows.
const chromiumBinaryPath = ""

// chromiumZip is nil — no standard Chromium archive for Windows.
var chromiumZip []byte = nil
