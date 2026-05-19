//go:build !linux || !amd64 || !embed_chromium

package spitolas

// fingerprintVersion is empty when Fingerprint-Chromium is not embedded.
const fingerprintVersion = ""

// fingerprintBinaryPath is empty when Fingerprint-Chromium is not embedded.
const fingerprintBinaryPath = ""

// fingerprintArchive is nil when Fingerprint-Chromium is not embedded.
var fingerprintArchive []byte = nil
