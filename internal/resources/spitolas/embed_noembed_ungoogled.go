//go:build linux && !embed_chromium

package spitolas

// ungoogledVersion is empty when Ungoogled-Chromium is not embedded in the build.
const ungoogledVersion = ""

// ungoogledBinaryPath is empty when Ungoogled-Chromium is not embedded.
const ungoogledBinaryPath = ""

// ungoogledChromiumTarXz is nil when Ungoogled-Chromium is not embedded.
var ungoogledChromiumTarXz []byte = nil
