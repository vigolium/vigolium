package spitolas

// BrowserDownload defines download metadata for an embedded browser archive.
type BrowserDownload struct {
	Name     string // browser name: "chromium", "ungoogled", or "fingerprint"
	Platform string // target platform: "macosarm", "linux64", "linuxarm64", "macos"
	Version  string // browser version string
	URL      string // download URL for the archive
	Archive  string // local filename under chromium/ subdirectory
}

// Downloads lists all browser archives to embed.
// Edit entries here, then run:
//
//	make deps-chrome          — download all archives
//	make deps-chrome-update   — update a single entry's version + URL
var Downloads = []BrowserDownload{
	// MacOS — latest Chromium snapshot for ARM
	{Name: "chromium", Platform: "macosarm", Version: "latest", URL: "https://download-chromium.appspot.com/dl/Mac_Arm?type=snapshots", Archive: "chromium-mac-arm.zip"},

	// Linux — Ungoogled-Chromium (https://ungoogled-software.github.io/ungoogled-chromium-binaries/)
	{Name: "ungoogled", Platform: "linux64", Version: "145.0.7632.75-1", URL: "https://github.com/ungoogled-software/ungoogled-chromium-portablelinux/releases/download/145.0.7632.75-1/ungoogled-chromium-145.0.7632.75-1-x86_64_linux.tar.xz", Archive: "ungoogled-chromium-145.0.7632.75-1-x86_64_linux.tar.xz"},
	{Name: "ungoogled", Platform: "linuxarm64", Version: "145.0.7632.75-1", URL: "https://github.com/ungoogled-software/ungoogled-chromium-portablelinux/releases/download/145.0.7632.75-1/ungoogled-chromium-145.0.7632.75-1-arm64_linux.tar.xz", Archive: "ungoogled-chromium-145.0.7632.75-1-arm64_linux.tar.xz"},

	// Fingerprint-Chromium (https://github.com/adryfish/fingerprint-chromium/releases)
	{Name: "fingerprint", Platform: "linux64", Version: "142.0.7444.175", URL: "https://github.com/adryfish/fingerprint-chromium/releases/download/142.0.7444.175/ungoogled-chromium-142.0.7444.175-1-x86_64_linux.tar.xz", Archive: "fingerprint-chromium-142.0.7444.175-1-x86_64_linux.tar.xz"},
	{Name: "fingerprint", Platform: "macos", Version: "142.0.7444.175", URL: "https://github.com/adryfish/fingerprint-chromium/releases/download/142.0.7444.175/ungoogled-chromium_142.0.7444.175-1.1_macos.dmg", Archive: "fingerprint-chromium-142.0.7444.175-1.1_macos.dmg"},
}
