package agent

import (
	"path/filepath"
	"strings"
)

// skipDirs is the consolidated set of directory names to skip during source walks.
// These are universally low-value for security analysis: dependency caches,
// build output, VCS internals, IDE config, CI/CD, and test fixtures.
var skipDirs = map[string]bool{
	// Dependency directories
	"node_modules": true, "vendor": true, "bower_components": true,
	".bundle": true, "Pods": true, ".dart_tool": true, ".pub-cache": true,
	".cargo": true, ".gradle": true, ".mvn": true,

	// Build/output directories
	"dist": true, "build": true, "out": true,
	".next": true, ".nuxt": true, ".output": true,
	"target": true, // Java (Maven/Gradle), Rust (Cargo)

	// Python environments and caches
	"__pycache__": true, ".venv": true, "venv": true,
	".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	".eggs": true, "*.egg-info": true,

	// Coverage/test output
	"coverage": true, ".nyc_output": true, ".cache": true,

	// VCS and IDE
	".git": true, ".svn": true, ".hg": true,
	".idea": true, ".vscode": true, ".settings": true, ".eclipse": true,

	// CI/CD and infrastructure
	".github": true, ".gitlab": true, ".circleci": true,
	".terraform": true, ".pulumi": true,

	// Test fixtures (not test source files — those can reveal auth patterns)
	"testdata": true, "__snapshots__": true, "fixtures": true,

	// Documentation (usually non-code)
	"docs": true, "doc": true,

	// Misc
	".sass-cache": true, ".parcel-cache": true, ".turbo": true,
	"tmp": true, "temp": true, "logs": true,
}

// skipFileExts are file extensions to exclude from directory tree listings.
// These are media, binary, font, and lock files that have no security-analysis value.
var skipFileExts = map[string]bool{
	// Images
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".svg": true, ".ico": true, ".webp": true, ".bmp": true, ".tiff": true,
	// Audio/video
	".mp4": true, ".mp3": true, ".wav": true, ".webm": true,
	".avi": true, ".mov": true, ".flv": true, ".ogg": true,
	// Fonts
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	// Documents (non-code)
	".pdf": true,
	// Compiled/binary
	".pyc": true, ".pyo": true, ".class": true,
	".o": true, ".so": true, ".dylib": true, ".dll": true, ".exe": true,
	".a": true, ".lib": true,
	// Archives
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
	".jar": true, ".war": true, ".ear": true,
	// Lock/checksum files
	".lock": true, ".sum": true,
	// Source maps
	".map": true,
}

// skipFileSuffixes are multi-part suffixes (beyond simple extension) to exclude.
// Checked via strings.HasSuffix on the filename.
var skipFileSuffixes = []string{
	".min.js", ".min.css",     // Minified bundles
	".pb.go", "_generated.go", // Generated Go code
	".generated.ts", ".generated.js", // Generated TypeScript/JavaScript
	".d.ts", // TypeScript declaration files (useful for API surface but noisy)
}

// shouldSkipDir returns true if the directory name should be skipped during source walks.
func shouldSkipDir(name string) bool {
	return skipDirs[name]
}

// shouldSkipFile returns true if the file should be excluded from tree listings
// and source file collection. Checks extension and multi-part suffixes.
func shouldSkipFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if skipFileExts[ext] {
		return true
	}
	lower := strings.ToLower(name)
	for _, suffix := range skipFileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
