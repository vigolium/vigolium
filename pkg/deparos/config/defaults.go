package config

import "time"

// Default values matching Burp Suite Content Discovery exactly.
// Extracted from did.java lines 10-37.

var (
	// Default custom extensions (did.java line 27).
	DefaultCustomExtensions = []string{
		"php",
		"asp",
		"aspx",
		"jsp",
		"jspa",
		"do",
	}

	// AllowedObservedExtensions - whitelist of extensions that can be added to observedExtensions.
	// Only extensions matching this list (case-insensitive) will be tracked for dynamic task generation.
	AllowedObservedExtensions = map[string]struct{}{
		"a": {}, "asp": {}, "aspx": {}, "backup": {}, "bak": {}, "c": {}, "cfg": {},
		"cfm": {}, "cfml": {}, "class": {}, "com": {}, "conf": {}, "cpp": {}, "dat": {},
		"data": {}, "db": {}, "dbc": {}, "dbf": {}, "debug": {}, "dev": {}, "dhtml": {},
		"dll": {}, "doc": {}, "docx": {}, "dot": {}, "exe": {},
		// "gif": {}, "jpg": {},
		"gz":  {},
		"htm": {}, "html": {}, "htr": {}, "htw": {}, "htx": {}, "ida": {}, "idc": {},
		"idq": {}, "inc": {}, "ini": {}, "jar": {}, "java": {}, "jhtml": {},
		"js": {}, "jsp": {}, "log": {}, "lst": {}, "net": {}, "o": {}, "old": {},
		// Compound JavaScript extensions (for bundled files like app.min.js)
		"min.js": {}, "chunk.js": {}, "bundle.js": {}, "esm.js": {}, "cjs.js": {}, "mjs.js": {},
		"pdf": {}, "php": {}, "php3": {}, "php4": {}, "php5": {}, "phtm": {}, "phtml": {},
		"pl": {}, "printer": {}, "prn": {}, "py": {}, "rb": {}, "reg": {}, "rtf": {},
		"save": {}, "sgml": {}, "sh": {}, "shtm": {}, "shtml": {}, "source": {}, "src": {},
		"stm": {}, "sys": {}, "tar": {}, "tar.gz": {}, "temp": {}, "test": {}, "text": {},
		"tgz": {}, "tmp": {}, "tst": {}, "txt": {}, "xls": {}, "xlsx": {}, "xml": {},
		"zip": {}, "~": {}, "rar": {}, "7z": {},
	}

	// Default variant extensions (did.java lines 100-137).
	// "Interesting extensions" for extension mutation/derivation tasks.
	// These are tested when a file is discovered (e.g., admin.php → admin.bak)
	DefaultVariantExtensions = []string{
		// Burp's exact list from did.java:100-137
		"~1", "$$$", "1", "bac", "backup", "bak", "conf", "cs", "csproj",
		"gz", "inc", "ini", "java", "log", "old", "sav", "tar", "tmp", "zip",
		"~bk", "0", "BAC", "BACKUP", "BAK", "OLD", "INC", "lst", "orig",
		"ORIG", "save", "temp", "TMP", "-OLD", "-old", "vbproj", "vb",
	}
)

// NewDefaultConfig returns a configuration with Burp Suite's default values.
func NewDefaultConfig() *Config {
	return &Config{
		Target: TargetConfig{
			StartURL: "",
			Mode:     ModeFilesAndDirs,
			Recursion: RecursionConfig{
				Enabled:  true, // did.java line 14
				MaxDepth: 16,   // did.java line 15
			},
			ScopeMode: "subdomain", // Default: same main domain (eTLD+1)
		},
		Filenames: FilenameConfig{
			Wordlists:            WordlistConfig{}, // All paths empty = disabled
			UseObservedNames:     true,             // Spider link extraction
			UseObservedFiles:     true,             // Test full observed filenames
			EnableNumericFuzzing: true,             // Numeric variant generation
		},
		Extensions: ExtensionConfig{
			TestCustom:      true,                     // did.java line 24
			CustomList:      DefaultCustomExtensions,  // did.java line 27
			TestObserved:    true,                     // did.java line 25
			TestVariants:    true,                     // did.java line 26
			VariantList:     DefaultVariantExtensions, // did.java line 31
			TestNoExtension: true,                     // did.java line 28
		},
		Engine: EngineConfig{
			CaseSensitivity:  CaseAutoDetect,   // ang.java default (auto-detect)
			DiscoveryThreads: 40,               // did.java line 33
			Timeout:          10 * time.Second, // HTTP per-request timeout
			ObservedMaxItems: 50000,            // Max items per observed provider
		},
		Modules: DefaultModuleConfig(),
	}
}
