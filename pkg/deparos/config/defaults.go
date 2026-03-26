package config

import "time"

// Default values for content discovery configuration.

var (
	// DefaultCustomExtensions lists commonly tested file extensions.
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

	// DefaultBackupExtensions lists backup/temp file extensions tested when a file is discovered
	// (e.g., admin.php -> admin.bak).
	DefaultBackupExtensions = []string{
		"~1", "$$$", "1", "bac", "backup", "bak", "conf", "cs", "csproj",
		"gz", "inc", "ini", "java", "log", "old", "sav", "tar", "tmp", "zip",
		"~bk", "0", "BAC", "BACKUP", "BAK", "OLD", "INC", "lst", "orig",
		"ORIG", "save", "temp", "TMP", "-OLD", "-old", "vbproj", "vb",
	}
)

// NewDefaultConfig returns a configuration with sensible default values.
func NewDefaultConfig() *Config {
	return &Config{
		Target: TargetConfig{
			StartURL: "",
			Mode:     ModeFilesAndDirs,
			Recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: 16,  
			},
			ScopeMode: "subdomain", // Default: same main domain (eTLD+1)
		},
		Filenames: FilenameConfig{
			Wordlists:            WordlistConfig{}, // All paths empty = disabled
			UseObservedNames:     true,             // Spider link extraction
			UseObservedPaths:     true,             // Test observed directory paths
			UseObservedFiles:     true,             // Test full observed filenames
			EnableNumericFuzzing: false,            // Opt-in: numeric variant generation
			WordlistExtraction: WordlistExtractConfig{
				Enabled:         false, // Opt-in: extract words from response bodies
				DelimExceptions: "-_",  // Common delimiters in web paths
				MaxCombine:      2,     // Max segments to combine
				MinLength:       3,     // Min token length
				MaxLength:       64,    // Max token length
			},
		},
		Extensions: ExtensionConfig{
			TestCustom:      true,                    
			CustomList:      DefaultCustomExtensions, 
			TestObserved:    true,                    
			TestBackupExtensions: true,                   
			BackupExtensions:     DefaultBackupExtensions,
			TestNoExtension: true,                    
		},
		Engine: EngineConfig{
			CaseSensitivity:  CaseAutoDetect,  
			DiscoveryThreads: 40,              
			Timeout:          10 * time.Second, // HTTP per-request timeout
			ObservedMaxItems: 4000,             // Max items per observed provider
		},
		Modules: DefaultModuleConfig(),
	}
}
