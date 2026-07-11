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

	// DefaultCandidateExtensions lists every server-side extension the engine is
	// willing to fuzz once it has CONFIRMED the application actually serves that
	// extension as a valid route (see ExtensionConfig.ConfirmRequired). It is a
	// superset of DefaultCustomExtensions covering the major server stacks:
	// PHP, classic/modern ASP(.NET), Java/JSP/Struts, ColdFusion and CGI.
	DefaultCandidateExtensions = []string{
		"php", "php3", "php4", "php5", "phtml",
		"asp", "aspx", "ashx", "asmx",
		"jsp", "jspx", "jspa", "do", "action",
		"cfm", "cfml",
		"cgi",
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
		// Server-side route extensions confirmed/fuzzed by the extension-confirm
		// pipeline (Java/Struts, ASP.NET handlers, CGI). cfm/cfml/asp/aspx/jsp
		// and the php* family are already covered above.
		"action": {}, "do": {}, "jspx": {}, "ashx": {}, "asmx": {}, "cgi": {},
	}

	// DefaultJSBundleNames is the curated list of common base names (no
	// extension) the SPA-gated JS-bundle sweep probes on monolith /
	// server-rendered apps (see ExtensionConfig.JSBundleSweep). Each name is
	// tried as both .js (bundles) and .json (sibling config/data). These are
	// hand-written, never-content-hashed names that are frequently NOT linked
	// from the HTML — confirmed hits are fed to the JS-fetch pipeline for
	// endpoint/secret extraction. Biased toward names that, when present, expose
	// interesting routes/config (admin, config, api, auth, settings, …).
	DefaultJSBundleNames = []string{
		"main", "app", "index", "script", "scripts", "bundle", "common",
		"core", "site", "global", "vendor", "base", "default", "custom",
		"config", "settings", "api", "auth", "login", "user", "users",
		"admin", "dashboard", "upload", "internal", "debug", "dev",
		"functions", "utils", "helpers",
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
			TestCustom:           true,
			CustomList:           DefaultCustomExtensions,
			TestObserved:         true,
			TestBackupExtensions: true,
			BackupExtensions:     DefaultBackupExtensions,
			TestNoExtension:      true,
			// Confirmation-gated extension fuzzing (default on): server-side
			// extensions are only swept with the wordlist once the app is proven
			// to serve them as a valid route. Confirmation comes from what the
			// site actually reveals — observed URLs (genuine references in
			// content / spidered pages) and tech fingerprinting. The active
			// soft-404 differential probe (ConfirmViaProbe) is OFF by default: it
			// guesses common filenames (index.php, default.php, login.php), so on
			// a catch-all / SPA-shell host it confirms extensions the server does
			// not actually run. Opt back in via discovery.extensions.confirm_via_probe.
			ConfirmRequired:       true,
			ConfirmViaObserved:    true,
			ConfirmViaFingerprint: true,
			ConfirmViaProbe:       false,
			Candidates:            DefaultCandidateExtensions,
			// SPA-gated JS-bundle name sweep (default on): probe common bundle
			// names on monolith apps and feed hits to jstangle. No-op on SPAs.
			JSBundleSweep: true,
		},
		Engine: EngineConfig{
			CaseSensitivity:  CaseAutoDetect,
			DiscoveryThreads: 40,
			Timeout:          10 * time.Second, // HTTP per-request timeout
			ObservedMaxItems: 4000,             // Max items per observed provider
			PrefixBreaker: PrefixBreakerConfig{
				Enabled:        true,
				MinSamples:     12,
				TripRatio:      0.9,
				PrefixSegments: 1,
				LengthBucket:   256,
			},
		},
		JSTangle: JSTangleConfig{
			Enabled: true, ReplayMode: "exact", ReplaySafety: "read-only", SourceMaps: true, AssetGraph: true,
			WorkerCount: 0, MemoryBudgetMB: 768, CacheMB: 128,
			WorkerMaxJobs: 100, WorkerMaxRSSMB: 1024, JobTimeout: 60 * time.Second,
			NormalInputMB: 1, MaxASTInputMB: 4, HardInputMB: 10, MaxRequestsPerFile: 500,
			MaxASTNodes:   500_000,
			MaxAssetDepth: 4, MaxAssetsPerParent: 64, MaxAssetsPerHost: 512, MaxAssetsTotal: 2048,
		},
		Modules: DefaultModuleConfig(),
	}
}
