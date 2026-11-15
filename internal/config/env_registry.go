package config

import (
	"os"
	"sort"
	"strings"
)

// EnvVar is one VIGOLIUM_* environment variable the binary reads.
type EnvVar struct {
	Name string
	// Description says what it does, in one line.
	Description string
	// OverridesKey is the settings key the variable replaces when set, so
	// TraceSources can name it as the source ("" = not a settings key).
	OverridesKey string
	// Sensitive values are redacted when listed.
	Sensitive bool
	// Prefix marks a name that is a prefix: every variable starting with it
	// is read.
	Prefix bool
	// Template marks a variable the binary reads only through a ${NAME}
	// placeholder in the generated config file.
	Template bool
}

// EnvRegistry lists every VIGOLIUM_* variable the binary reads. A ratchet
// test greps the source for VIGOLIUM_ literals and fails when one is missing
// here, so `vigolium config env` stays complete.
var EnvRegistry = []EnvVar{
	{Name: "VIGOLIUM_AGENT", Description: "Marks the caller as a coding agent (suppresses the update notice, like CLAUDECODE)"},
	{Name: "VIGOLIUM_API_KEY", Description: "API key for `server` auth and for `ingest -s` to a remote server", Sensitive: true},
	{Name: "VIGOLIUM_AUDIT_", Description: "Variables with this prefix are passed through to the audit driver", Prefix: true},
	{Name: "VIGOLIUM_AUDIT_BASE_URL", Description: "Download base URL for the vigolium-audit helper (audit_external builds)"},
	{Name: "VIGOLIUM_AUDIT_BINARY", Description: "Path of a vigolium-audit helper to use instead of the embedded one"},
	{Name: "VIGOLIUM_AUDIT_CACHE_DIR", Description: "Directory the vigolium-audit helper is extracted to"},
	{Name: "VIGOLIUM_AUTO_UPDATE", Description: "Enable automatic self-update on start"},
	{Name: "VIGOLIUM_AUTO_UPDATE_REEXECED", Description: "Internal: set on the process re-executed after a self-update"},
	{Name: "VIGOLIUM_BIN", Description: "Path of this binary, exported to agent child processes"},
	{Name: "VIGOLIUM_BROWSER_HEADED", Description: "Run the spidering browser with a visible window"},
	{Name: "VIGOLIUM_BURP_BRIDGE_URL", Description: "Default Burp/Caido bridge URL (--burp-bridge-url)"},
	{Name: "VIGOLIUM_CHROME_NO_SANDBOX", Description: "Launch the PDF renderer's Chrome with --no-sandbox"},
	{Name: "VIGOLIUM_CONFIG", Description: "Config file path, exported to agent child processes (--config)"},
	{Name: "VIGOLIUM_DB", Description: "Database file, project scoping kept (--db)", OverridesKey: "database.sqlite.path"},
	{Name: "VIGOLIUM_DB_PATH", Description: "Database file pin; project scoping off for reads", OverridesKey: "database.sqlite.path"},
	{Name: "VIGOLIUM_DB_PASSWORD", Description: "PostgreSQL password (config template placeholder)", Sensitive: true, Template: true},
	{Name: "VIGOLIUM_DEFAULT_UA", Description: "User-Agent for every request; wins over scanning_strategy.http.user_agent"},
	{Name: "VIGOLIUM_DISABLE_UPDATE_CHECK", Description: "Skip the update check"},
	{Name: "VIGOLIUM_HOME", Description: "Directory for the replay cookie jar (default ~/.vigolium)"},
	{Name: "VIGOLIUM_JSON_LEGACY_KEYS", Description: "Render pre-envelope legacy keys in -j output (--json-legacy-keys)"},
	{Name: "VIGOLIUM_JSON_PRETTY", Description: "Indent -j output"},
	{Name: "VIGOLIUM_OAST_DOMAIN", Description: "Interactsh server (config template placeholder for oast.server_url)", Template: true},
	{Name: "VIGOLIUM_OAST_TOKEN", Description: "Interactsh token (config template placeholder; `kit oast new` fallback)", Sensitive: true},
	{Name: "VIGOLIUM_OLIUM_DEBUG", Description: "Log the agent runtime's provider traffic"},
	{Name: "VIGOLIUM_PACKAGE_MANAGER", Description: "How this binary was installed (brew, npm, …), for update instructions"},
	{Name: "VIGOLIUM_PDF_TIMEOUT", Description: "Timeout for PDF report rendering"},
	{Name: "VIGOLIUM_PIOLIUM_USERHOME", Description: "Home directory the piolium driver runs under"},
	{Name: "VIGOLIUM_PROJECT_NAME", Description: "Project by name (--project-name)"},
	{Name: "VIGOLIUM_PROJECT_READONLY", Description: "Set to true to refuse project create/delete/config writes from the CLI"},
	{Name: "VIGOLIUM_PROJECT_UUID", Description: "Project by UUID, name or prefix (--project-uuid)"},
	{Name: "VIGOLIUM_PROXY", Description: "Proxy for every request (--proxy)"},
	{Name: "VIGOLIUM_REPORT_SHARED_URL", Description: "URL for the HTML report's \"Raw Report URL\" button (--report-url)"},
	{Name: "VIGOLIUM_SERVER_HOST", Description: "Address `server` binds (--host)"},
	{Name: "VIGOLIUM_SKILLS_DIR", Description: "Extra directory of agent skills"},
	{Name: "VIGOLIUM_SPIDER_HOST_PARALLELISM", Description: "Hosts the targeted re-spider crawls in parallel"},
	{Name: "VIGOLIUM_SPIDER_NO_SESSION_REUSE", Description: "Start each re-spider host with a fresh browser session"},
	{Name: "VIGOLIUM_SQL_TRACE", Description: "Log every SQL statement"},
	{Name: "VIGOLIUM_STORAGE_ACCESS_KEY", Description: "Cloud storage access key (config template placeholder)", Sensitive: true, Template: true},
	{Name: "VIGOLIUM_STORAGE_BUCKET_NAME", Description: "Cloud storage bucket (config template placeholder)", Template: true},
	{Name: "VIGOLIUM_STORAGE_ENABLED", Description: "Turn cloud storage on or off", OverridesKey: "storage.enabled"},
	{Name: "VIGOLIUM_STORAGE_SECRET_KEY", Description: "Cloud storage secret key (config template placeholder)", Sensitive: true, Template: true},
	{Name: "VIGOLIUM_TOTP_SECRET", Description: "TOTP seed for `auth totp` / session login", Sensitive: true},
	{Name: "VIGOLIUM_UPDATE_BASE_URL", Description: "Base URL self-update downloads from"},
	{Name: "VIGOLIUM_WORDLIST_DIR", Description: "Directory of discovery wordlists"},
}

// EnvSetting is one EnvRegistry variable with its current state.
type EnvSetting struct {
	EnvVar
	Set   bool
	Value string
}

// EnvSettings returns every registry variable (and, for a prefix entry, each
// set variable under it) with whether it is set and its value, sorted by
// name. Sensitive values are returned as-is; redaction is the caller's.
func EnvSettings() []EnvSetting {
	var out []EnvSetting
	for _, v := range EnvRegistry {
		if v.Prefix {
			for _, kv := range os.Environ() {
				name, val, _ := strings.Cut(kv, "=")
				if strings.HasPrefix(name, v.Name) && !registered(name) {
					e := v
					e.Name, e.Prefix = name, false
					out = append(out, EnvSetting{EnvVar: e, Set: true, Value: val})
				}
			}
			continue
		}
		val, ok := os.LookupEnv(v.Name)
		out = append(out, EnvSetting{EnvVar: v, Set: ok, Value: val})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func registered(name string) bool {
	for _, v := range EnvRegistry {
		if !v.Prefix && v.Name == name {
			return true
		}
	}
	return false
}
