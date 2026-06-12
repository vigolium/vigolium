package rails_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-sensitive-files"
	ModuleName  = "Rails Sensitive Files"
	ModuleShort = "Detects exposed Rails configuration files, credentials, and artifacts"
)

var (
	ModuleDesc = `**What it means:** A sensitive Ruby on Rails application file is reachable over HTTP from the web root, usually because a misconfigured web server or container serves the application directory as static content. Depending on the file, this leaks the master key, encrypted credentials, database configuration, secret_key_base, dependency manifests, server config, application logs, or even a full SQLite database.

**How it's exploited:** An attacker requests the file directly and reads its contents. A leaked master.key or secrets.yml lets them decrypt credentials and forge signed/encrypted session cookies for account takeover; database.yml or an exposed SQLite database yields DB credentials and stored data; logs can expose PII, tokens, and internal routes; and Gemfile.lock pins exact dependency versions an attacker maps to known CVEs.

**Fix:** Block direct access to the application source and config directories at the web server or reverse proxy, never serve the Rails root as static files, and rotate any keys or credentials that were exposed.`

	ModuleConfirmation = "Confirmed when Rails configuration files are accessible and contain expected content markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "file-exposure", "info-disclosure", "light"}
)
