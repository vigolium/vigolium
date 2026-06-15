package rails_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-sensitive-files"
	ModuleName  = "Rails Sensitive Files"
	ModuleShort = "Detects exposed Rails configuration files, credentials, and artifacts"
)

var (
	ModuleDesc = `**What it means:** A sensitive Ruby on Rails file is reachable over HTTP from the web root because a misconfigured server serves the application directory as static content, leaking the master key, encrypted credentials, database.yml, secret_key_base, or a full SQLite database.

**How it's exploited:** An attacker requests the file and reads it. A leaked master.key or secrets.yml decrypts credentials and forges session cookies for account takeover; database.yml yields DB credentials; Gemfile.lock pins versions to map known CVEs.

**Fix:** Block direct access to source and config directories at the proxy, never serve the Rails root statically, and rotate exposed credentials.`

	ModuleConfirmation = "Confirmed when Rails configuration files are accessible and contain expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"rails", "ruby", "file-exposure", "info-disclosure", "light"}
)
