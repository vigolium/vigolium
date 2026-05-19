package rails_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-sensitive-files"
	ModuleName  = "Rails Sensitive Files"
	ModuleShort = "Detects exposed Rails configuration files, credentials, and artifacts"
)

var (
	ModuleDesc = `## Description
Probes for Rails-specific sensitive files that may be exposed due to misconfigured web
servers or containerized deployments serving the application root as static files.
Checks for master keys, encrypted credentials, database configs, Gemfiles, logs,
SQLite databases, and server configurations.

## Notes
- Sends GET/HEAD requests to known Rails configuration file paths
- Uses content markers to confirm file type and reduce false positives
- Fingerprints 404 responses to avoid custom error page false positives
- Each finding has severity based on the sensitivity of the exposed file

## References
- https://guides.rubyonrails.org/security.html
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when Rails configuration files are accessible and contain expected content markers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "file-exposure", "info-disclosure", "light"}
)
