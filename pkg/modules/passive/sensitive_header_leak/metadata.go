package sensitive_header_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-header-leak"
	ModuleName  = "Sensitive Data in Response Headers"
	ModuleShort = "Detects high-entropy / key-shaped values disclosed in custom response headers"
)

var (
	ModuleDesc = `## Description
Some applications stuff sensitive material - encryption keys, IVs, API
tokens, signed-URL parameters - into custom response headers. Header-based
disclosure is easy to miss in body-focused secret scanning. The nginx-ui
GHSA-g9w5-qffc-6762 vulnerability is the canonical example: the ` + "`/api/backup`" + `
endpoint disclosed the AES-256 ` + "`key:iv`" + ` pair in an ` + "`X-Backup-Security`" + `
response header alongside the encrypted backup body.

This module flags response headers whose names or values match well-known
sensitive patterns:

- known sensitive header name list (` + "`X-Backup-Security`" + `, ` + "`X-AWS-*-Token`" + `,
  ` + "`X-Auth-Token`" + `, ` + "`Set-Cookie`" + ` containing ` + "`secret=`" + ` etc.)
- ` + "`base64:base64`" + ` shaped values (typical of ` + "`key:iv`" + ` disclosure)
- AKIA / AIza / ghp_ / xoxb_ etc. token prefixes
- high Shannon entropy in suspect header names (potential keys / signatures)

## References
- https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762
- CWE-200 Information Exposure`

	ModuleConfirmation = "Confirmed when a non-standard response header carries a value matching known sensitive token formats or a high-entropy key-shaped string"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "secrets", "headers", "light"}
)
