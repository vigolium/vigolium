package secret_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "secret-detect"
	ModuleName  = "Secret Detection"
	ModuleShort = "Detects leaked secrets and credentials in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively scans HTTP response bodies for leaked secrets, credentials, API keys,
and connection strings using the Kingfisher secret detection engine.

## Notes
- Scans response bodies only (no additional HTTP requests sent)
- Skips binary/media content types
- Uses lazy-initialized singleton Kingfisher scanner
- Generates one finding per detected secret

## References
- https://github.com/mongodb/kingfisher`

	ModuleConfirmation = "Confirmed when Kingfisher detects a known secret pattern in the HTTP response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
