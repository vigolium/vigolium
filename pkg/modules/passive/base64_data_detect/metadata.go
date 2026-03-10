package base64_data_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "base64-data-detect"
	ModuleName  = "Base64 Data Detect"
	ModuleShort = "Identifies interesting base64 encoded data like JSON, PHP Object in requests/responses"
)

var (
	ModuleDesc = `## Description
Passively detects interesting base64 encoded data in HTTP requests and responses.
Matches known prefixes for JSON (eyJ), PHP serialized objects (YTo, Tzo),
XML/PHP (PD8/PD9), HTTPS/HTTP URLs (aHR0cHM6L, aHR0cDo), and Java serialized
objects (rO0).

## Notes
- Scans both request and response content
- Low noise: only flags known interesting base64 prefixes
- Manual review is recommended to assess the encoded data

## References
- https://portswigger.net/kb/issues/00700200_base64-encoded-data-in-parameter
- https://cheatsheetseries.owasp.org/index.html
- https://github.com/tomnomnom/gf/blob/master/examples/base64.json`

	ModuleConfirmation = "Confirmed when request or response contains base64-encoded data matching known interesting prefixes (JSON, PHP objects, URLs, Java objects)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"info-disclosure", "deserialization", "light"}
)
