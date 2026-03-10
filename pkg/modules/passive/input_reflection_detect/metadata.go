package input_reflection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "input-reflection-detect"
	ModuleName  = "Input Reflection Detect"
	ModuleShort = "Detects request parameter values reflected in responses"
)

var (
	ModuleDesc = `## Description
Passively detects when request parameter values are reflected verbatim in the response body.
Input reflection is a prerequisite for many injection vulnerabilities including XSS.

## Notes
- Only checks text/html responses
- Filters out short values (<4 chars), all-numeric values, and token-like values
- Reports reflected parameters as informational findings for further investigation

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting`

	ModuleConfirmation = "Indicated when a request parameter value appears verbatim in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"xss", "injection", "light"}
)
