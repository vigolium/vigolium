package csv_formula_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csv-formula-injection"
	ModuleName  = "CSV / Formula Injection"
	ModuleShort = "Detects unescaped formula cells in CSV and XLSX export responses"
)

var (
	ModuleDesc = `**What it means:** A CSV or XLSX export contains cells a spreadsheet application evaluates as formulas: values starting with = + - @ tab or carriage return holding a function call, a DDE command or a scanner canary, with no neutralising leading apostrophe.

**How it's exploited:** An attacker stores a value such as =HYPERLINK(...) or a DDE command in a field that lands in an export. When a victim opens the file, the formula leaks data or launches commands.

**Fix:** Prefix cells starting with = + - @ tab or carriage return with an apostrophe, and quote every field.`

	ModuleConfirmation = "Confirmed when a CSV cell starting with = + - @ tab or carriage return contains a scan canary, a function call or a DDE command, or an XLSX formula cell contains a scan canary, a DDE command or an external-data function"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"injection", "csv-injection", "light"}
)
