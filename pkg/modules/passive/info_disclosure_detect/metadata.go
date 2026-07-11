package info_disclosure_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "info-disclosure-detect"
	ModuleName  = "Info Disclosure Detect"
	ModuleShort = "Detects information disclosure patterns in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A response exposes a software version, valid private address, corroborated debug marker, or directory listing. Versions and addresses are observations; debug and listing patterns require independent anchors. Stack traces use a dedicated detector.

**How it's exploited:** Attackers map internal systems, identify version-specific exploits, or use debug context to sharpen later attacks.

**Fix:** Suppress unnecessary banners, disable debug mode and directory indexing, and return generic production errors.`

	ModuleConfirmation = "Observation for version/private-address markers; candidate only when independent debug or directory-listing anchors corroborate the pattern"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
