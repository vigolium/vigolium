package django_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-admin-exposure"
	ModuleName  = "Django Admin Exposure"
	ModuleShort = "Probes for exposed Django admin panel and login page"
)

var (
	ModuleDesc = `**What it means:** An isolated credential-free request reached a Django-specific administration login interface. This records security-relevant attack surface, not administrative access or an authentication flaw.

**How it's exploited:** Attackers can identify the framework and target the login with known credentials or separate authentication weaknesses. Mere login-page reachability does not prove credential weakness, brute-force viability, or authorization bypass.

**Fix:** If policy requires it, restrict the interface to trusted networks or VPN. Independently enforce strong credentials, rate limiting, and multi-factor authentication.`

	ModuleConfirmation = "Observed when credential-free requests return 200 with a Django-specific anchor plus an admin-form marker and pass catch-all controls"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
