package payment_integration_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "payment-integration-audit"
	ModuleName  = "Payment Integration Risk Surface"
	ModuleShort = "Flags client-controlled amounts / trusted payment-status params on payment-gateway pages"
)

var (
	ModuleDesc = `**What it means:** The page integrates a payment gateway and exposes a client-controlled amount/currency field, or trusts a payment status passed in a URL parameter — the surface for price tampering and forged payment confirmation.

**How it's exploited:** An attacker lowers the amount or changes the currency in the checkout request, or forges a success status in the return URL, so an order is fulfilled without valid payment if the server trusts client values.

**Fix:** Compute and verify amounts server-side, and confirm payment status via the gateway API or a signed webhook (never the return URL).`

	ModuleConfirmation = "Reported when a payment gateway is detected on the page AND either a client-controlled amount/currency field or a payment-status URL parameter is present"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"payment", "business-logic", "recon", "light"}
)
