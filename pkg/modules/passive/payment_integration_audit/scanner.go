package payment_integration_audit

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// gatewaySignatures are host/SDK strings that mark a payment-gateway integration.
// Detection is gated on one of these so the amount/status heuristics below only
// fire in a genuine payment context (keeping this out of the false-positive zone
// where a bare "amount" field on a non-payment page would trip it).
var gatewaySignatures = map[string]string{
	"js.stripe.com":         "Stripe",
	"checkout.stripe.com":   "Stripe",
	"api.stripe.com":        "Stripe",
	"paypal.com/sdk":        "PayPal",
	"paypalobjects.com":     "PayPal",
	"www.paypal.com":        "PayPal",
	"checkout.razorpay.com": "Razorpay",
	"api.razorpay.com":      "Razorpay",
	"braintreegateway.com":  "Braintree",
	"braintree-web":         "Braintree",
	"checkout.adyen.com":    "Adyen",
	"live.adyen.com":        "Adyen",
	"js.checkout.com":       "Checkout.com",
	"squareup.com":          "Square",
	"secure.payu":           "PayU",
	"checkout.paddle.com":   "Paddle",
}

// amountFieldRe matches a form/hidden input carrying a client-controlled money
// value — the price-tampering surface.
var amountFieldRe = regexp.MustCompile(`(?is)<input\b[^>]*\bname\s*=\s*["'](amount|price|total|subtotal|cost|currency|unit_price|item_price|order_total|grand_total)["'][^>]*>`)

// statusParamNames are query/body parameters that carry a payment outcome an app
// might wrongly trust from the return URL.
var statusParamNames = map[string]struct{}{
	"status": {}, "payment_status": {}, "paymentstatus": {}, "paid": {},
	"success": {}, "transaction_status": {}, "result": {}, "payment_result": {},
}

// Module implements the Payment Integration Risk Surface passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new module instance.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("payment_integration_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest flags payment risk surface. It requires a payment-gateway
// signature AND at least one risk indicator, so an ordinary page is never flagged.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}
	body := ctx.Response().BodyToString()

	gateway := detectGateway(body)
	if gateway == "" {
		return nil, nil // no payment context — fail closed
	}

	var indicators []string
	if amountFieldRe.MatchString(body) {
		indicators = append(indicators, "client-controlled amount/currency form field (price-tampering surface)")
	}
	if p := paymentStatusParam(ctx); p != "" {
		indicators = append(indicators, "payment status trusted from URL parameter '"+p+"' (verify via gateway/webhook, not the return URL)")
	}
	if len(indicators) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := urlx.Host + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	extracted := append([]string{"gateway=" + gateway}, indicators...)
	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Payment Integration Risk Surface (" + gateway + ")",
			Description: "This " + gateway + " checkout page exposes " + strings.Join(indicators, "; ") + ". If the server trusts these client-side values instead of computing the amount server-side and verifying payment status via the gateway API / signed webhook, an attacker can tamper with the price or forge a successful payment. This is a recon-level pointer to verify server-side validation, not a confirmed flaw.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// detectGateway returns the payment gateway name if a signature is present in body.
func detectGateway(body string) string {
	lower := strings.ToLower(body)
	for sig, name := range gatewaySignatures {
		if strings.Contains(lower, sig) {
			return name
		}
	}
	return ""
}

// paymentStatusParam returns the name of a payment-status query/body parameter
// present on the request, or "".
func paymentStatusParam(ctx *httpmsg.HttpRequestResponse) string {
	params, err := ctx.Request().Parameters()
	if err != nil {
		return ""
	}
	for _, p := range params {
		if _, ok := statusParamNames[strings.ToLower(p.Name())]; ok {
			return p.Name()
		}
	}
	return ""
}
