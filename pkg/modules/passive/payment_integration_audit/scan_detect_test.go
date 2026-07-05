package payment_integration_audit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func ctx(target, respBody string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: shop.example.com\r\n\r\n", target)
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("shop.example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + respBody
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

func TestFlagsAmountFieldOnGateway(t *testing.T) {
	t.Parallel()
	body := `<html><head><script src="https://js.stripe.com/v3"></script></head>` +
		`<body><form><input type="hidden" name="amount" value="1000"></form></body></html>`
	res, err := New().ScanPerRequest(ctx("/checkout", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, res[0].Info.Name, "Stripe")
}

func TestFlagsStatusParamOnGateway(t *testing.T) {
	t.Parallel()
	body := `<html><body>Thanks! <script src="https://www.paypal.com/sdk/js"></script></body></html>`
	res, err := New().ScanPerRequest(ctx("/return?status=success", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Contains(t, res[0].Info.Name, "PayPal")
}

func TestNoGatewayNoFinding(t *testing.T) {
	t.Parallel()
	// An "amount" field but no payment gateway → not a payment context.
	body := `<html><body><form><input name="amount" value="5"></form></body></html>`
	res, err := New().ScanPerRequest(ctx("/donate?status=ok", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no payment gateway → no finding")
}

func TestGatewayNoIndicatorNoFinding(t *testing.T) {
	t.Parallel()
	body := `<html><head><script src="https://js.stripe.com/v3"></script></head><body>ok</body></html>`
	res, err := New().ScanPerRequest(ctx("/pricing", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "gateway present but no amount field / status param → no finding")
}
