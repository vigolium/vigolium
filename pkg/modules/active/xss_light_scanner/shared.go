package xss_light_scanner

import (
	"strings"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// performPassiveCheck checks if the base value reflects in the response body.
// Returns true if we should proceed with scanning (either no base value or it reflects).
func performPassiveCheck(baseBody string, ip httpmsg.InsertionPoint) bool {
	baseValue := ip.BaseValue()
	if baseValue == "" {
		return true
	}
	if baseBody == "" {
		return true
	}
	return strings.Contains(baseBody, baseValue)
}

// sendRawPayload sends a request with the literal payload bytes and returns the
// response chain. Lets variants (e.g. the encoded scanner) inject an
// already-transformed payload without reconstructing the send/validate logic.
func sendRawPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	payloadStr string,
	httpClient *http.Requester,
) (*httpUtils.ResponseChain, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payloadStr))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, err
	}

	fuzzedReq = fuzzedReq.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// sendAndValidateRawPayload sends a literal payload string and validates the
// response. Returns nil body if the response should be skipped (redirect,
// empty, wrong content type). The string-based core of sendAndValidatePayload.
func sendAndValidateRawPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	payloadStr string,
	httpClient *http.Requester,
) ([]byte, error) {
	resp, err := sendRawPayload(ctx, ip, payloadStr, httpClient)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Close()

	// Skip 3xx redirects
	statusCode := resp.Response().StatusCode
	if statusCode >= 300 && statusCode < 400 {
		return nil, nil
	}

	body := resp.Body().Bytes()
	if len(body) == 0 {
		return nil, nil
	}

	// Validate Content-Type
	contentType := resp.Response().Header.Get("Content-Type")
	if !canExecuteJSContentType(contentType) && !looksLikeHTML(body) {
		return nil, nil
	}

	return body, nil
}

// sendAndValidatePayload sends a canary payload and validates the response.
func sendAndValidatePayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	payload *CanaryPayload,
	httpClient *http.Requester,
) ([]byte, error) {
	return sendAndValidateRawPayload(ctx, ip, payload.FullPayload, httpClient)
}

// canExecuteJSContentType checks Content-Type header for JavaScript execution.
func canExecuteJSContentType(contentType string) bool {
	if contentType == "" {
		return true
	}

	ct := strings.ToLower(strings.Split(contentType, ";")[0])
	ct = strings.TrimSpace(ct)

	if strings.Contains(ct, "/html") {
		return true
	}

	if strings.HasSuffix(ct, "/xml") || strings.Contains(ct, "+xml") {
		return true
	}

	return false
}

// looksLikeHTML checks if body looks like HTML.
func looksLikeHTML(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	length := min(len(body), 1024)
	preview := strings.ToLower(string(body[:length]))

	return strings.Contains(preview, "<!doctype") ||
		strings.Contains(preview, "<html") ||
		strings.Contains(preview, "<head") ||
		strings.Contains(preview, "<body") ||
		strings.Contains(preview, "<script") ||
		strings.Contains(preview, "<div") ||
		strings.Contains(preview, "<title") ||
		strings.Contains(preview, "<h1") ||
		strings.Contains(preview, "<h2") ||
		strings.Contains(preview, "<h3") ||
		strings.Contains(preview, "<form")
}

// classifyAttributeContext determines context for attribute values.
func classifyAttributeContext(tagName string, attr *HtmlAttribute) ReflectionContext {
	attrName := strings.ToLower(attr.Name)

	if IsEventHandler(attrName) {
		switch attr.QuoteType {
		case QuoteDouble:
			return JSInEventHandlerDQ
		case QuoteSingle:
			return JSInEventHandlerSQ
		case QuoteBacktick:
			return JSInEventHandlerBT
		default:
			return JSInEventHandlerUnquoted
		}
	}

	if IsURLAttribute(tagName, attrName) {
		switch attr.QuoteType {
		case QuoteDouble:
			return JSInURLAttributeDQ
		case QuoteSingle:
			return JSInURLAttributeSQ
		case QuoteBacktick:
			return JSInURLAttributeBT
		default:
			return JSInUnquotedURLAttribute
		}
	}

	switch attr.QuoteType {
	case QuoteDouble:
		return HTMLAttributeValueDQBreakout
	case QuoteSingle:
		return HTMLAttributeValueSQBreakout
	case QuoteBacktick:
		return HTMLAttributeValueBTBreakout
	default:
		return HTMLAttributeValueUnquotedBreakout
	}
}
