package llm_endpoint_fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func ctxJSON(reqBody, respBody string) *httpmsg.HttpRequestResponse {
	rawReq := "POST /v1/chat/completions HTTP/1.1\r\nHost: ai.example.com\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + itoa(len(reqBody)) + "\r\n\r\n" + reqBody
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("ai.example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + respBody
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestDetectsChatCompletion(t *testing.T) {
	t.Parallel()
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	respBody := `{"object":"chat.completion","choices":[{"message":{"role":"assistant","content":"hello"}}]}`
	res, err := New().ScanPerRequest(ctxJSON(reqBody, respBody), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "LLM Endpoint Detected", res[0].Info.Name)
}

func TestIgnoresNonLLMJSON(t *testing.T) {
	t.Parallel()
	reqBody := `{"username":"bob","password":"x"}`
	respBody := `{"status":"ok","token":"abc"}`
	res, err := New().ScanPerRequest(ctxJSON(reqBody, respBody), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-LLM JSON API must not be fingerprinted as LLM")
}
