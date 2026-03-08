package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	httpUtils "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	pdHttpUtils "github.com/projectdiscovery/utils/http"
)

// formatHostPort formats host and port into the standard "host:port" or "host" format.
// Default ports (80 for HTTP, 443 for HTTPS) are omitted.
func formatHostPort(httpService *httpmsg.Service) string {
	host := httpService.Host()
	port := httpService.Port()
	protocol := httpService.Protocol()

	// Omit default ports
	if (port == 80 && protocol == "http") || (port == 443 && protocol == "https") {
		return host
	}

	return host + ":" + strconv.Itoa(port)
}

// SendAndReceive sends a raw HTTP request bytes and returns an HTTPTransaction.
// It parses the raw bytes into an http.Request and executes it.
// The httpService parameter provides the scheme, host, and port context that is lost during raw byte parsing.
func SendAndReceive(
	requestBytes []byte,
	httpService *httpmsg.Service,
	httpClient *httpUtils.Requester,
) (*HTTPTransaction, error) {
	if len(requestBytes) == 0 {
		return nil, fmt.Errorf("requestBytes cannot be empty in sendAndReceive")
	}
	if httpService == nil {
		return nil, fmt.Errorf("httpService cannot be nil in sendAndReceive")
	}

	// Parse raw bytes into HttpRequestResponse
	parsedRequest, err := httpmsg.ParseRawRequest(string(requestBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse request bytes: %w", err)
	}
	parsedRequest = parsedRequest.WithService(httpService)

	resp, _, err := httpClient.Execute(parsedRequest, httpUtils.Options{})
	if err != nil {
		return nil, err
	}

	// Build std http.Request for compatibility with HTTPTransaction
	reader := bufio.NewReader(bytes.NewReader(requestBytes))
	stdRequest, _ := http.ReadRequest(reader)
	if stdRequest != nil {
		stdRequest.URL.Scheme = httpService.Protocol()
		stdRequest.URL.Host = formatHostPort(httpService)
		stdRequest.Host = httpService.Host()
	}

	return NewHTTPTransaction(stdRequest, resp), nil
}

// HTTPTransaction gói gọn Request, Response và Response Body
type HTTPTransaction struct {
	request  *http.Request
	response *pdHttpUtils.ResponseChain
}

func NewHTTPTransaction(
	request *http.Request,
	response *pdHttpUtils.ResponseChain,
) *HTTPTransaction {
	return &HTTPTransaction{
		request:  request,
		response: response,
	}
}
func (t *HTTPTransaction) Close() {
	if t.response != nil {
		t.response.Close()
		t.response = nil
		t.request = nil
	}
}

func (t *HTTPTransaction) GetResponse() *http.Response {
	return t.response.Response()
}

func (t *HTTPTransaction) IsHasResponse() bool {
	return t.response != nil
}

func (t *HTTPTransaction) GetResponseBody() []byte {
	if t.response == nil {
		return []byte{}
	}
	return t.response.Body().Bytes()
}

func (t *HTTPTransaction) GetResponseBodyString() string {
	if t.response == nil {
		return ""
	}
	return t.response.Body().String()
}

func (t *HTTPTransaction) GetRequest() *http.Request {
	return t.request
}

func (t *HTTPTransaction) GetResponseStatusCode() int {
	if t.response == nil {
		return 0
	}
	return t.response.Response().StatusCode
}

func (t *HTTPTransaction) GetRawResponseHeaders() []byte {
	if t.response == nil {
		return []byte{}
	}
	return t.response.Headers().Bytes()
}

func (t *HTTPTransaction) GetResponseHeaders() http.Header {
	if t.response == nil {
		return http.Header{}
	}
	return t.response.Response().Header
}

func (t *HTTPTransaction) GetResponseChain() *pdHttpUtils.ResponseChain {
	return t.response
}
