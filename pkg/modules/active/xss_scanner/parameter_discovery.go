package xss_scanner

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	myutils "github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
	httpUtils "github.com/projectdiscovery/utils/http"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/samber/lo"
	"go.uber.org/zap"
)

// ParameterDiscovery handles discovery of additional parameters via echo detection
type ParameterDiscovery struct{}

// NewParameterDiscovery creates a new parameter discovery instance
func NewParameterDiscovery() *ParameterDiscovery {
	return &ParameterDiscovery{}
}

// DiscoverAndScanParameters discovers new echo parameters and scans them
func (pd *ParameterDiscovery) DiscoverAndScanParameters(
	urlx *urlutil.URL,
	rawRequest []byte,
	moreParams []string,
	currentParams []string,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
	callback func(httpmsg.InsertionPoint),
) error {
	// Filter out already-checked and duplicate parameters
	toCheckParams := make([]string, 0)
	for _, param := range moreParams {
		if lo.Contains(currentParams, param) {
			continue
		}
		toCheckParams = append(toCheckParams, param)
	}

	if len(toCheckParams) == 0 {
		return nil
	}

	// Discover which parameters echo back
	echoParams, err := pd.findEchoQueryParams(rawRequest, 32, toCheckParams, httpService, httpClient)
	if err != nil {
		return err
	}

	if len(echoParams) == 0 {
		return nil
	}

	// Limit to max 20 params
	if len(echoParams) > 20 {
		zap.L().Info("found echo params, limiting to 20", zap.Int("found", len(echoParams)))
		echoParams = echoParams[:20]
	}

	// Create insertion points and scan each discovered parameter
	for _, paramName := range echoParams {
		ip, err := pd.createInsertionPointForNewParam(rawRequest, paramName, myutils.RandomString(6))
		if err != nil {
			zap.L().Warn("failed to create insertion point for param",
				zap.String("param", paramName),
				zap.Error(err))
			continue
		}
		callback(ip)
	}

	return nil
}

// findEchoQueryParams discovers parameters that reflect in response
func (pd *ParameterDiscovery) findEchoQueryParams(
	rawRequest []byte,
	chunkSize int,
	params []string,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) ([]string, error) {
	if chunkSize <= 0 {
		chunkSize = 1
	}

	echoParams := make([]string, 0)

	// Create chunks of parameters to test
	chunks := lo.Chunk(params, chunkSize)

	for _, chunk := range chunks {
		reflectTrackingMap := make(map[string]string)

		// Get current URL parameters using request_builder API
		urlParams, err := httpmsg.GetURLParametersMap(rawRequest)
		if err != nil {
			continue
		}

		// Add all parameters from chunk with random values
		for _, param := range chunk {
			value := myutils.RandomString(6)
			urlParams[param] = value
			reflectTrackingMap[value] = param
		}

		// Set all parameters back to request
		modifiedRequestRaw, err := httpmsg.SetURLParametersMap(rawRequest, urlParams)
		if err != nil {
			continue
		}

		// Parse the modified request
		modifiedRequest, err := httpmsg.ParseRawRequest(string(modifiedRequestRaw))
		if err != nil {
			continue
		}
		modifiedRequest = modifiedRequest.WithService(httpService)

		// Execute the request
		resp, _, err := httpClient.Execute(modifiedRequest, http.Options{})
		if err != nil {
			continue
		}

		// Check if response is valid for XSS testing
		if !isScriptContentExecutable(resp) {
			resp.Close()
			continue
		}

		// Check which random values are reflected in response
		responseBody := resp.Body().String()
		for value, paramName := range reflectTrackingMap {
			if strings.Contains(responseBody, value) {
				echoParams = append(echoParams, paramName)
			}
		}
		resp.Close()
	}

	return echoParams, nil
}

// createInsertionPointForNewParam creates an insertion point for a parameter that doesn't exist in the original request
func (pd *ParameterDiscovery) createInsertionPointForNewParam(
	rawRequest []byte,
	paramName string,
	paramValue string,
) (httpmsg.InsertionPoint, error) {
	// Add the parameter to the request using request_builder API
	modifiedRequest, err := httpmsg.AppendURLParameter(rawRequest, paramName, paramValue)
	if err != nil {
		return nil, errors.Wrap(err, "failed to append URL parameter")
	}

	// Create insertion points for the modified request
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(modifiedRequest, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create insertion points")
	}

	// Find the insertion point for the new parameter
	for _, ip := range insertionPoints {
		if ip.Name() == paramName {
			return ip, nil
		}
	}

	return nil, errors.Errorf("insertion point for param '%s' not found", paramName)
}

// isScriptContentExecutable checks if the response is valid for XSS testing
func isScriptContentExecutable(resp *httpUtils.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}

	// Check content type
	contentType := resp.Response().Header.Get("Content-Type")
	if contentType != "" {
		contentType = strings.ToLower(contentType)
		if !strings.Contains(contentType, "html") &&
			!strings.Contains(contentType, "xml") {
			return false
		}
	}

	return true
}
