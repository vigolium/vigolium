package infra

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func SwapToGetMethodRequest(originalReq []byte) []byte {
	// Get body parameters and URL parameters
	bodyParams, _ := httpmsg.GetBodyParametersMap(originalReq)
	urlParams, _ := httpmsg.GetURLParametersMap(originalReq)

	// Merge body params into URL params (URL params take precedence)
	if len(bodyParams) > 0 {
		for key, value := range bodyParams {
			// Only add body param if it's not already in URL params
			if _, exists := urlParams[key]; !exists {
				urlParams[key] = value
			}
		}
	}

	// Set merged params as URL parameters
	newReq := originalReq
	var err error
	if len(urlParams) > 0 {
		newReq, err = httpmsg.SetURLParametersMap(originalReq, urlParams)
		if err != nil {
			return originalReq
		}
	}

	// Clear body
	newReq, err = httpmsg.ClearBody(newReq)
	if err != nil {
		return originalReq
	}

	// Change method to GET
	newReq, err = httpmsg.SetMethod(newReq, "GET")
	if err != nil {
		return originalReq
	}

	// Remove Content-Type header (already done by ClearBody, but ensure it's gone)
	newReq, _ = httpmsg.RemoveHeader(newReq, "Content-Type")

	return newReq
}
