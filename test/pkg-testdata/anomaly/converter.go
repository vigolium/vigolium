package testdata

// ConvertToResponses converts CapturedResponse slice to a slice that can be converted to anomaly.Response
// Returns raw data that caller can pass to anomaly.NewResponse()
type ResponseData struct {
	StatusCode int
	Body       string
	Headers    map[string][]string
}

// ExtractResponseData converts CapturedResponse slice to ResponseData slice
func ExtractResponseData(captured []CapturedResponse) []ResponseData {
	responses := make([]ResponseData, 0, len(captured))

	for _, c := range captured {
		if c.FetchError != "" {
			// Skip failed fetches
			continue
		}

		resp := ResponseData{
			StatusCode: c.StatusCode,
			Body:       c.Body,
			Headers:    c.Headers,
		}
		responses = append(responses, resp)
	}

	return responses
}
