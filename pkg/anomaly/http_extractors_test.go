package anomaly

import "testing"

func Test_GetContentType_Upcase(t *testing.T) {
	headers := map[string]string{
		"Host":         "example.com",
		"Content-Type": "text/html; charset=utf-8",
	}
	contentType := getContentType(convertMap(headers))
	t.Log(contentType)
}
