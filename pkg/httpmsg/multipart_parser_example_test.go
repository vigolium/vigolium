package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ExampleExtractBoundary demonstrates extracting boundary from Content-Type header.
func ExampleExtractBoundary() {
	contentType := "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
	boundary := httpmsg.ExtractBoundary(contentType)

	fmt.Println(boundary)
	// Output: ----WebKitFormBoundary7MA4YWxkTrZu0gW
}

// ExampleParseMultipartBody demonstrates parsing a simple multipart form.
func ExampleParseMultipartBody() {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST /upload HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"username\"\r\n\r\n" +
			"john_doe\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	for _, param := range params {
		fmt.Printf("Name: %s, Value: %s\n", param.Name(), param.Value())
	}
	// Output: Name: username, Value: john_doe
}

// ExampleParseMultipartBody_fileUpload demonstrates parsing a file upload.
func ExampleParseMultipartBody_fileUpload() {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST /upload HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\n" +
			"Content-Type: image/jpeg\r\n\r\n" +
			"binary image data here\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	for _, param := range params {
		switch param.Type() {
		case httpmsg.ParamBodyMultipart:
			fmt.Printf("Field: %s\n", param.Name())
		case httpmsg.ParamMultipartAttr:
			fmt.Printf("Attribute: %s = %s\n", param.Name(), param.Value())
		}
	}
	// Output:
	// Field: avatar
	// Attribute: filename = photo.jpg
}

// ExampleParseMultipartBody_multipleFields demonstrates parsing multiple fields.
func ExampleParseMultipartBody_multipleFields() {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST /submit HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"email\"\r\n\r\n" +
			"user@example.com\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"message\"\r\n\r\n" +
			"Hello World\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	for _, param := range params {
		fmt.Printf("%s: %s\n", param.Name(), param.Value())
	}
	// Output:
	// email: user@example.com
	// message: Hello World
}

// ExampleParseMultipartRequest demonstrates automatic boundary extraction.
func ExampleParseMultipartRequest() {
	request := []byte(
		"POST /api/data HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
			"value\r\n" +
			"------WebKitFormBoundary--")

	params, err := httpmsg.ParseMultipartRequest(request)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	for _, param := range params {
		fmt.Printf("%s=%s\n", param.Name(), param.Value())
	}
	// Output: field=value
}

// ExampleParseMultipartBody_withMetadata demonstrates accessing metadata.
func ExampleParseMultipartBody_withMetadata() {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST /upload HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"document\"; filename=\"doc.pdf\"\r\n" +
			"Content-Type: application/pdf\r\n\r\n" +
			"PDF content\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	for _, param := range params {
		if param.Type() == httpmsg.ParamBodyMultipart && param.Metadata() != "" {
			fmt.Printf("Field: %s\n", param.Name())
			fmt.Printf("Has metadata: yes\n")
		}
	}
	// Output:
	// Field: document
	// Has metadata: yes
}

// ExampleParseMultipartBody_offsets demonstrates byte offset tracking.
func ExampleParseMultipartBody_offsets() {
	boundary := "----WebKit"
	request := []byte(
		"POST / HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKit\r\n" +
			"Content-Disposition: form-data; name=\"test\"\r\n\r\n" +
			"data\r\n" +
			"------WebKit--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	if len(params) > 0 {
		param := params[0]
		// Verify offsets by extracting from original request
		extractedName := string(request[param.NameStart():param.NameEnd()])
		extractedValue := string(request[param.ValueStart():param.ValueEnd()])

		fmt.Printf("Name: %s (extracted: %s)\n", param.Name(), extractedName)
		fmt.Printf("Value: %s (extracted: %s)\n", param.Value(), extractedValue)
		fmt.Printf("Offsets valid: %t\n", extractedName == param.Name() && extractedValue == param.Value())
	}
	// Output:
	// Name: test (extracted: test)
	// Value: data (extracted: data)
	// Offsets valid: true
}

// ExampleParseMultipartBody_emptyValue demonstrates handling empty values.
func ExampleParseMultipartBody_emptyValue() {
	boundary := "----WebKitFormBoundary"
	request := []byte(
		"POST /submit HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundary\r\n" +
			"Content-Disposition: form-data; name=\"empty\"\r\n\r\n" +
			"\r\n" +
			"------WebKitFormBoundary--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	for _, param := range params {
		fmt.Printf("Name: %s, Empty: %t\n", param.Name(), param.Value() == "")
	}
	// Output: Name: empty, Empty: true
}

// ExampleParseMultipartBody_complexForm demonstrates a realistic form with mixed content.
func ExampleParseMultipartBody_complexForm() {
	boundary := "----WebKitFormBoundaryABC123"
	request := []byte(
		"POST /api/profile HTTP/1.1\r\n" +
			"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" +
			"------WebKitFormBoundaryABC123\r\n" +
			"Content-Disposition: form-data; name=\"userId\"\r\n\r\n" +
			"42\r\n" +
			"------WebKitFormBoundaryABC123\r\n" +
			"Content-Disposition: form-data; name=\"bio\"\r\n\r\n" +
			"Software developer\r\n" +
			"------WebKitFormBoundaryABC123\r\n" +
			"Content-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\n" +
			"Content-Type: image/png\r\n\r\n" +
			"PNG_DATA\r\n" +
			"------WebKitFormBoundaryABC123--")

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseMultipartBody(request, bodyOffset, boundary)

	textFields := 0
	fileFields := 0

	for _, param := range params {
		if param.Type() == httpmsg.ParamBodyMultipart {
			if param.Metadata() == "" {
				textFields++
			} else {
				fileFields++
			}
		}
	}

	fmt.Printf("Text fields: %d\n", textFields)
	fmt.Printf("File fields: %d\n", fileFields)
	// Output:
	// Text fields: 2
	// File fields: 1
}

// ExampleExtractBoundary_withWhitespace demonstrates trimming whitespace.
func ExampleExtractBoundary_withWhitespace() {
	contentType := "multipart/form-data; boundary=  ----WebKit  "
	boundary := httpmsg.ExtractBoundary(contentType)

	fmt.Printf("Boundary: '%s'\n", boundary)
	// Output: Boundary: '----WebKit'
}
