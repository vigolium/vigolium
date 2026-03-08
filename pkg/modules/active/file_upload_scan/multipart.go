package file_upload_scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// commonUploadDirs are paths where uploaded files are commonly stored.
var commonUploadDirs = []string{
	"/uploads/",
	"/upload/",
	"/files/",
	"/images/",
	"/media/",
	"/static/uploads/",
}

// replaceFilePart reconstructs a multipart request, replacing only the file part
// with new filename, content-type, and body while preserving all other parts.
func replaceFilePart(raw []byte, probe uploadProbe) ([]byte, error) {
	ct := ""
	for _, hdr := range getHeaders(raw) {
		if strings.EqualFold(hdr.Name, "Content-Type") {
			ct = hdr.Value
			break
		}
	}

	boundary := httpmsg.ExtractBoundary(ct)
	if boundary == "" {
		return nil, fmt.Errorf("no boundary found in Content-Type")
	}

	bodyOffset := httpmsg.FindBodyOffset(raw)
	if bodyOffset < 0 {
		return nil, fmt.Errorf("no body found in request")
	}

	params, err := httpmsg.ParseMultipartBody(raw, bodyOffset, boundary)
	if err != nil {
		return nil, err
	}

	// Rebuild multipart body from parts
	var newBody strings.Builder
	filePartReplaced := false

	for _, p := range params {
		// Skip filename attributes (they are separate Param entries)
		if p.Type() == httpmsg.ParamMultipartAttr {
			continue
		}

		newBody.WriteString("--")
		newBody.WriteString(boundary)
		newBody.WriteString("\r\n")

		if !filePartReplaced && isFilePart(p) {
			// Replace the file part
			fmt.Fprintf(&newBody,
				"Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n",
				p.Name(), probe.filename,
			)
			fmt.Fprintf(&newBody, "Content-Type: %s\r\n", probe.contentType)
			newBody.WriteString("\r\n")
			newBody.WriteString(probe.body)
			newBody.WriteString("\r\n")
			filePartReplaced = true
		} else {
			// Preserve non-file part as-is
			fmt.Fprintf(&newBody,
				"Content-Disposition: form-data; name=\"%s\"\r\n",
				p.Name(),
			)
			newBody.WriteString("\r\n")
			newBody.WriteString(p.Value())
			newBody.WriteString("\r\n")
		}
	}

	newBody.WriteString("--")
	newBody.WriteString(boundary)
	newBody.WriteString("--\r\n")

	// Replace the body in the raw request
	modified, err := httpmsg.SetBody(raw, []byte(newBody.String()))
	if err != nil {
		return nil, err
	}

	return modified, nil
}

// isFilePart checks if a multipart parameter is a file upload part.
// File parts have metadata containing "filename=" in their Content-Disposition.
func isFilePart(p *httpmsg.Param) bool {
	metadata := p.Metadata()
	return strings.Contains(metadata, "filename=")
}


// extractUploadPath attempts to find the uploaded file's path from the response.
func extractUploadPath(body string) string {
	// Try JSON response with common field names
	var jsonResp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResp); err == nil {
		for _, key := range []string{"url", "path", "file_url", "file_path", "location", "link"} {
			if val, ok := jsonResp[key]; ok {
				if s, ok := val.(string); ok && s != "" {
					return s
				}
			}
		}
	}

	// Try HTML response - look for links to uploaded files
	linkPattern := regexp.MustCompile(`(?i)(?:href|src)=["']([^"']*(?:upload|file)[^"']*)["']`)
	if matches := linkPattern.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// getHeaders extracts headers from raw request using httpmsg.
func getHeaders(raw []byte) []httpmsg.HttpHeader {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil
	}
	return req.Request().Headers()
}
