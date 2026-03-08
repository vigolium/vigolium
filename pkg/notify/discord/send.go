package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// send sends a JSON webhook message.
func (b *Backend) send(msg *WebhookMessage) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook message: %w", err)
	}

	req, err := http.NewRequest("POST", b.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vigolium-Scanner/1.0")

	return b.doRequest(req)
}

// sendWithFile sends a message with file attachment via multipart/form-data.
func (b *Backend) sendWithFile(msg *WebhookMessage, filename string, content []byte) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add payload_json field
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook message: %w", err)
	}

	jsonHeader := make(textproto.MIMEHeader)
	jsonHeader.Set("Content-Disposition", `form-data; name="payload_json"`)
	jsonHeader.Set("Content-Type", "application/json")
	jsonPart, err := writer.CreatePart(jsonHeader)
	if err != nil {
		return fmt.Errorf("failed to create json part: %w", err)
	}
	if _, err := jsonPart.Write(jsonData); err != nil {
		return fmt.Errorf("failed to write json: %w", err)
	}

	// Add file field
	fileHeader := make(textproto.MIMEHeader)
	fileHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="files[0]"; filename="%s"`, filename))
	fileHeader.Set("Content-Type", "text/plain")
	filePart, err := writer.CreatePart(fileHeader)
	if err != nil {
		return fmt.Errorf("failed to create file part: %w", err)
	}
	if _, err := filePart.Write(content); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest("POST", b.webhookURL, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Vigolium-Scanner/1.0")

	return b.doRequest(req)
}

// sendFile sends only a file (for raw messages that exceed limit).
func (b *Backend) sendFile(filename string, content []byte) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file field
	fileHeader := make(textproto.MIMEHeader)
	fileHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="files[0]"; filename="%s"`, filename))
	fileHeader.Set("Content-Type", "text/plain")
	filePart, err := writer.CreatePart(fileHeader)
	if err != nil {
		return fmt.Errorf("failed to create file part: %w", err)
	}
	if _, err := filePart.Write(content); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest("POST", b.webhookURL, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Vigolium-Scanner/1.0")

	return b.doRequest(req)
}

// sendContent sends a plain text content message.
func (b *Backend) sendContent(content string) error {
	msg := &WebhookMessage{Content: content}
	return b.send(msg)
}

// doRequest executes the HTTP request and handles response.
func (b *Backend) doRequest(req *http.Request) error {
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited (HTTP 429)")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
