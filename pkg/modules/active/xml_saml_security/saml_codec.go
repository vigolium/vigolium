package xml_saml_security

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"

	"github.com/pkg/errors"
)

// DecodedSAML holds the decoded SAML data and encoding flags.
type DecodedSAML struct {
	XMLContent   string
	IsCompressed bool
	IsBase64     bool
}

// DecodeSAML decodes a SAML parameter value.
// Flow: URL decode -> Base64 decode -> DEFLATE decompress -> XML
func DecodeSAML(input string) (*DecodedSAML, error) {
	result := &DecodedSAML{
		IsCompressed: false,
		IsBase64:     false,
	}

	// Step 1: URL decode using PathUnescape (preserves + as +, unlike QueryUnescape)
	// This is important because Base64 uses + as a valid character
	decoded, err := url.PathUnescape(input)
	if err != nil {
		decoded = input // If URL decode fails, use original
	}

	// Step 2: Try Base64 decode
	base64Decoded, err := base64.StdEncoding.DecodeString(decoded)
	if err != nil {
		// Not base64, check if it's plain XML
		if isXML(decoded) {
			result.XMLContent = decoded
			return result, nil
		}
		return nil, errors.New("not valid SAML: not base64 and not XML")
	}
	result.IsBase64 = true

	// Step 3: Try DEFLATE decompress
	decompressed, err := DeflateDecompress(base64Decoded)
	if err != nil {
		// Not compressed, check if decoded bytes are XML
		xmlContent := string(base64Decoded)
		if isXML(xmlContent) {
			result.XMLContent = xmlContent
			return result, nil
		}
		return nil, errors.New("not valid SAML: base64 decoded but not XML")
	}
	result.IsCompressed = true
	result.XMLContent = string(decompressed)

	if !isXML(result.XMLContent) {
		return nil, errors.New("not valid SAML: decompressed content is not XML")
	}

	return result, nil
}

// EncodeSAML encodes XML back to SAML format using original encoding.
func EncodeSAML(xmlContent string, original *DecodedSAML) string {
	data := []byte(xmlContent)

	// Step 1: Compress if original was compressed
	if original.IsCompressed {
		compressed, err := DeflateCompress(data)
		if err == nil {
			data = compressed
		}
	}

	// Step 2: Base64 encode if original was base64
	if original.IsBase64 {
		return base64.StdEncoding.EncodeToString(data)
	}

	return string(data)
}

// DeflateDecompress decompresses DEFLATE data (raw, no header).
func DeflateDecompress(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = reader.Close() }()

	var buf bytes.Buffer
	_, err := io.Copy(&buf, reader)
	if err != nil {
		return nil, errors.Wrap(err, "deflate decompression failed")
	}

	return buf.Bytes(), nil
}

// DeflateCompress compresses data using DEFLATE (raw, no header).
func DeflateCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create deflate writer")
	}

	_, err = writer.Write(data)
	if err != nil {
		_ = writer.Close()
		return nil, errors.Wrap(err, "deflate compression write failed")
	}

	err = writer.Close()
	if err != nil {
		return nil, errors.Wrap(err, "deflate compression close failed")
	}

	return buf.Bytes(), nil
}

func isXML(content string) bool {
	return len(content) > 0 && content[0] == '<'
}
