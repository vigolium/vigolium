package form

import (
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// File generation constants.
const (
	DefaultImageWidth  = 800
	DefaultImageHeight = 600
	DefaultPNGName     = "ff_upload.png"
)

// FileType represents supported file types for upload.
type FileType string

const (
	FileTypePNG  FileType = "png"
	FileTypeJPEG FileType = "jpeg"
	FileTypeGIF  FileType = "gif"
	FileTypePDF  FileType = "pdf"
	FileTypeTXT  FileType = "txt"
	FileTypeDoc  FileType = "doc"
	FileTypeXLS  FileType = "xls"
	FileTypeCSV  FileType = "csv"
	FileTypeXML  FileType = "xml"
	FileTypeJSON FileType = "json"
	FileTypeHTML FileType = "html"
	FileTypeZIP  FileType = "zip"
)

// generatedFiles caches generated file paths by type.
var (
	generatedFiles = make(map[FileType]string)
	generateMu     sync.Mutex
)

// GetFilePathForAccept returns an appropriate file path based on accept attribute.
// Parses accept attribute (e.g., "image/*", ".pdf,.doc", "application/pdf")
// and generates/returns a matching file.
func GetFilePathForAccept(accept string) (string, error) {
	fileType := parseAcceptToFileType(accept)
	return GetFilePathForType(fileType)
}

// GetFilePathForType returns a file path for the specified file type.
// Generates the file on first call, then caches for subsequent calls.
func GetFilePathForType(fileType FileType) (string, error) {
	generateMu.Lock()
	defer generateMu.Unlock()

	// Return cached path if exists
	if path, exists := generatedFiles[fileType]; exists {
		// Verify file still exists
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		// File was deleted, remove from cache and regenerate
		delete(generatedFiles, fileType)
	}

	// Generate file
	tempDir := os.TempDir()
	filename := fmt.Sprintf("ff_upload.%s", fileType)
	path := filepath.Join(tempDir, filename)

	var err error
	switch fileType {
	case FileTypePNG:
		err = generatePNG(path)
	case FileTypeJPEG:
		err = generateJPEG(path)
	case FileTypeGIF:
		err = generateGIF(path)
	case FileTypePDF:
		err = generatePDF(path)
	case FileTypeTXT:
		err = generateTXT(path)
	case FileTypeDoc:
		err = generateDoc(path)
	case FileTypeXLS:
		err = generateXLS(path)
	case FileTypeCSV:
		err = generateCSV(path)
	case FileTypeXML:
		err = generateXML(path)
	case FileTypeJSON:
		err = generateJSON(path)
	case FileTypeHTML:
		err = generateHTML(path)
	case FileTypeZIP:
		err = generateZIP(path)
	default:
		// Fallback to PNG for unknown types
		err = generatePNG(path)
	}

	if err != nil {
		return "", fmt.Errorf("failed to generate %s file: %w", fileType, err)
	}

	generatedFiles[fileType] = path
	return path, nil
}

// GetDefaultFilePath returns path to default PNG file (backward compatible).
func GetDefaultFilePath() (string, error) {
	return GetFilePathForType(FileTypePNG)
}

// parseAcceptToFileType converts accept attribute to FileType.
// Supports: MIME types (image/png), wildcards (image/*), extensions (.pdf).
func parseAcceptToFileType(accept string) FileType {
	if accept == "" {
		return FileTypePNG // Default
	}

	accept = strings.ToLower(strings.TrimSpace(accept))

	// Check each part (accept can be comma-separated)
	for part := range strings.SplitSeq(accept, ",") {
		part = strings.TrimSpace(part)

		// Extension format: .pdf, .doc, .jpg
		if ext, found := strings.CutPrefix(part, "."); found {
			if ft := extensionToFileType(ext); ft != "" {
				return ft
			}
		}

		// MIME type format: image/png, application/pdf
		if strings.Contains(part, "/") {
			if ft := mimeToFileType(part); ft != "" {
				return ft
			}
		}
	}

	// Default fallback
	return FileTypePNG
}

// extensionToFileType maps file extensions to FileType.
func extensionToFileType(ext string) FileType {
	switch strings.ToLower(ext) {
	case "png":
		return FileTypePNG
	case "jpg", "jpeg":
		return FileTypeJPEG
	case "gif":
		return FileTypeGIF
	case "pdf":
		return FileTypePDF
	case "txt", "text":
		return FileTypeTXT
	case "doc", "docx":
		return FileTypeDoc
	case "xls", "xlsx":
		return FileTypeXLS
	case "csv":
		return FileTypeCSV
	case "xml":
		return FileTypeXML
	case "json":
		return FileTypeJSON
	case "html", "htm":
		return FileTypeHTML
	case "zip":
		return FileTypeZIP
	default:
		return ""
	}
}

// mimeToFileType maps MIME types to FileType.
func mimeToFileType(mime string) FileType {
	mime = strings.ToLower(mime)

	// Exact matches
	switch mime {
	case "image/png":
		return FileTypePNG
	case "image/jpeg", "image/jpg":
		return FileTypeJPEG
	case "image/gif":
		return FileTypeGIF
	case "application/pdf":
		return FileTypePDF
	case "text/plain":
		return FileTypeTXT
	case "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return FileTypeDoc
	case "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return FileTypeXLS
	case "text/csv":
		return FileTypeCSV
	case "text/xml", "application/xml":
		return FileTypeXML
	case "application/json":
		return FileTypeJSON
	case "text/html":
		return FileTypeHTML
	case "application/zip":
		return FileTypeZIP
	}

	// Wildcard matches
	if strings.HasPrefix(mime, "image/") || mime == "image/*" {
		return FileTypePNG // Default image
	}
	if strings.HasPrefix(mime, "text/") || mime == "text/*" {
		return FileTypeTXT
	}
	if strings.HasPrefix(mime, "application/") || mime == "application/*" {
		return FileTypePDF // Default application
	}

	return ""
}

// File generators

func generatePNG(path string) error {
	img := createGradientImage()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return png.Encode(f, img)
}

func generateJPEG(path string) error {
	img := createGradientImage()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return jpeg.Encode(f, img, &jpeg.Options{Quality: 85})
}

func generateGIF(path string) error {
	// GIF requires palette image - create simple gradient
	img := image.NewPaletted(image.Rect(0, 0, DefaultImageWidth, DefaultImageHeight), nil)
	// Use standard palette
	palette := make([]color.Color, 256)
	for i := range 256 {
		palette[i] = color.RGBA{R: uint8(i), G: uint8(150), B: uint8(200), A: 255}
	}
	img.Palette = palette

	for y := range DefaultImageHeight {
		for x := range DefaultImageWidth {
			idx := uint8((x * 255) / DefaultImageWidth)
			img.SetColorIndex(x, y, idx)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Write minimal GIF manually (image/gif package adds complexity)
	// For simplicity, just write as PNG since most accept="image/*" will accept it
	return png.Encode(f, img)
}

func generatePDF(path string) error {
	// Minimal valid PDF structure
	content := `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 24 Tf 100 700 Td (Test Upload) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000206 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
300
%%EOF`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateTXT(path string) error {
	content := `Test File
==================

This is a test file generated.

Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateDoc(path string) error {
	// Minimal RTF format (readable by Word)
	content := `{\rtf1\ansi\deff0
{\fonttbl{\f0 Arial;}}
\f0\fs24 Test Document\par
\par
This is a test document generated for form upload testing.\par
\par
Lorem ipsum dolor sit amet, consectetur adipiscing elit.\par
}`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateXLS(path string) error {
	// Minimal CSV that Excel can open
	content := `Name,Value,Description
Test1,100,First test row
Test2,200,Second test row
Test3,300,Third test row
Total,600,Sum of values
`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateCSV(path string) error {
	content := `id,name,email,status
1,John Doe,john@example.com,active
2,Jane Smith,jane@example.com,active
3,Bob Wilson,bob@example.com,inactive
`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateXML(path string) error {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<root>
  <document>
    <title>Test XML</title>
    <description>Test XML file for form upload testing</description>
    <items>
      <item id="1">First item</item>
      <item id="2">Second item</item>
      <item id="3">Third item</item>
    </items>
  </document>
</root>
`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateJSON(path string) error {
	content := `{
  "name": "Test JSON",
  "version": "1.0.0",
  "description": "Test JSON file for form upload testing",
  "data": {
    "items": [
      {"id": 1, "value": "first"},
      {"id": 2, "value": "second"},
      {"id": 3, "value": "third"}
    ]
  }
}
`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateHTML(path string) error {
	content := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test HTML</title>
</head>
<body>
    <h1>Test HTML Document</h1>
    <p>This is a test HTML file generated for form upload testing.</p>
    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
    </ul>
</body>
</html>
`
	return os.WriteFile(path, []byte(content), 0644)
}

func generateZIP(path string) error {
	// Minimal valid ZIP file (empty archive)
	// ZIP end of central directory record
	content := []byte{
		0x50, 0x4B, 0x05, 0x06, // End of central directory signature
		0x00, 0x00, // Number of this disk
		0x00, 0x00, // Disk where central directory starts
		0x00, 0x00, // Number of central directory records on this disk
		0x00, 0x00, // Total number of central directory records
		0x00, 0x00, 0x00, 0x00, // Size of central directory
		0x00, 0x00, 0x00, 0x00, // Offset of start of central directory
		0x00, 0x00, // Comment length
	}
	return os.WriteFile(path, content, 0644)
}

// createGradientImage creates an 800x600 RGBA image with blue-purple gradient.
func createGradientImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, DefaultImageWidth, DefaultImageHeight))
	for y := range DefaultImageHeight {
		for x := range DefaultImageWidth {
			r := uint8(100 + x*100/DefaultImageWidth)
			g := uint8(150 - y*50/DefaultImageHeight)
			b := uint8(200)
			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	return img
}
