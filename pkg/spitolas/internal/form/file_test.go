package form

import (
	"image/png"
	"os"
	"testing"
)

func TestGetDefaultFilePath(t *testing.T) {
	path, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() error = %v", err)
	}

	if path == "" {
		t.Fatal("GetDefaultFilePath() returned empty path")
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("Generated file does not exist at path: %s", path)
	}
}

func TestGetDefaultFilePathPNGValid(t *testing.T) {
	path, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() error = %v", err)
	}

	// Open and decode as PNG to verify it's a valid PNG
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open generated file: %v", err)
	}
	defer func() { _ = f.Close() }()

	img, err := png.Decode(f)
	if err != nil {
		t.Fatalf("Failed to decode PNG: %v", err)
	}

	// Verify dimensions
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	if width != DefaultImageWidth {
		t.Errorf("PNG width = %d, want %d", width, DefaultImageWidth)
	}
	if height != DefaultImageHeight {
		t.Errorf("PNG height = %d, want %d", height, DefaultImageHeight)
	}
}

func TestGetDefaultFilePathMagicBytes(t *testing.T) {
	path, err := GetDefaultFilePath()
	if err != nil {
		t.Fatalf("GetDefaultFilePath() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	// PNG magic bytes: 0x89 0x50 0x4E 0x47 (0x89 P N G)
	if len(data) < 4 {
		t.Fatal("File too small to be a valid PNG")
	}

	expected := []byte{0x89, 0x50, 0x4E, 0x47}
	for i, b := range expected {
		if data[i] != b {
			t.Errorf("Magic byte[%d] = 0x%02X, want 0x%02X", i, data[i], b)
		}
	}
}

func TestGetDefaultFilePathIdempotent(t *testing.T) {
	// Call multiple times - should return same path
	path1, err1 := GetDefaultFilePath()
	path2, err2 := GetDefaultFilePath()

	if err1 != nil || err2 != nil {
		t.Fatalf("GetDefaultFilePath() errors: %v, %v", err1, err2)
	}

	if path1 != path2 {
		t.Errorf("GetDefaultFilePath() not idempotent: %s != %s", path1, path2)
	}
}

func TestGetFilePathForAccept(t *testing.T) {
	tests := []struct {
		accept   string
		wantType FileType
	}{
		// Empty/default
		{"", FileTypePNG},

		// Extension format
		{".pdf", FileTypePDF},
		{".doc", FileTypeDoc},
		{".docx", FileTypeDoc},
		{".jpg", FileTypeJPEG},
		{".jpeg", FileTypeJPEG},
		{".png", FileTypePNG},
		{".gif", FileTypeGIF},
		{".txt", FileTypeTXT},
		{".csv", FileTypeCSV},
		{".xml", FileTypeXML},
		{".json", FileTypeJSON},
		{".html", FileTypeHTML},
		{".zip", FileTypeZIP},
		{".xls", FileTypeXLS},
		{".xlsx", FileTypeXLS},

		// MIME type format
		{"image/png", FileTypePNG},
		{"image/jpeg", FileTypeJPEG},
		{"image/gif", FileTypeGIF},
		{"application/pdf", FileTypePDF},
		{"text/plain", FileTypeTXT},
		{"text/csv", FileTypeCSV},
		{"text/xml", FileTypeXML},
		{"application/json", FileTypeJSON},
		{"text/html", FileTypeHTML},
		{"application/zip", FileTypeZIP},

		// Wildcard MIME types
		{"image/*", FileTypePNG},
		{"text/*", FileTypeTXT},
		{"application/*", FileTypePDF},

		// Multiple accept values (comma-separated)
		{".pdf,.doc,.docx", FileTypePDF},
		{"image/*,.pdf", FileTypePNG},
		{".doc,image/*", FileTypeDoc},

		// Case insensitivity
		{"IMAGE/PNG", FileTypePNG},
		{".PDF", FileTypePDF},
		{"Application/PDF", FileTypePDF},

		// With whitespace
		{" .pdf ", FileTypePDF},
		{" image/png , .doc ", FileTypePNG},
	}

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			path, err := GetFilePathForAccept(tt.accept)
			if err != nil {
				t.Fatalf("GetFilePathForAccept(%q) error = %v", tt.accept, err)
			}

			if path == "" {
				t.Fatalf("GetFilePathForAccept(%q) returned empty path", tt.accept)
			}

			// Verify file exists
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Fatalf("File does not exist at path: %s", path)
			}

			// Verify correct file type by checking extension
			wantExt := "." + string(tt.wantType)
			if !hasExtension(path, wantExt) {
				t.Errorf("GetFilePathForAccept(%q) path = %s, want extension %s", tt.accept, path, wantExt)
			}
		})
	}
}

func hasExtension(path, ext string) bool {
	return len(path) > len(ext) && path[len(path)-len(ext):] == ext
}

func TestGetFilePathForType(t *testing.T) {
	fileTypes := []FileType{
		FileTypePNG,
		FileTypeJPEG,
		FileTypeGIF,
		FileTypePDF,
		FileTypeTXT,
		FileTypeDoc,
		FileTypeXLS,
		FileTypeCSV,
		FileTypeXML,
		FileTypeJSON,
		FileTypeHTML,
		FileTypeZIP,
	}

	for _, ft := range fileTypes {
		t.Run(string(ft), func(t *testing.T) {
			path, err := GetFilePathForType(ft)
			if err != nil {
				t.Fatalf("GetFilePathForType(%q) error = %v", ft, err)
			}

			if path == "" {
				t.Fatalf("GetFilePathForType(%q) returned empty path", ft)
			}

			// Verify file exists
			info, err := os.Stat(path)
			if os.IsNotExist(err) {
				t.Fatalf("File does not exist at path: %s", path)
			}

			// Verify file has content
			if info.Size() == 0 {
				t.Errorf("GetFilePathForType(%q) generated empty file", ft)
			}
		})
	}
}

func TestGetFilePathForTypeCaching(t *testing.T) {
	// First call generates file
	path1, err := GetFilePathForType(FileTypeJSON)
	if err != nil {
		t.Fatalf("First GetFilePathForType(JSON) error = %v", err)
	}

	// Second call should return cached path
	path2, err := GetFilePathForType(FileTypeJSON)
	if err != nil {
		t.Fatalf("Second GetFilePathForType(JSON) error = %v", err)
	}

	if path1 != path2 {
		t.Errorf("GetFilePathForType not caching: %s != %s", path1, path2)
	}
}

func TestPDFMagicBytes(t *testing.T) {
	path, err := GetFilePathForType(FileTypePDF)
	if err != nil {
		t.Fatalf("GetFilePathForType(PDF) error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read PDF file: %v", err)
	}

	// PDF magic bytes: %PDF
	if len(data) < 4 {
		t.Fatal("PDF file too small")
	}

	expected := []byte{'%', 'P', 'D', 'F'}
	for i, b := range expected {
		if data[i] != b {
			t.Errorf("PDF magic byte[%d] = 0x%02X, want 0x%02X", i, data[i], b)
		}
	}
}

func TestZIPMagicBytes(t *testing.T) {
	path, err := GetFilePathForType(FileTypeZIP)
	if err != nil {
		t.Fatalf("GetFilePathForType(ZIP) error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read ZIP file: %v", err)
	}

	// ZIP magic bytes: PK (0x50 0x4B)
	if len(data) < 4 {
		t.Fatal("ZIP file too small")
	}

	// For minimal empty ZIP, the signature is End of Central Directory (0x50 0x4B 0x05 0x06)
	if data[0] != 0x50 || data[1] != 0x4B {
		t.Errorf("ZIP magic bytes = 0x%02X 0x%02X, want 0x50 0x4B", data[0], data[1])
	}
}
