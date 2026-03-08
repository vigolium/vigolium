package http

import "testing"

func TestIsMediaContent(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		urlPath  string
		want     bool
	}{
		// MIME type prefix checks
		{"image png", "image/png", "/test", true},
		{"image jpeg", "image/jpeg", "/test.txt", true},
		{"image gif", "image/gif", "/test", true},
		{"image webp", "image/webp", "/test", true},
		{"image svg", "image/svg+xml", "/test", true},
		{"audio mpeg", "audio/mpeg", "/audio", true},
		{"audio wav", "audio/wav", "/audio", true},
		{"video mp4", "video/mp4", "/video", true},
		{"video webm", "video/webm", "/video", true},
		{"font woff", "font/woff", "/font", true},
		{"font woff2", "font/woff2", "/font", true},

		// Specific excluded MIME types
		{"application font-woff", "application/font-woff", "/f", true},
		{"application font-woff2", "application/font-woff2", "/f", true},
		{"application x-font-ttf", "application/x-font-ttf", "/f", true},
		{"application x-font-otf", "application/x-font-otf", "/f", true},
		{"application vnd.ms-fontobject", "application/vnd.ms-fontobject", "/f", true},

		// CSS - filtered (not useful for discovery)
		{"text css", "text/css", "/style.css", true},

		// Non-media types - should NOT be filtered
		{"text html", "text/html", "/index.html", false},
		{"application json", "application/json", "/api", false},
		{"text plain", "text/plain", "/readme.txt", false},
		{"application javascript", "application/javascript", "/app.js", false},
		{"application xml", "application/xml", "/data.xml", false},
		{"text xml", "text/xml", "/feed.xml", false},
		{"application pdf", "application/pdf", "/doc.pdf", false},

		// Extension fallback - empty MIME type
		{"no mime with png ext", "", "/image.png", true},
		{"no mime with jpg ext", "", "/photo.jpg", true},
		{"no mime with jpeg ext", "", "/photo.jpeg", true},
		{"no mime with gif ext", "", "/animation.gif", true},
		{"no mime with webp ext", "", "/image.webp", true},
		{"no mime with svg ext", "", "/icon.svg", true},
		{"no mime with ico ext", "", "/favicon.ico", true},
		{"no mime with mp3 ext", "", "/song.mp3", true},
		{"no mime with mp4 ext", "", "/video.mp4", true},
		{"no mime with woff ext", "", "/font.woff", true},
		{"no mime with woff2 ext", "", "/font.woff2", true},
		{"no mime with ttf ext", "", "/font.ttf", true},
		{"no mime with otf ext", "", "/font.otf", true},
		{"no mime with eot ext", "", "/font.eot", true},
		{"no mime with txt ext", "", "/file.txt", false},
		{"no mime with html ext", "", "/page.html", false},
		{"no mime with js ext", "", "/app.js", false},
		{"no mime no ext", "", "/api/users", false},

		// octet-stream with extension check
		{"octet-stream with png", "application/octet-stream", "/img.png", true},
		{"octet-stream with mp4", "application/octet-stream", "/vid.mp4", true},
		{"octet-stream with woff2", "application/octet-stream", "/font.woff2", true},
		{"octet-stream with txt", "application/octet-stream", "/file.txt", false},
		{"octet-stream with html", "application/octet-stream", "/page.html", false},
		{"octet-stream no ext", "application/octet-stream", "/binary", false},

		// Edge cases
		{"empty both", "", "", false},
		{"uppercase mime", "IMAGE/PNG", "/test", true},
		{"mixed case mime", "Image/Jpeg", "/test", true},
		{"mixed case ext", "", "/image.PNG", true},
		{"mixed case ext 2", "", "/photo.JpG", true},
		// Note: In actual usage, result.URL.Path is already parsed without query string
		{"path without query", "", "/image.png", true},
		{"deep path", "", "/assets/images/logo.png", true},
		{"deep path no media", "", "/api/v1/users/123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMediaContent(tt.mimeType, tt.urlPath)
			if got != tt.want {
				t.Errorf("IsMediaContent(%q, %q) = %v, want %v",
					tt.mimeType, tt.urlPath, got, tt.want)
			}
		})
	}
}

func TestIsMediaExtension(t *testing.T) {
	tests := []struct {
		urlPath string
		want    bool
	}{
		// Images
		{"/image.png", true},
		{"/photo.jpg", true},
		{"/photo.jpeg", true},
		{"/animation.gif", true},
		{"/image.webp", true},
		{"/icon.svg", true},
		{"/favicon.ico", true},
		{"/image.bmp", true},
		{"/image.tiff", true},
		{"/image.tif", true},

		// Audio
		{"/song.mp3", true},
		{"/audio.wav", true},
		{"/audio.ogg", true},
		{"/audio.flac", true},
		{"/audio.aac", true},
		{"/audio.m4a", true},

		// Video
		{"/video.mp4", true},
		{"/video.webm", true},
		{"/video.mkv", true},
		{"/video.avi", true},
		{"/video.mov", true},
		{"/video.wmv", true},
		{"/video.flv", true},

		// Fonts
		{"/font.woff", true},
		{"/font.woff2", true},
		{"/font.ttf", true},
		{"/font.otf", true},
		{"/font.eot", true},

		// CSS - filtered
		{"/style.css", true},

		// Non-media
		{"/file.txt", false},
		{"/page.html", false},
		{"/app.js", false},
		{"/data.json", false},
		{"/doc.pdf", false},
		{"/archive.zip", false},
		{"/noextension", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.urlPath, func(t *testing.T) {
			got := isMediaExtension(tt.urlPath)
			if got != tt.want {
				t.Errorf("isMediaExtension(%q) = %v, want %v",
					tt.urlPath, got, tt.want)
			}
		})
	}
}
