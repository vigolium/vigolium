package lfi_generic

import (
	"encoding/base64"
	"testing"
)

func TestConfirmPHPFilterBase64(t *testing.T) {
	t.Parallel()
	phpSrc := base64.StdEncoding.EncodeToString([]byte("<?php $x = 1; echo $x; ?>"))
	pngBlob := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

	tests := []struct {
		name     string
		data     string
		baseline string
		want     bool
	}{
		{
			name: "base64 of PHP source confirms",
			data: phpSrc,
			want: true,
		},
		{
			name: "PHP base64 embedded in larger body confirms",
			data: "some prefix " + phpSrc + " trailing",
			want: true,
		},
		{
			name: "base64 PNG data-URI does not confirm",
			data: `<img src="data:image/png;base64,` + pngBlob + `">`,
			want: false,
		},
		{
			name:     "blob already in baseline is rejected",
			data:     phpSrc,
			baseline: phpSrc,
			want:     false,
		},
		{
			name: "no base64 at all",
			data: "<html><body>plain page</body></html>",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := confirmPHPFilterBase64(tc.data, tc.baseline); got != tc.want {
				t.Fatalf("confirmPHPFilterBase64() = %v, want %v", got, tc.want)
			}
		})
	}
}
