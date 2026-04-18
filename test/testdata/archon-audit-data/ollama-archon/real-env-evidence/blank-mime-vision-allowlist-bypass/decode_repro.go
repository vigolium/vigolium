package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Copy of openai.decodeImageURL (openai/openai.go:674-705) at the finding's target commit.
type ImageData []byte

func decodeImageURL(url string) (ImageData, error) {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return nil, errors.New("image URLs are not currently supported, please use base64 encoded data instead")
	}

	types := []string{"jpeg", "jpg", "png", "webp"}

	if strings.HasPrefix(url, "data:;base64,") {
		url = strings.TrimPrefix(url, "data:;base64,")
	} else {
		valid := false
		for _, t := range types {
			prefix := "data:image/" + t + ";base64,"
			if strings.HasPrefix(url, prefix) {
				url = strings.TrimPrefix(url, prefix)
				valid = true
				break
			}
		}
		if !valid {
			return nil, errors.New("invalid image input")
		}
	}

	img, err := base64.StdEncoding.DecodeString(url)
	if err != nil {
		return nil, errors.New("invalid image input")
	}
	return img, nil
}

func main() {
	// Case 1: attacker binary via blank MIME (data:;base64,)
	attackerBytes := []byte{0x00, 0x01, 0x02, 0x7f, 0xff, 0xfe, 0xca, 0xfe}
	attackerB64 := base64.StdEncoding.EncodeToString(attackerBytes)

	url1 := "data:;base64," + attackerB64
	out1, err1 := decodeImageURL(url1)
	fmt.Printf("Case 1 (blank MIME): url=%q err=%v bytesOut=%x\n", url1, err1, out1)

	// Case 2: attacker binary via declared image/jpeg (existing allowlist bypass via MIME lie)
	url2 := "data:image/jpeg;base64," + attackerB64
	out2, err2 := decodeImageURL(url2)
	fmt.Printf("Case 2 (lied MIME): url=%q err=%v bytesOut=%x\n", url2, err2, out2)

	// Case 3: outside allowlist -- e.g. gif
	url3 := "data:image/gif;base64," + attackerB64
	out3, err3 := decodeImageURL(url3)
	fmt.Printf("Case 3 (gif MIME): url=%q err=%v bytesOut=%x\n", url3, err3, out3)

	// Case 4: tar octet-stream
	url4 := "data:application/octet-stream;base64," + attackerB64
	out4, err4 := decodeImageURL(url4)
	fmt.Printf("Case 4 (octet-stream): url=%q err=%v bytesOut=%x\n", url4, err4, out4)
}
