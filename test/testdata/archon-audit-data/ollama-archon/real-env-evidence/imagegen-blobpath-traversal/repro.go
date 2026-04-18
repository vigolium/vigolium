package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ollama/ollama/x/imagegen/transfer"
	"context"
)

// This simulates the attack: a registry returns a manifest whose blob list
// contains a traversal digest. We verify the downloader rejects it.

type manifestJSON struct {
	SchemaVersion int `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

func main() {
	// Attacker's traversal digest
	traversalDigest := "sha256:../../../etc/passwd"
	evilContent := []byte("not a real blob - traversal attempt")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(os.Stderr, "server got:", r.URL.Path)
		if strings.Contains(r.URL.Path, "/blobs/") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(evilContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	destDir, _ := os.MkdirTemp("", "cold-verify-*")
	defer os.RemoveAll(destDir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := transfer.Download(ctx, transfer.DownloadOptions{
		Blobs: []transfer.Blob{
			{Digest: traversalDigest, Size: int64(len(evilContent))},
		},
		BaseURL:    srv.URL,
		DestDir:    destDir,
		Repository: "library/evil",
	})

	fmt.Printf("download returned error: %v\n", err)

	// Check whether a file got created via traversal
	target := filepath.Join(destDir, "..", "..", "..", "etc", "passwd")
	absTarget, _ := filepath.Abs(target)
	fmt.Printf("Checking target path %s\n", absTarget)

	// Also check the direct compute path
	cleaned := strings.Replace(traversalDigest, ":", "-", 1)
	joinedPath := filepath.Join(destDir, cleaned)
	fmt.Printf("filepath.Join result: %s\n", joinedPath)

	// Also verify sha256 math
	h := sha256.Sum256(evilContent)
	fmt.Printf("sha256(content) = sha256:%x\n", h)
	fmt.Printf("expected (traversal) = %s\n", traversalDigest)

	// Dump JSON for reference
	_ = json.NewEncoder(os.Stderr).Encode(map[string]interface{}{
		"error": fmt.Sprintf("%v", err),
	})

	_ = io.Discard
}
