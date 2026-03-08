//go:build sast_e2e

package sast

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/toolexec/astgrep"
)

// TestSAST_E2E_Extraction_To_Scan validates the full chain:
// source stub → ast-grep → routes → HRR → insertion points.
// Requires the ast-grep binary to be available.
func TestSAST_E2E_Extraction_To_Scan(t *testing.T) {
	ctx := context.Background()

	scanner, err := astgrep.NewScanner(nil)
	require.NoError(t, err, "failed to create scanner")

	// Ensure the binary is available
	err = scanner.EnsureBinary(ctx)
	require.NoError(t, err, "ast-grep binary not available (download or install required)")

	frameworks := []struct {
		name    string
		baseURL string
	}{
		{"gin", "http://localhost:8080"},
		{"fastapi", "http://localhost:8000"},
		{"express", "http://localhost:3000"},
	}

	for _, fw := range frameworks {
		t.Run(fw.name, func(t *testing.T) {
			stubDir := stubPath(fw.name)

			// Step 1: Extract routes from source
			result, err := scanner.ScanDirWithFramework(ctx, stubDir, fw.name)
			require.NoError(t, err, "ScanDirWithFramework failed for %s", fw.name)

			routes := astgrep.MatchesToRoutes(result.Matches)
			require.NotEmpty(t, routes, "no routes extracted from %s stub", fw.name)

			t.Logf("[%s] Extracted %d routes from %d matches", fw.name, len(routes), len(result.Matches))

			// Step 2: Convert each route to HRR
			var successCount int
			for _, route := range routes {
				if route.Path == "" {
					continue
				}

				method := normalizeMethod(route.Method)
				fullURL := fw.baseURL + route.Path
				rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\n\r\n", method, route.Path)

				rr, err := httpmsg.ParseRawRequest(rawReq)
				if err != nil {
					t.Logf("[%s] Skip route %s %s: parse error: %v", fw.name, method, route.Path, err)
					continue
				}

				// Step 3: Create insertion points
				points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), false)
				if err != nil {
					t.Logf("[%s] Skip route %s %s: insertion point error: %v", fw.name, method, route.Path, err)
					continue
				}

				t.Logf("[%s] Route %s %s → %d insertion points (url=%s)",
					fw.name, method, route.Path, len(points), fullURL)
				successCount++
			}

			assert.Greater(t, successCount, 0,
				"[%s] at least one route should successfully convert to HRR with insertion points", fw.name)
		})
	}
}
