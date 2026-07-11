package secret_detect

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/secretscan"
)

// TestIsBinaryBlobMatch_PinsToExactOccurrence proves the offset-aware guard
// classifies the occurrence the detector actually matched, not the first textual
// one. The same value appears twice: inside a long base64 blob (a false positive)
// and as a genuine delimited assignment (a real leak). The no-offset (start<0)
// locate-first path always finds the blob first and would wrongly drop the
// genuine occurrence too; passing the offsets judges each occurrence correctly.
func TestIsBinaryBlobMatch_PinsToExactOccurrence(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE1" // arbitrary base64-family token
	blob := strings.Repeat("A", 200) + secret + strings.Repeat("B", 200)
	genuine := `api_key = "` + secret + `";`
	body := []byte(blob + "\n" + genuine)

	blobStart := 200
	genuineStart := len(blob) + 1 + len(`api_key = "`)
	require.Equal(t, secret, string(body[blobStart:blobStart+len(secret)]))
	require.Equal(t, secret, string(body[genuineStart:genuineStart+len(secret)]))

	// Pinned to the blob occurrence → recognized as a blob (drop).
	assert.True(t, IsBinaryBlobMatch(body, secret, blobStart, blobStart+len(secret)))
	// Pinned to the genuine occurrence → NOT a blob (keep).
	assert.False(t, IsBinaryBlobMatch(body, secret, genuineStart, genuineStart+len(secret)))
	// The no-offset path collapses both to the blob occurrence — the bug the offset
	// threading fixes.
	assert.True(t, IsBinaryBlobMatch(body, secret, -1, -1))
}

// TestGradeMatch_UsesMatchOffsetForStructuralGuard is the end-to-end version:
// GradeMatch must keep a genuine delimited occurrence and drop a blob-embedded one
// of the same value, driven purely by each match's byte offset.
func TestGradeMatch_UsesMatchOffsetForStructuralGuard(t *testing.T) {
	secret := "hV7pQ2mZ9kR4sT1wB6nD8xL3cF5gJ0aY" // 32 mixed-alnum, high entropy
	blob := strings.Repeat("Q", 200) + secret + strings.Repeat("Z", 200)
	genuine := `token = "` + secret + `"`
	body := []byte(blob + "\n" + genuine)

	ev := EvidenceContext{
		Body:       body,
		Host:       "example.com",
		URL:        "https://example.com/app.js",
		RespHead:   "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n",
		StatusCode: 200,
	}
	mk := func(start int) secretscan.Match {
		return secretscan.Match{
			RuleID: "test.rule", RuleName: "Test Rule", Source: "kingfisher",
			Confidence: "high", Secret: secret, Start: start, End: start + len(secret),
		}
	}

	genuineStart := len(blob) + 1 + len(`token = "`)
	kept, ok := GradeMatch(mk(genuineStart), ev)
	assert.True(t, ok, "genuine delimited occurrence must be kept")
	require.NotNil(t, kept)
	assert.Equal(t, secret, kept.ExtractedResults[0])

	_, ok = GradeMatch(mk(200), ev) // the blob-embedded occurrence
	assert.False(t, ok, "blob-embedded occurrence must be dropped")
}
