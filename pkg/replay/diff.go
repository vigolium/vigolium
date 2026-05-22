package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/utils"
)

// baselineFromResponse builds a Summary from raw response bytes plus
// the stored status / response-time metadata. The body is hashed
// separately from content-length so the diff catches changes that
// don't shift size (e.g. session-token rotation, csrf nonce).
func baselineFromResponse(rawResponse []byte, status int, responseTimeMs int64, excerptCap int) *Summary {
	if excerptCap <= 0 {
		excerptCap = DefaultExcerptCap
	}
	body := extractResponseBody(rawResponse)
	sum := sha256.Sum256(body)
	excerpt, truncated := clipBytes(body, excerptCap)
	return &Summary{
		Status:         status,
		ResponseLen:    len(body),
		ContentHash:    hex.EncodeToString(sum[:8]),
		ResponseTimeMs: responseTimeMs,
		Excerpt:        excerpt,
		Truncated:      truncated,
		RawBody:        body,
	}
}

func extractResponseBody(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	start := utils.GetBodyStart(raw)
	if start >= len(raw) {
		return nil
	}
	return raw[start:]
}

// computeDiff compares baseline and replay, sets flags, and writes an
// interpretation hint. Payloads are scanned for verbatim reflection in
// the replay excerpt — reflections past the excerpt cap are missed, so
// callers needing certainty should consult RawBody.
func computeDiff(baseline, replay *Summary, payloads []string) *Diff {
	d := &Diff{
		BaselineStatus: baseline.Status,
		BaselineLen:    baseline.ResponseLen,
		BaselineHash:   baseline.ContentHash,
	}
	if replay.Error != "" {
		d.Interpretation = "replay returned a network error; see replay.error"
		return d
	}
	d.StatusChanged = replay.Status != baseline.Status
	d.LengthDelta = replay.ResponseLen - baseline.ResponseLen
	d.ContentChanged = replay.ContentHash != baseline.ContentHash

	for _, p := range payloads {
		if p == "" {
			continue
		}
		if strings.Contains(replay.Excerpt, p) {
			d.ReflectsPayload = append(d.ReflectsPayload, p)
		}
	}

	switch {
	case len(d.ReflectsPayload) > 0:
		d.Interpretation = "payload reflected verbatim in response body — likely candidate for XSS / template injection / SSRF reflection; verify context."
	case d.StatusChanged && replay.Status >= 500:
		d.Interpretation = "server error after mutation — possible injection causing exception; inspect excerpt for stack trace / error message."
	case d.StatusChanged:
		d.Interpretation = fmt.Sprintf("status changed %d → %d; possible auth/logic effect.", baseline.Status, replay.Status)
	case d.ContentChanged && abs(d.LengthDelta) > 64:
		d.Interpretation = "response content materially different from baseline; worth manual inspection."
	case d.ContentChanged:
		d.Interpretation = "response content differs in small ways from baseline (formatting / timestamps / nonces typical)."
	default:
		d.Interpretation = "response identical to baseline; payload likely did not take effect."
	}
	return d
}

func clipBytes(b []byte, limit int) (string, bool) {
	if len(b) <= limit {
		return string(b), false
	}
	return string(b[:limit]), true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
