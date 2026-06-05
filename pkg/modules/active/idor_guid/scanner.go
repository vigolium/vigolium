package idor_guid

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
)

// uuidPattern matches standard UUID format (8-4-4-4-12 hex digits).
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// idParamNames are parameter name substrings that suggest object references.
var idParamNames = []string{
	"id", "uuid", "guid", "user_id", "userid", "account_id", "accountid",
	"order_id", "orderid", "item_id", "itemid", "object_id", "objectid",
	"resource_id", "resourceid", "record_id", "recordid", "ref", "key",
	"customer_id", "customerid", "session_id", "sessionid", "token",
	"doc_id", "docid", "file_id", "fileid", "asset_id", "assetid",
}

// Module implements the IDOR GUID Predictability active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new IDOR GUID Predictability module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("idor_guid"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests for predictable GUID/UUID patterns and sequential integer IDs.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	paramValue := ip.BaseValue()
	paramName := ip.Name()

	// Only test parameters that plausibly carry an object reference.
	if !qualifiesAsIDORCandidate(ip, paramName, paramValue) {
		return nil, nil
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, paramValue, paramType) {
			return nil, nil
		}
	}

	// Get baseline response info
	var baselineBody string
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineStatus = ctx.Response().StatusCode()
	}

	var results []*output.ResultEvent

	// Branch 1: UUIDv1 detection
	if uuidPattern.MatchString(paramValue) {
		if isUUIDv1(paramValue) {
			neighbors := generateUUIDv1Neighbors(paramValue)
			for _, neighbor := range neighbors {
				result, err := m.tryPredictedID(ctx, ip, httpClient, urlx.String(), paramName, neighbor, baselineBody, baselineStatus, "UUIDv1 time-neighbor")
				if err != nil {
					if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
						return results, nil
					}
					continue
				}
				if result != nil {
					results = append(results, result)
					return results, nil
				}
			}
		}
		return results, nil
	}

	// Branch 2: Sequential numeric ID detection
	if isNumeric(paramValue) {
		numVal, err := strconv.ParseInt(paramValue, 10, 64)
		if err != nil {
			return results, nil
		}
		for _, delta := range []int64{-1, 1} {
			neighbor := strconv.FormatInt(numVal+delta, 10)
			result, tryErr := m.tryPredictedID(ctx, ip, httpClient, urlx.String(), paramName, neighbor, baselineBody, baselineStatus, "sequential integer")
			if tryErr != nil {
				if errors.Is(tryErr, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}
			if result != nil {
				results = append(results, result)
				return results, nil
			}
		}
	}

	return results, nil
}

// tryPredictedID sends a request with a predicted ID and evaluates whether it
// indicates access to a different valid resource.
func (m *Module) tryPredictedID(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	urlStr string,
	paramName string,
	predictedID string,
	baselineBody string,
	baselineStatus int,
	technique string,
) (*output.ResultEvent, error) {
	fuzzedRaw := ip.BuildRequest([]byte(predictedID))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	respBody := resp.Body().String()
	respStatus := resp.Response().StatusCode

	// A finding is reported when:
	// 1. The predicted ID returns 200 OK
	// 2. The response body length > 100 (not empty/trivial)
	// 3. The status matches the original but body content differs (different resource)
	if respStatus == 200 && len(respBody) > 100 && respStatus == baselineStatus && respBody != baselineBody {
		// Content gate: a predicted-id response that is itself a login / SSO
		// challenge (or an access-denied notice) is NOT a distinct object — it is
		// the generic unauthenticated shell every protected endpoint returns, and
		// it "differs from the baseline" only by the per-request CSRF/session
		// tokens (session_code, KC_RESTART, …) the login form embeds. This is the
		// Keycloak /openid-connect/auth false positive: the predicted id returned
		// the same Sign-In page with a fresh nonce. Reject before the (more
		// expensive) determinism refetch.
		if authzutil.IsAuthChallengePage(respBody) {
			return nil, nil
		}

		// Determinism gate: many endpoints (analytics beacons, randomized JS
		// bundles) return different content on every request regardless of the
		// id, so a predicted-id response that "differs from the baseline" is just
		// per-request noise, not a real object reference. Re-issue the ORIGINAL id
		// a couple of times and keep the finding only when the predicted-id
		// difference exceeds the endpoint's own same-id variation. Fail open
		// (keep) if the refetch could not run.
		verdict := modkit.ConfirmCrossIDDifferential(
			httpClient,
			ctx.Service(),
			ip.BuildRequest([]byte(ip.BaseValue())),
			baselineBody,
			baselineStatus,
			respBody,
			modkit.CrossIDConfig{},
		)
		if verdict.Ran && !verdict.Trustworthy {
			return nil, nil
		}

		return &output.ResultEvent{
			URL:              urlStr,
			Matched:          urlStr,
			Request:          string(fuzzedRaw),
			Response:         resp.FullResponseString(),
			FuzzingParameter: paramName,
			ExtractedResults: []string{fmt.Sprintf("technique=%s predicted_id=%s", technique, predictedID)},
			Info: output.Info{
				Name:        fmt.Sprintf("IDOR GUID Predictability: %s", technique),
				Description: fmt.Sprintf("Predicted identifier %q injected into parameter %q returned a valid different resource, indicating predictable object references", predictedID, paramName),
			},
		}, nil
	}

	return nil, nil
}

// isUUIDv1 checks if a UUID string is version 1 (the 13th character is '1').
func isUUIDv1(uuid string) bool {
	// UUID format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx
	// The version nibble V is at index 14 (after two hyphens at index 8 and 13).
	clean := strings.ReplaceAll(uuid, "-", "")
	if len(clean) != 32 {
		return false
	}
	// Version nibble is the 13th hex digit (0-indexed: position 12)
	return clean[12] == '1'
}

// generateUUIDv1Neighbors extracts the timestamp from a UUIDv1 and generates
// neighbor UUIDs by incrementing/decrementing the timestamp by small amounts.
func generateUUIDv1Neighbors(uuid string) []string {
	clean := strings.ReplaceAll(uuid, "-", "")
	if len(clean) != 32 {
		return nil
	}

	// UUIDv1 field layout (hex chars in the clean 32-char string):
	// time_low:                chars 0-7   (8 hex chars)
	// time_mid:                chars 8-11  (4 hex chars)
	// time_hi_and_version:     chars 12-15 (4 hex chars, first nibble is version)
	// clock_seq_hi_and_res:    chars 16-17 (2 hex chars)
	// clock_seq_low:           chars 18-19 (2 hex chars)
	// node:                    chars 20-31 (12 hex chars)

	timeLowHex := clean[0:8]
	timeMidHex := clean[8:12]
	timeHiHex := clean[12:16]
	suffix := clean[16:32] // clock_seq + node (preserved as-is)

	timeLow, err := strconv.ParseUint(timeLowHex, 16, 32)
	if err != nil {
		return nil
	}
	timeMid, err := strconv.ParseUint(timeMidHex, 16, 16)
	if err != nil {
		return nil
	}
	timeHiRaw, err := strconv.ParseUint(timeHiHex, 16, 16)
	if err != nil {
		return nil
	}

	// Mask off the version nibble (top 4 bits) from time_hi
	timeHi := timeHiRaw & 0x0FFF

	// Reconstruct the 60-bit timestamp:
	// timestamp = time_low | (time_mid << 32) | (time_hi << 48)
	timestamp := timeLow | (timeMid << 32) | (timeHi << 48)

	var neighbors []string
	for delta := int64(-5); delta <= 5; delta++ {
		if delta == 0 {
			continue
		}
		newTS := int64(timestamp) + delta
		if newTS < 0 {
			continue
		}
		ts := uint64(newTS)

		newTimeLow := ts & 0xFFFFFFFF
		newTimeMid := (ts >> 32) & 0xFFFF
		newTimeHi := (ts >> 48) & 0x0FFF
		// Re-apply version nibble (1 = UUIDv1)
		newTimeHiVersion := newTimeHi | 0x1000

		newClean := fmt.Sprintf("%08x%04x%04x%s", newTimeLow, newTimeMid, newTimeHiVersion, suffix)

		// Reconstruct the dashed UUID format
		newUUID := fmt.Sprintf("%s-%s-%s-%s-%s",
			newClean[0:8], newClean[8:12], newClean[12:16], newClean[16:20], newClean[20:32])

		neighbors = append(neighbors, newUUID)
	}

	return neighbors
}

// qualifiesAsIDORCandidate reports whether an insertion point plausibly carries
// an enumerable object reference worth predicting neighbors for.
//
// It exists to suppress the broad class of false positives where a non-object
// value happens to look numeric or UUID-shaped:
//   - Standard request headers (Upgrade-Insecure-Requests, DNT, Sec-Fetch-*,
//     Cache-Control, …) carry flag/protocol values that address nothing, so a
//     predicted "neighbor" just re-fetches the same page. A header only
//     qualifies when its NAME names an identifier (X-User-Id, Account-Id, …).
//   - A bare flag value (0 or 1) on a non-ID-named parameter is a boolean
//     toggle, not an enumerable identifier.
func qualifiesAsIDORCandidate(ip httpmsg.InsertionPoint, name, value string) bool {
	idNamed := isIDRelatedParam(name)

	// Request headers are object references only when the header name says so.
	if ip.Type() == httpmsg.INS_HEADER && !idNamed {
		return false
	}

	// An ID-named parameter is always worth testing, whatever the value shape.
	if idNamed {
		return true
	}

	// Otherwise the VALUE must itself look like an object reference: a UUID, or a
	// numeric id whose magnitude is plausible for an identifier (not a flag).
	if uuidPattern.MatchString(value) {
		return true
	}
	return isNumeric(value) && !isFlagValue(value)
}

// isFlagValue reports whether a numeric string is a boolean/flag value (0 or 1)
// rather than an enumerable object identifier.
func isFlagValue(s string) bool {
	return s == "0" || s == "1"
}

// isIDRelatedParam checks if a parameter name suggests an object reference.
func isIDRelatedParam(name string) bool {
	nameLower := strings.ToLower(name)
	for _, p := range idParamNames {
		if strings.Contains(nameLower, p) {
			return true
		}
	}
	return false
}

// isNumeric checks if a string represents a numeric value.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}
