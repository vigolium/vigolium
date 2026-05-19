package authzutil

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyParamName_HighSignal(t *testing.T) {
	tests := []string{"id", "user_id", "userId", "account_id", "accountId", "order_id"}
	for _, name := range tests {
		signal, score := ClassifyParamName(name)
		assert.Equal(t, HighSignal, signal, "name=%q", name)
		assert.Equal(t, 3, score, "name=%q", name)
	}
}

func TestClassifyParamName_MediumSignal(t *testing.T) {
	tests := []string{"num", "ref", "key", "token", "uuid", "guid"}
	for _, name := range tests {
		signal, score := ClassifyParamName(name)
		assert.Equal(t, MediumSignal, signal, "name=%q", name)
		assert.Equal(t, 2, score, "name=%q", name)
	}
}

func TestClassifyParamName_SuffixPattern(t *testing.T) {
	tests := []string{"item_id", "itemId", "custom_ID", "fooId"}
	for _, name := range tests {
		signal, score := ClassifyParamName(name)
		assert.Equal(t, HighSignal, signal, "name=%q", name)
		assert.Equal(t, 3, score, "name=%q", name)
	}
}

func TestClassifyParamName_NoSignal(t *testing.T) {
	tests := []string{"page", "limit", "sort", "format", "callback", "q"}
	for _, name := range tests {
		signal, score := ClassifyParamName(name)
		assert.Equal(t, NoSignal, signal, "name=%q", name)
		assert.Equal(t, 0, score, "name=%q", name)
	}
}

func TestClassifyParamValue_SequentialInt(t *testing.T) {
	idType, pred, score := ClassifyParamValue("12345")
	assert.Equal(t, SequentialInt, idType)
	assert.Equal(t, PredictVeryHigh, pred)
	assert.Equal(t, 3, score)
}

func TestClassifyParamValue_SmallInt(t *testing.T) {
	idType, pred, score := ClassifyParamValue("42")
	assert.Equal(t, SequentialInt, idType)
	assert.Equal(t, PredictVeryHigh, pred)
	assert.Equal(t, 3, score)
}

func TestClassifyParamValue_StructuredCode(t *testing.T) {
	idType, pred, score := ClassifyParamValue("ORD-12345")
	assert.Equal(t, StructuredCode, idType)
	assert.Equal(t, PredictHigh, pred)
	assert.Equal(t, 3, score)
}

func TestClassifyParamValue_StructuredCodeWithSuffix(t *testing.T) {
	idType, _, _ := ClassifyParamValue("INV-001-2")
	assert.Equal(t, StructuredCode, idType)
}

func TestClassifyParamValue_Base64Int(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("12345"))
	idType, pred, score := ClassifyParamValue(encoded)
	assert.Equal(t, Base64Int, idType)
	assert.Equal(t, PredictHigh, pred)
	assert.Equal(t, 3, score)
}

func TestClassifyParamValue_UUIDv1(t *testing.T) {
	idType, pred, score := ClassifyParamValue("550e8400-e29b-11d4-a716-446655440000")
	assert.Equal(t, UUIDv1, idType)
	assert.Equal(t, PredictMedium, pred)
	assert.Equal(t, 2, score)
}

func TestClassifyParamValue_UUIDv4(t *testing.T) {
	idType, pred, score := ClassifyParamValue("550e8400-e29b-41d4-a716-446655440000")
	assert.Equal(t, UUIDv4, idType)
	assert.Equal(t, PredictLow, pred)
	assert.Equal(t, 1, score)
}

func TestClassifyParamValue_Email(t *testing.T) {
	idType, pred, score := ClassifyParamValue("user@example.com")
	assert.Equal(t, Email, idType)
	assert.Equal(t, PredictMedium, pred)
	assert.Equal(t, 2, score)
}

func TestClassifyParamValue_Hex(t *testing.T) {
	idType, pred, score := ClassifyParamValue("abcdef0123456789abcdef01234567")
	assert.Equal(t, Hex, idType)
	assert.Equal(t, PredictLow, pred)
	assert.Equal(t, 1, score)
}

func TestClassifyParamValue_Unknown(t *testing.T) {
	tests := []string{"", "hello-world", "some text", "true", "false"}
	for _, val := range tests {
		idType, pred, score := ClassifyParamValue(val)
		assert.Equal(t, Unknown, idType, "value=%q", val)
		assert.Equal(t, PredictNone, pred, "value=%q", val)
		assert.Equal(t, 0, score, "value=%q", val)
	}
}

func TestClassifyPathContext_WithResourceNoun(t *testing.T) {
	segments := []string{"", "api", "users", "123", "orders", "456"}

	noun, score := ClassifyPathContext(segments, "123")
	assert.Equal(t, "users", noun)
	assert.Equal(t, 2, score)

	noun, score = ClassifyPathContext(segments, "456")
	assert.Equal(t, "orders", noun)
	assert.Equal(t, 2, score)
}

func TestClassifyPathContext_IDWithoutNoun(t *testing.T) {
	segments := []string{"", "api", "v2", "12345"}
	noun, score := ClassifyPathContext(segments, "12345")
	assert.Equal(t, "", noun)
	assert.Equal(t, 1, score)
}

func TestClassifyPathContext_NoMatch(t *testing.T) {
	segments := []string{"", "api", "v2", "status"}
	noun, score := ClassifyPathContext(segments, "status")
	assert.Equal(t, "", noun)
	assert.Equal(t, 0, score)
}

func TestClassifyPathContext_Empty(t *testing.T) {
	noun, score := ClassifyPathContext(nil, "123")
	assert.Equal(t, "", noun)
	assert.Equal(t, 0, score)

	noun, score = ClassifyPathContext([]string{"", "api"}, "")
	assert.Equal(t, "", noun)
	assert.Equal(t, 0, score)
}

func TestClassifyParam_HighSignalPlusInt(t *testing.T) {
	result := ClassifyParam("user_id", "12345", false, nil)
	assert.True(t, result.IsObjectID)
	assert.Equal(t, SequentialInt, result.IDType)
	assert.Equal(t, HighSignal, result.NameSignal)
	assert.Equal(t, 3, result.NameScore)
	assert.Equal(t, 3, result.ValueScore)
	assert.GreaterOrEqual(t, result.TotalScore, 6)
}

func TestClassifyParam_MediumSignalPlusInt(t *testing.T) {
	result := ClassifyParam("ref", "42", false, nil)
	assert.True(t, result.IsObjectID)
	assert.Equal(t, SequentialInt, result.IDType)
	assert.Equal(t, MediumSignal, result.NameSignal)
	assert.GreaterOrEqual(t, result.TotalScore, 5)
}

func TestClassifyParam_NoSignalNonID(t *testing.T) {
	result := ClassifyParam("page", "next", false, nil)
	assert.False(t, result.IsObjectID)
	assert.Equal(t, 0, result.TotalScore)
}

func TestClassifyParam_PathWithResourceNoun(t *testing.T) {
	segments := []string{"", "api", "users", "123"}
	result := ClassifyParam("1", "123", true, segments)
	assert.True(t, result.IsObjectID)
	assert.Equal(t, "users", result.ResourceNoun)
	assert.Equal(t, 2, result.PathScore)
}

func TestClassifyParam_PathUUID(t *testing.T) {
	segments := []string{"", "api", "orders", "550e8400-e29b-41d4-a716-446655440000"}
	result := ClassifyParam("2", "550e8400-e29b-41d4-a716-446655440000", true, segments)
	assert.True(t, result.IsObjectID)
	assert.Equal(t, UUIDv4, result.IDType)
	assert.Equal(t, "orders", result.ResourceNoun)
}
