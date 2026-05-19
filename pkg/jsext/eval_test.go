package jsext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEval_BasicExpression(t *testing.T) {
	result := Eval("1 + 2", APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, "3", result.Value)
}

func TestEval_StringExpression(t *testing.T) {
	result := Eval(`"hello" + " " + "world"`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, `"hello world"`, result.Value)
}

func TestEval_ObjectExpression(t *testing.T) {
	result := Eval(`({a: 1, b: "two"})`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, `{"a":1,"b":"two"}`, result.Value)
}

func TestEval_LogInfo(t *testing.T) {
	// vigolium.log.info should not crash
	result := Eval(`vigolium.log.info("hello from eval")`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Empty(t, result.Value) // log calls return undefined
}

func TestEval_UtilsBase64Encode(t *testing.T) {
	result := Eval(`vigolium.utils.base64Encode("test")`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, `"dGVzdA=="`, result.Value)
}

func TestEval_UtilsMD5(t *testing.T) {
	result := Eval(`vigolium.utils.md5("hello")`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, `"5d41402abc4b2a76b9719d911017c592"`, result.Value)
}

func TestEval_ScriptError(t *testing.T) {
	result := Eval(`throw new Error("boom")`, APIOptions{})
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "boom")
}

func TestEval_SyntaxError(t *testing.T) {
	result := Eval(`if (`, APIOptions{})
	require.Error(t, result.Error)
}

func TestEval_EmptySource(t *testing.T) {
	result := Eval("", APIOptions{})
	require.NoError(t, result.Error)
	assert.Empty(t, result.Value)
}

func TestEval_UndefinedReturn(t *testing.T) {
	result := Eval(`var x = 42;`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Empty(t, result.Value)
}

func TestEval_NullReturn(t *testing.T) {
	result := Eval(`null`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Empty(t, result.Value)
}

func TestEval_ConfigVars(t *testing.T) {
	result := Eval(`vigolium.config.myKey`, APIOptions{
		ConfigVars: map[string]string{"myKey": "myVal"},
	})
	require.NoError(t, result.Error)
	assert.Equal(t, `"myVal"`, result.Value)
}

func TestEval_MultiStatement(t *testing.T) {
	result := Eval(`
		var a = vigolium.utils.base64Encode("foo");
		var b = vigolium.utils.base64Decode(a);
		b
	`, APIOptions{})
	require.NoError(t, result.Error)
	assert.Equal(t, `"foo"`, result.Value)
}
