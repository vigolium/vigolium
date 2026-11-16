package cli

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // the legacy ViewState MAC under test is HMAC-SHA1.
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kitTestViewState signs a serialized ViewState with HMAC-SHA1 over
// serialized || generator (4 LE bytes), as ASP.NET's legacy MAC does.
func kitTestViewState(t *testing.T, keyHex string, modifier []byte) string {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	serialized := []byte{0xFF, 0x01, 0x0F, 0x02, 0x96, 0x01, 0x64}
	mac := hmac.New(sha1.New, key)
	mac.Write(serialized)
	mac.Write(modifier)
	return base64.StdEncoding.EncodeToString(append(serialized, mac.Sum(nil)...))
}

const kitMSDocsKey = "D61B3C89CB33A2F1422FF158AFF7320E8DB8CB5CDA1742572A487D94018787EF42682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"

func TestKitViewStateCrackEmbeddedKey(t *testing.T) {
	swapGlobal(t, &kitViewStateGenerator, "CA0B0334")
	swapGlobal(t, &kitViewStateKeys, nil)
	swapGlobal(t, &kitViewStateFailOnCrack, false)
	vs := kitTestViewState(t, kitMSDocsKey, []byte{0x34, 0x03, 0x0B, 0xCA})

	doc := emitCaptured(t, func() error { return runKitViewStateCrack(kitViewStateCrackCmd, []string{vs}) })
	items := requireEnvelope(t, doc, "kit viewstate-crack", "read")
	require.Len(t, items, 1)
	res := items[0].(map[string]any)
	assert.Equal(t, true, res["cracked"])
	assert.Equal(t, "SHA1", res["algorithm"])
	assert.Equal(t, kitMSDocsKey, res["validation_key"])
	assert.Contains(t, res["key_source"], "Microsoft Docs")
	assert.Equal(t, "legacy", res["mac_mode"])
}

func TestKitViewStateCrackInlineKeyAndMiss(t *testing.T) {
	inline := "00112233445566778899AABBCCDDEEFF00112233"
	swapGlobal(t, &kitViewStateGenerator, "0000ABCD")
	swapGlobal(t, &kitViewStateFailOnCrack, true)
	vs := kitTestViewState(t, inline, []byte{0xCD, 0xAB, 0x00, 0x00})

	swapGlobal(t, &kitViewStateKeys, nil)
	doc := emitCaptured(t, func() error { return runKitViewStateCrack(kitViewStateCrackCmd, []string{vs}) })
	res := requireEnvelope(t, doc, "kit viewstate-crack", "read")[0].(map[string]any)
	assert.Equal(t, false, res["cracked"], "an unlisted key is not recovered")
	assert.Equal(t, true, res["serialized"])

	swapGlobal(t, &kitViewStateKeys, []string{inline})
	var runErr error
	doc = emitCaptured(t, func() error {
		runErr = runKitViewStateCrack(kitViewStateCrackCmd, []string{vs})
		return nil
	})
	res = requireEnvelope(t, doc, "kit viewstate-crack", "read")[0].(map[string]any)
	assert.Equal(t, true, res["cracked"])
	assert.Equal(t, "--validation-key", res["key_source"])
	var match matchError
	assert.ErrorAs(t, runErr, &match, "--fail-on-crack reports the match through the exit status")
}

func TestKitViewStateCrackUsageErrors(t *testing.T) {
	swapGlobal(t, &kitViewStateKeys, nil)
	swapGlobal(t, &kitViewStateGenerator, "")
	assert.Error(t, runKitViewStateCrack(kitViewStateCrackCmd, []string{"/wEPDwUKLTEyMzQ1Njc4ZGQ="}), "--generator is required")
	swapGlobal(t, &kitViewStateGenerator, "XYZ")
	assert.Error(t, runKitViewStateCrack(kitViewStateCrackCmd, []string{"/wEPDwUKLTEyMzQ1Njc4ZGQ="}))
	swapGlobal(t, &kitViewStateGenerator, "CA0B0334")
	assert.Error(t, runKitViewStateCrack(kitViewStateCrackCmd, []string{"not base64!"}))
}
