package viewstateutil

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // the legacy ViewState MAC under test is HMAC-SHA1.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// msDocsKey is the validationKey Microsoft's protected-configuration
// walkthrough publishes (dtkwfdky).
const msDocsKey = "D61B3C89CB33A2F1422FF158AFF7320E8DB8CB5CDA1742572A487D94018787EF42682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"

// serializedSample is an ObjectStateFormatter stream: header 0xFF 0x01, then a
// Pair (0x0F) of an Int32 (0x02 + 7-bit varint) and a null (0x64).
var serializedSample = []byte{0xFF, 0x01, 0x0F, 0x02, 0x96, 0x01, 0x64}

// signViewState builds a __VIEWSTATE the way ASP.NET's legacy path does
// (MachineKeySection.GetEncodedData): serialized || HMAC(key, serialized ||
// modifier), base64. It concatenates by hand rather than calling LegacyMAC,
// so the test does not check the code against itself.
func signViewState(t *testing.T, newHash func() hash.Hash, keyHex string, modifier []byte) string {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	input := append(append([]byte{}, serializedSample...), modifier...)
	mac := hmac.New(newHash, key)
	mac.Write(input)
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, serializedSample...), mac.Sum(nil)...))
}

func TestGeneratorModifierIsLittleEndian(t *testing.T) {
	t.Parallel()
	mod, err := GeneratorModifier("CA0B0334")
	require.NoError(t, err)
	assert.Equal(t, []byte{0x34, 0x03, 0x0B, 0xCA}, mod)

	for _, bad := range []string{"", "CA0B03", "ZZ0B0334", "CA0B033412"} {
		_, err := GeneratorModifier(bad)
		assert.Error(t, err, bad)
	}
}

// LegacyMAC is standard HMAC over serialized || modifier: RFC 4231 test case 1
// (key 0x0b x20, data "Hi There") pins the HMAC-SHA256 output.
func TestLegacyMACKnownAnswer(t *testing.T) {
	t.Parallel()
	alg := LegacyAlgorithms[1]
	require.Equal(t, "HMACSHA256", alg.Name)
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	got := LegacyMAC(alg, key, []byte("Hi "), []byte("There"))
	assert.Equal(t, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hex.EncodeToString(got))
}

func TestCrackLegacyEveryAlgorithm(t *testing.T) {
	t.Parallel()
	keys, err := ParseMachineKeys([]byte(msDocsKey + " Microsoft Docs example\n"))
	require.NoError(t, err)
	modifier, err := GeneratorModifier("CA0B0334")
	require.NoError(t, err)

	for _, tc := range []struct {
		alg     string
		newHash func() hash.Hash
	}{
		{"SHA1", sha1.New}, {"HMACSHA256", sha256.New}, {"HMACSHA384", sha512.New384}, {"HMACSHA512", sha512.New},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()
			decoded, err := DecodeViewState(signViewState(t, tc.newHash, msDocsKey, modifier))
			require.NoError(t, err)
			m, ok := CrackLegacy(decoded, modifier, keys)
			require.True(t, ok)
			assert.Equal(t, tc.alg, m.Algorithm)
			assert.Equal(t, "Microsoft Docs example", m.Key.Source)

			// The modifier is part of the MAC: another page's generator misses.
			other, _ := GeneratorModifier("00000001")
			_, ok = CrackLegacy(decoded, other, keys)
			assert.False(t, ok, "a different __VIEWSTATEGENERATOR must not match")
		})
	}
}

func TestCrackLegacyMisses(t *testing.T) {
	t.Parallel()
	keys, err := ParseMachineKeys([]byte(msDocsKey + " docs\n"))
	require.NoError(t, err)
	modifier, _ := GeneratorModifier("CA0B0334")

	unlisted := "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
	decoded, _ := DecodeViewState(signViewState(t, sha256.New, unlisted, modifier))
	_, ok := CrackLegacy(decoded, modifier, keys)
	assert.False(t, ok, "a ViewState signed with an unlisted key must not match")

	// Ciphertext (no 0xFF 0x01 header) is never checked.
	_, ok = CrackLegacy([]byte{0x12, 0x34, 0x56, 0x78, 0x9a}, modifier, keys)
	assert.False(t, ok)
	// A MAC-less ViewState (EnableViewStateMac=false) has nothing to match.
	_, ok = CrackLegacy(serializedSample, modifier, keys)
	assert.False(t, ok)
}

func TestParseMachineKeys(t *testing.T) {
	t.Parallel()
	keys, err := ParseMachineKeys([]byte("# comment\n\nAABB first source\nCCDD\n"))
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, []byte{0xAA, 0xBB}, keys[0].ValidationKey)
	assert.Equal(t, "first source", keys[0].Source)
	assert.Empty(t, keys[1].Source)

	_, err = ParseMachineKeys([]byte("AutoGenerate,IsolateApps\n"))
	assert.Error(t, err, "a non-hex key is an error, not a skipped line")
	_, err = ParseMachineKeys([]byte("ABC odd length\n"))
	assert.Error(t, err)
}

// The embedded list parses, every key has a source, and it carries the
// Microsoft Docs example.
func TestEmbeddedMachineKeyList(t *testing.T) {
	t.Parallel()
	keys, err := PublishedKeys()
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	found := false
	for _, k := range keys {
		assert.NotEmpty(t, k.Source, "every embedded key names its source")
		if k.Hex() == msDocsKey {
			found = true
		}
	}
	assert.True(t, found)
}

// HasSerializedHeader agrees with IsSerialized on the decoded value: whatever
// type token follows FF 01 (it moves the third base64 character through E-H).
func TestHasSerializedHeader(t *testing.T) {
	t.Parallel()
	for _, raw := range [][]byte{
		{0xFF, 0x01, 0x0F, 0x02}, {0xFF, 0x01, 0x64, 0x00}, {0xFF, 0x01, 0xA0}, {0xFF, 0x01, 0xC8, 0x01},
		{0x12, 0x34, 0x56, 0x78}, {0xFF, 0x02, 0x0F}, {0xFF, 0x01},
	} {
		vs := base64.StdEncoding.EncodeToString(raw)
		decoded, err := DecodeViewState(vs)
		require.NoError(t, err)
		if IsSerialized(decoded) {
			assert.True(t, HasSerializedHeader(" "+vs+" "), vs)
		}
		assert.Equal(t, len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0x01, HasSerializedHeader(vs), vs)
	}
	assert.False(t, HasSerializedHeader("/w"))
	assert.False(t, HasSerializedHeader("not base64!"))
}
