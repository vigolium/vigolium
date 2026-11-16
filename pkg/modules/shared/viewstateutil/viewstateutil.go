// Package viewstateutil checks an ASP.NET __VIEWSTATE's MAC against known
// machineKey validation keys, offline. It is shared by the passive
// aspnet-viewstate-detect module and `vigolium kit viewstate-crack`, so the two
// cannot drift.
//
// Covered: the legacy (pre-4.5) MAC, which ASP.NET computes when the
// application does not run the 4.5 crypto stack (no
// <httpRuntime targetFramework="4.5"/> and no
// <machineKey compatibilityMode="Framework45"/>). Per the .NET reference source
// (System.Web/UI/ObjectStateFormatter.cs Deserialize and GetMacKeyModifier,
// System.Web/Configuration/MachineKeySection.cs GetDecodedData, HashData,
// GetHMACSHA1Hash, HashDataUsingKeyedAlgorithm and
// InitValidationAndEncyptionSizes), the field is
//
//	base64( serialized || HMAC-H(validationKey, serialized || modifier) )
//
// where H follows the configured validation: SHA1 (also the validation used
// when validation is AES or 3DES) is HMAC-SHA1, and HMACSHA256/384/512 are
// those HMACs. The modifier is the page's client-state identifier as four
// little-endian bytes; the page publishes it as __VIEWSTATEGENERATOR, the
// identifier formatted "X8". ASP.NET's HMAC pads the key to the hash block
// size (64 bytes for SHA-1/256, 128 for SHA-384/512), which is standard HMAC
// for keys no longer than the block.
//
// Not covered, and never reported as checked:
//   - the 4.5+ purpose-based MAC (AspNetCryptoServiceProvider), whose keys are
//     derived per purpose with SP800-108 from the page's directory and type
//     name;
//   - validation="MD5", whose digest the reference source delegates to a native
//     helper (UnsafeNativeMethods.GetSHA1Hash with a 16-byte output) that cannot
//     be checked from the managed source;
//   - a page that sets ViewStateUserKey, which appends that per-user string to
//     the modifier;
//   - an encrypted ViewState (legacy ViewStateEncryptionMode, or validation
//     AES/3DES with encryption on): its bytes are ciphertext, not the
//     serialized stream.
package viewstateutil

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // ASP.NET's legacy ViewState MAC is HMAC-SHA1; verifying it needs SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// Algorithm is one legacy validation algorithm: the machineKey validation
// names that select it and its HMAC.
type Algorithm struct {
	// Name is the machineKey validation value reported for a match.
	Name    string
	newHash func() hash.Hash
}

// LegacyAlgorithms are the keyed validations the legacy MAC uses, in the order
// they are tried. SHA1 also stands for validation="AES" and "3DES", which
// validate with HMAC-SHA1.
var LegacyAlgorithms = []Algorithm{
	{Name: "SHA1", newHash: sha1.New},
	{Name: "HMACSHA256", newHash: sha256.New},
	{Name: "HMACSHA384", newHash: sha512.New384},
	{Name: "HMACSHA512", newHash: sha512.New},
}

// MachineKey is a published validation key and where it was published.
type MachineKey struct {
	ValidationKey []byte
	Source        string
}

// Hex is the validation key as web.config writes it: uppercase hex.
func (k MachineKey) Hex() string {
	return strings.ToUpper(hex.EncodeToString(k.ValidationKey))
}

// publishedKeysList is the embedded list of published validation keys.
const publishedKeysList = "aspnet.machinekeys.list"

// PublishedKeys returns the embedded published-key list (aspnet.machinekeys.list),
// parsed once. The slice is shared: callers must not modify it, and a caller
// adding its own keys appends to a copy (slices.Clip).
var PublishedKeys = sync.OnceValues(func() ([]MachineKey, error) {
	data, err := wordlists.WordlistsFS.ReadFile(publishedKeysList)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", publishedKeysList, err)
	}
	keys, err := ParseMachineKeys(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", publishedKeysList, err)
	}
	return keys, nil
})

// Match is a key that reproduces a ViewState's MAC.
type Match struct {
	Key       MachineKey
	Algorithm string
}

// ParseMachineKeys reads a key list: one key per line as hex, optionally
// followed by whitespace and the key's source; blank lines and lines starting
// with '#' are skipped. A line whose key is not hex is an error, so a bad
// embedded list fails its test instead of silently shrinking.
func ParseMachineKeys(data []byte) ([]MachineKey, error) {
	var keys []MachineKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		key, err := ParseKeyHex(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		keys = append(keys, MachineKey{ValidationKey: key, Source: strings.Join(fields[1:], " ")})
	}
	return keys, sc.Err()
}

// ParseKeyHex decodes a validationKey as written in web.config. An
// "AutoGenerate" value is not a key.
func ParseKeyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	key, err := hex.DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("validation key %q is not hex", textutil.TruncateRunesEllipsis(s, 16, "…"))
	}
	return key, nil
}

// GeneratorModifier turns a __VIEWSTATEGENERATOR value (the client-state
// identifier as eight hex digits) into the four little-endian modifier bytes
// the MAC covers.
func GeneratorModifier(generator string) ([]byte, error) {
	generator = strings.TrimSpace(generator)
	raw, err := hex.DecodeString(generator)
	if err != nil || len(raw) != 4 {
		return nil, fmt.Errorf("__VIEWSTATEGENERATOR %q is not eight hex digits", textutil.TruncateRunesEllipsis(generator, 16, "…"))
	}
	mod := make([]byte, 4)
	binary.LittleEndian.PutUint32(mod, binary.BigEndian.Uint32(raw))
	return mod, nil
}

// DecodeViewState base64-decodes a __VIEWSTATE value as ASP.NET does
// (standard alphabet, padded). A URL-encoded value must be unescaped first.
func DecodeViewState(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(value))
}

// IsSerialized reports whether decoded starts with the ObjectStateFormatter
// header (0xFF, then format version 0x01): the bytes are the plain serialized
// stream, not ciphertext.
func IsSerialized(decoded []byte) bool {
	return len(decoded) > 2 && decoded[0] == 0xFF && decoded[1] == 0x01
}

// HasSerializedHeader reports whether a __VIEWSTATE value's first base64
// quantum decodes to the ObjectStateFormatter header (0xFF 0x01), without
// decoding the whole value. It is a necessary condition for IsSerialized on
// DecodeViewState's result, so a false answer skips the full decode of an
// encrypted ViewState.
func HasSerializedHeader(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return false
	}
	var head [3]byte
	n, err := base64.StdEncoding.Decode(head[:], []byte(value[:4]))
	return err == nil && n >= 2 && head[0] == 0xFF && head[1] == 0x01
}

// LegacyMAC computes the legacy ViewState MAC of serialized under key.
func LegacyMAC(alg Algorithm, key, serialized, modifier []byte) []byte {
	mac := hmac.New(alg.newHash, key)
	mac.Write(serialized)
	mac.Write(modifier)
	return mac.Sum(nil)
}

// CrackLegacy returns the first key and algorithm whose legacy MAC matches the
// trailing bytes of decoded. decoded must be a serialized (unencrypted)
// ViewState; ok is false for anything else or when no key matches. A key
// longer than the algorithm's block is skipped: ASP.NET's own HMAC set-up
// does not hash such a key the way standard HMAC does.
func CrackLegacy(decoded, modifier []byte, keys []MachineKey) (Match, bool) {
	if !IsSerialized(decoded) {
		return Match{}, false
	}
	for _, alg := range LegacyAlgorithms {
		h := alg.newHash()
		size, block := h.Size(), h.BlockSize()
		if len(decoded) <= size+2 {
			continue
		}
		serialized, tag := decoded[:len(decoded)-size], decoded[len(decoded)-size:]
		for _, k := range keys {
			if len(k.ValidationKey) > block {
				continue
			}
			if hmac.Equal(LegacyMAC(alg, k.ValidationKey, serialized, modifier), tag) {
				return Match{Key: k, Algorithm: alg.Name}, true
			}
		}
	}
	return Match{}, false
}
