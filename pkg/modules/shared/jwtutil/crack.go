package jwtutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"sync/atomic"
)

// dictionaryPasses counts full wordlist passes (tests assert the length gate).
var dictionaryPasses atomic.Int64

// CrackHMAC attempts to recover the HMAC signing secret of a compact JWT by
// trying each candidate in secrets against the token's signature. It is the
// single implementation shared by the jwt_weak_secret scanner module and the
// `vigolium kit jwt-crack` utility, so the two cannot drift.
//
// For an HS256/384/512 token the matching hash is tried. For a token that
// declares an asymmetric algorithm (RS*/ES*/PS*) every HMAC variant is tried —
// the algorithm-confusion attack (CVE-2015-9235), where a server that expects
// to verify an RSA/EC signature with a public key can be tricked into verifying
// an HMAC signature keyed by that public key — and the returned alg label notes
// which HMAC variant matched. Returns ok=false when no candidate matches or the
// token is malformed / uses an unsupported algorithm.
func CrackHMAC(token string, secrets [][]byte) (secret string, alg string, ok bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", false
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return "", "", false
	}

	type hashVariant struct {
		newHash func() hash.Hash
		label   string
	}
	var variants []hashVariant
	switch hdr.Alg {
	case "HS256":
		variants = []hashVariant{{sha256.New, "HS256"}}
	case "HS384":
		variants = []hashVariant{{sha512.New384, "HS384"}}
	case "HS512":
		variants = []hashVariant{{sha512.New, "HS512"}}
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
		variants = []hashVariant{
			{sha256.New, fmt.Sprintf("%s (alg-confusion: tested as HS256)", hdr.Alg)},
			{sha512.New384, fmt.Sprintf("%s (alg-confusion: tested as HS384)", hdr.Alg)},
			{sha512.New, fmt.Sprintf("%s (alg-confusion: tested as HS512)", hdr.Alg)},
		}
	default:
		return "", "", false
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", false
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	for _, v := range variants {
		// An HMAC tag is exactly hash.Size() bytes. A signature of any other
		// length can never match, so the whole dictionary pass is skipped —
		// which is every genuine RS*/PS* token (256+ byte signatures) and every
		// ES* token outside the one same-size variant. Before, each such token
		// cost 3 x the wordlist in HMACs for a guaranteed miss.
		if v.newHash().Size() != len(signature) {
			continue
		}
		dictionaryPasses.Add(1)
		for _, cand := range secrets {
			mac := hmac.New(v.newHash, cand)
			mac.Write(signingInput)
			if hmac.Equal(mac.Sum(nil), signature) {
				return string(cand), v.label, true
			}
		}
	}
	return "", "", false
}
