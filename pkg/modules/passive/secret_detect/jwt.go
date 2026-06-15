package secret_detect

import "github.com/vigolium/vigolium/pkg/modules/shared/jwtutil"

// LowValueJWT reports whether the matched secret snippet is a JWT that we cannot
// confirm carries authenticated-credential material — either it does not decode
// as a JWT, or it decodes to a pre-authentication / metadata token (e.g. a
// Cloudflare Access SSO "meta" token). Such tokens are downgraded to
// Medium/Tentative because they are not usable secrets, while a JWT we can decode
// and confirm is a live credential keeps the baseline High/Firm.
//
// Returns false for non-JWT snippets (e.g. an AWS key), so the downgrade is
// scoped to JWT findings only. The JWT classification itself lives in the shared
// jwtutil package so the JWT-analysis modules (jwt_claims_detect, jwt_weak_secret)
// recognise the same pre-auth/meta tokens.
func LowValueJWT(snippet string) bool {
	return jwtutil.IsLowValue(snippet)
}

// ClassifyJWTSnippet reports whether a matched secret snippet is structurally a
// JWT and, if so, whether its decoded payload carries authenticated-credential
// material. See jwtutil.Classify.
func ClassifyJWTSnippet(snippet string) (isJWT, sensitive bool) {
	return jwtutil.Classify(snippet)
}
