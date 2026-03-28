package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCE verifies a PKCE code verifier against a code challenge using the S256 method.
func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" {
		return false
	}
	computed := ComputeS256Challenge(codeVerifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// ComputeS256Challenge computes the S256 PKCE challenge for a given verifier.
func ComputeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
