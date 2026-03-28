package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTClaims represents the claims in our access tokens.
type JWTClaims struct {
	Sub string `json:"sub"` // User ID (SF user ID)
	Aud string `json:"aud"` // Client ID
	Exp int64  `json:"exp"` // Expiration time (Unix)
	Iat int64  `json:"iat"` // Issued at (Unix)
	Jti string `json:"jti"` // Unique token ID
	Iss string `json:"iss"` // Issuer (our server URL)
}

// CreateAccessToken creates a signed JWT access token.
func CreateAccessToken(signingKey []byte, userID, clientID, issuer string, ttl time.Duration) (string, error) {
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := JWTClaims{
		Sub: userID,
		Aud: clientID,
		Exp: now.Add(ttl).Unix(),
		Iat: now.Unix(),
		Jti: jti,
		Iss: issuer,
	}

	return signJWT(signingKey, claims)
}

// ValidateAccessToken verifies a JWT signature and returns the claims.
func ValidateAccessToken(signingKey []byte, tokenStr string) (*JWTClaims, error) {
	parts, err := splitJWT(tokenStr)
	if err != nil {
		return nil, err
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	expectedSig := computeHMAC(signingKey, []byte(signingInput))
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding")
	}
	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Check expiration.
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// CreateRefreshToken generates a random refresh token and returns (raw_token, sha256_hash).
func CreateRefreshToken() (string, string, error) {
	raw, err := randomHex(32)
	if err != nil {
		return "", "", err
	}
	hash := HashToken(raw)
	return raw, hash, nil
}

// HashToken returns the hex-encoded SHA-256 hash of a token string.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func signJWT(key []byte, claims JWTClaims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload
	sig := computeHMAC(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func splitJWT(token string) ([3]string, error) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return [3]string{}, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	return [3]string{parts[0], parts[1], parts[2]}, nil
}

func computeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomCode generates a cryptographically random URL-safe string for auth codes.
func RandomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
