package oauth

import (
	"crypto/rand"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestCreateAndValidateAccessToken(t *testing.T) {
	key := testKey(t)

	token, err := CreateAccessToken(key, "005user", "client-1", "https://example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateAccessToken(key, token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Sub != "005user" {
		t.Errorf("expected sub=005user, got %s", claims.Sub)
	}
	if claims.Aud != "client-1" {
		t.Errorf("expected aud=client-1, got %s", claims.Aud)
	}
	if claims.Iss != "https://example.com" {
		t.Errorf("expected iss=https://example.com, got %s", claims.Iss)
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	key := testKey(t)

	token, err := CreateAccessToken(key, "005user", "client-1", "https://example.com", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateAccessToken(key, token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateAccessToken_WrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	token, err := CreateAccessToken(key1, "005user", "client-1", "https://example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateAccessToken(key2, token)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := ComputeS256Challenge(verifier)

	if !VerifyPKCE(verifier, challenge, "S256") {
		t.Error("PKCE verification should pass")
	}

	if VerifyPKCE("wrong-verifier", challenge, "S256") {
		t.Error("PKCE verification should fail with wrong verifier")
	}

	if VerifyPKCE(verifier, challenge, "plain") {
		t.Error("PKCE should reject non-S256 method")
	}
}

func TestCreateRefreshToken(t *testing.T) {
	raw1, hash1, err := CreateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	raw2, hash2, err := CreateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}

	if raw1 == raw2 {
		t.Error("refresh tokens should be unique")
	}
	if hash1 == hash2 {
		t.Error("refresh token hashes should be unique")
	}

	// Hash should be deterministic for same input.
	if HashToken(raw1) != hash1 {
		t.Error("HashToken should produce consistent results")
	}
}
