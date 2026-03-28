package store

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecrypt(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("my-secret-refresh-token-value")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	ciphertext, err := Encrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := testKey(t)
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestEncrypt_DifferentNonces(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same-input")

	c1, _ := Encrypt(plaintext, key)
	c2, _ := Encrypt(plaintext, key)

	if bytes.Equal(c1, c2) {
		t.Error("two encryptions of same plaintext should produce different ciphertext")
	}
}
