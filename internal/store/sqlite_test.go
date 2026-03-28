package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDCRClient_RoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	client := &DCRClient{
		ClientID:     "test-client-id",
		ClientSecret: "$2a$10$hashedvalue",
		RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
		ClientName:   "Claude.ai",
		CreatedAt:    time.Now().Truncate(time.Second),
	}

	if err := s.SaveDCRClient(ctx, client); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetDCRClient(ctx, "test-client-id")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected client, got nil")
	}
	if got.ClientName != "Claude.ai" {
		t.Errorf("expected Claude.ai, got %s", got.ClientName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Errorf("unexpected redirect URIs: %v", got.RedirectURIs)
	}
}

func TestDCRClient_NotFound(t *testing.T) {
	s := testStore(t)
	got, err := s.GetDCRClient(context.Background(), "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestAuthSession_RoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	sess := &AuthSession{
		SessionID:        "sess-123",
		MCPClientID:      "client-1",
		MCPRedirectURI:   "https://claude.ai/callback",
		MCPState:         "state-abc",
		MCPCodeChallenge: "challenge-xyz",
		MCPCodeMethod:    "S256",
		CreatedAt:        now,
		ExpiresAt:        now.Add(10 * time.Minute),
	}

	if err := s.SaveAuthSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetAuthSession(ctx, "sess-123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.MCPState != "state-abc" {
		t.Errorf("expected state-abc, got %s", got.MCPState)
	}

	if err := s.DeleteAuthSession(ctx, "sess-123"); err != nil {
		t.Fatal(err)
	}

	got, err = s.GetAuthSession(ctx, "sess-123")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestAuthCode_RoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	code := &AuthCode{
		Code:          "code-456",
		UserID:        "005user",
		MCPClientID:   "client-1",
		RedirectURI:   "https://claude.ai/callback",
		CodeChallenge: "challenge",
		CodeMethod:    "S256",
		CreatedAt:     now,
		ExpiresAt:     now.Add(60 * time.Second),
	}

	if err := s.SaveAuthCode(ctx, code); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetAuthCode(ctx, "code-456")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected code, got nil")
	}
	if got.Used {
		t.Error("code should not be used initially")
	}

	if err := s.MarkAuthCodeUsed(ctx, "code-456"); err != nil {
		t.Fatal(err)
	}

	got, err = s.GetAuthCode(ctx, "code-456")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Used {
		t.Error("code should be marked as used")
	}
}

func TestUserTokens_RoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	tokens := &UserTokens{
		UserID:              "005user",
		SFInstanceURL:       "https://varnish.my.salesforce.com",
		SFAccessTokenCrypt:  []byte("encrypted-access"),
		SFRefreshTokenCrypt: []byte("encrypted-refresh"),
		SFTokenIssuedAt:     now,
		UpdatedAt:           now,
	}

	if err := s.SaveUserTokens(ctx, tokens); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetUserTokens(ctx, "005user")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected tokens, got nil")
	}
	if got.SFInstanceURL != "https://varnish.my.salesforce.com" {
		t.Errorf("unexpected instance URL: %s", got.SFInstanceURL)
	}
	if string(got.SFAccessTokenCrypt) != "encrypted-access" {
		t.Errorf("unexpected access token: %s", got.SFAccessTokenCrypt)
	}
}

func TestUserTokens_Upsert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	tokens := &UserTokens{
		UserID:              "005user",
		SFInstanceURL:       "https://varnish.my.salesforce.com",
		SFAccessTokenCrypt:  []byte("old-token"),
		SFRefreshTokenCrypt: []byte("old-refresh"),
		SFTokenIssuedAt:     now,
		UpdatedAt:           now,
	}
	if err := s.SaveUserTokens(ctx, tokens); err != nil {
		t.Fatal(err)
	}

	tokens.SFAccessTokenCrypt = []byte("new-token")
	tokens.UpdatedAt = now.Add(time.Hour)
	if err := s.SaveUserTokens(ctx, tokens); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetUserTokens(ctx, "005user")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.SFAccessTokenCrypt) != "new-token" {
		t.Errorf("expected new-token, got %s", got.SFAccessTokenCrypt)
	}
}

func TestMCPRefreshToken_RoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	token := &MCPRefreshToken{
		TokenHash:   "sha256hash",
		UserID:      "005user",
		MCPClientID: "client-1",
		CreatedAt:   now,
		ExpiresAt:   now.Add(30 * 24 * time.Hour),
	}

	if err := s.SaveMCPRefreshToken(ctx, token); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetMCPRefreshToken(ctx, "sha256hash")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.Revoked {
		t.Error("token should not be revoked initially")
	}

	if err := s.RevokeMCPRefreshToken(ctx, "sha256hash"); err != nil {
		t.Fatal(err)
	}

	got, err = s.GetMCPRefreshToken(ctx, "sha256hash")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Error("token should be revoked")
	}
}
