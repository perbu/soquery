package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perbu/soquery/internal/audit"
	"github.com/perbu/soquery/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	encKey := make([]byte, 32)
	rand.Read(encKey)
	jwtKey := make([]byte, 32)
	rand.Read(jwtKey)

	return &Server{
		ExternalURL:    "https://mcp.example.com",
		SFInstanceURL:  "https://login.salesforce.com",
		SFClientID:     "sf-client-id",
		SFClientSecret: "sf-client-secret",
		Store:          st,
		EncryptionKey:  encKey,
		JWTSigningKey:  jwtKey,
		AuditLog:       audit.New(),
	}
}

func TestHandleMetadata(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	srv.HandleMetadata(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]interface{}
	json.NewDecoder(w.Body).Decode(&meta)

	if meta["issuer"] != "https://mcp.example.com" {
		t.Errorf("unexpected issuer: %v", meta["issuer"])
	}
	if meta["authorization_endpoint"] != "https://mcp.example.com/oauth/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", meta["authorization_endpoint"])
	}
}

func TestHandleProtectedResource(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	srv.HandleProtectedResource(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]interface{}
	json.NewDecoder(w.Body).Decode(&meta)

	if meta["resource"] != "https://mcp.example.com" {
		t.Errorf("unexpected resource: %v", meta["resource"])
	}
}

func TestHandleDCR(t *testing.T) {
	srv := testServer(t)

	body := `{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"Claude"}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.HandleDCR(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp DCRResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.ClientID == "" {
		t.Error("expected non-empty client_id")
	}
	if resp.ClientSecret == "" {
		t.Error("expected non-empty client_secret")
	}
	if resp.ClientName != "Claude" {
		t.Errorf("expected client_name=Claude, got %s", resp.ClientName)
	}
}

func TestHandleAuthorize_RedirectsToSF(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()

	// Register a client first.
	client := &store.DCRClient{
		ClientID:     "test-client",
		ClientSecret: "$2a$10$dummy",
		RedirectURIs: []string{"https://claude.ai/callback"},
		ClientName:   "Test",
		CreatedAt:    time.Now(),
	}
	srv.Store.SaveDCRClient(ctx, client)

	challenge := ComputeS256Challenge("my-verifier")
	authURL := "/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=https://claude.ai/callback&state=mystate&code_challenge=" + challenge + "&code_challenge_method=S256"

	req := httptest.NewRequest("GET", authURL, nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "https://login.salesforce.com/services/oauth2/authorize") {
		t.Errorf("expected redirect to SF, got %s", location)
	}
	if !strings.Contains(location, "client_id=sf-client-id") {
		t.Error("redirect should contain SF client ID")
	}
}

func TestHandleToken_AuthCodeExchange(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()

	// Setup: register client, create auth code.
	body := `{"redirect_uris":["https://claude.ai/callback"],"client_name":"Test"}`
	dcrReq := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	dcrReq.Header.Set("Content-Type", "application/json")
	dcrW := httptest.NewRecorder()
	srv.HandleDCR(dcrW, dcrReq)

	var dcrResp DCRResponse
	json.NewDecoder(dcrW.Body).Decode(&dcrResp)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := ComputeS256Challenge(verifier)

	now := time.Now()
	authCode := &store.AuthCode{
		Code:          "test-auth-code",
		UserID:        "005user",
		MCPClientID:   dcrResp.ClientID,
		RedirectURI:   "https://claude.ai/callback",
		CodeChallenge: challenge,
		CodeMethod:    "S256",
		CreatedAt:     now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	srv.Store.SaveAuthCode(ctx, authCode)

	// Exchange the code.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"test-auth-code"},
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://claude.ai/callback"},
	}

	tokenReq := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()

	srv.HandleToken(tokenW, tokenReq)

	if tokenW.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", tokenW.Code, tokenW.Body.String())
	}

	var tokenResp map[string]interface{}
	json.NewDecoder(tokenW.Body).Decode(&tokenResp)

	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if tokenResp["refresh_token"] == nil || tokenResp["refresh_token"] == "" {
		t.Error("expected non-empty refresh_token")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", tokenResp["token_type"])
	}

	// Validate the access token.
	accessToken := tokenResp["access_token"].(string)
	claims, err := ValidateAccessToken(srv.JWTSigningKey, accessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "005user" {
		t.Errorf("expected sub=005user, got %s", claims.Sub)
	}

	// Code should not be reusable.
	tokenReq2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW2 := httptest.NewRecorder()
	srv.HandleToken(tokenW2, tokenReq2)
	if tokenW2.Code == 200 {
		t.Error("reused auth code should be rejected")
	}
}

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		url    string
		want   string
		hasErr bool
	}{
		{"https://login.salesforce.com/id/00Dxx0000001abc/005xx0000001def", "005xx0000001def", false},
		{"https://test.salesforce.com/id/00Dxx/005xx", "005xx", false},
		{"https://login.salesforce.com/bad/path", "", true},
	}

	for _, tt := range tests {
		got, err := extractUserID(tt.url)
		if tt.hasErr && err == nil {
			t.Errorf("expected error for %s", tt.url)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("unexpected error for %s: %v", tt.url, err)
		}
		if got != tt.want {
			t.Errorf("extractUserID(%s) = %s, want %s", tt.url, got, tt.want)
		}
	}
}
