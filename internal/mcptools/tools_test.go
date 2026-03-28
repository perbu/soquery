package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perbu/soquery/internal/audit"
	"github.com/perbu/soquery/internal/oauth"
	"github.com/perbu/soquery/internal/store"
)

// TestEndToEnd simulates the full flow: DCR -> authorize -> SF callback -> token exchange -> tool call.
func TestEndToEnd(t *testing.T) {
	// --- Setup: mock Salesforce ---
	sfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/services/oauth2/token":
			// SF token exchange
			json.NewEncoder(w).Encode(map[string]string{
				"access_token":  "sf-access-token-123",
				"refresh_token": "sf-refresh-token-456",
				"instance_url":  "", // will be set below
				"id":            "https://login.salesforce.com/id/00Dxx/005testuser",
			})
		case strings.HasPrefix(r.URL.Path, "/services/data/") && strings.Contains(r.URL.Path, "/query"):
			// SOQL query
			if r.Header.Get("Authorization") != "Bearer sf-access-token-123" {
				w.WriteHeader(401)
				w.Write([]byte(`[{"message":"Session expired"}]`))
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"totalSize": 1,
				"done":      true,
				"records": []map[string]interface{}{
					{"attributes": map[string]interface{}{"type": "Account"}, "Id": "001abc", "Name": "Test Corp"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/sobjects/"):
			// List objects
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sobjects": []map[string]interface{}{
					{"name": "Account", "label": "Account", "queryable": true, "createable": true, "updateable": true, "deletable": true},
				},
			})
		default:
			t.Logf("unhandled SF request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer sfServer.Close()

	// Patch the SF token response to include the mock server URL as instance_url.
	sfServerPatched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/oauth2/token" {
			json.NewEncoder(w).Encode(map[string]string{
				"access_token":  "sf-access-token-123",
				"refresh_token": "sf-refresh-token-456",
				"instance_url":  sfServer.URL,
				"id":            "https://login.salesforce.com/id/00Dxx/005testuser",
			})
			return
		}
		// Proxy everything else to the main sfServer
		sfServer.Config.Handler.ServeHTTP(w, r)
	}))
	defer sfServerPatched.Close()

	// --- Setup: our OAuth/MCP server ---
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	encKey := make([]byte, 32)
	rand.Read(encKey)
	jwtKey := make([]byte, 32)
	rand.Read(jwtKey)

	oauthSrv := &oauth.Server{
		ExternalURL:    "http://test.local",
		SFInstanceURL:  sfServerPatched.URL,
		SFClientID:     "test-sf-client",
		SFClientSecret: "test-sf-secret",
		Store:          db,
		EncryptionKey:  encKey,
		JWTSigningKey:  jwtKey,
		AuditLog:       audit.New(),
	}

	mux := http.NewServeMux()
	oauthSrv.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()
	// Update external URL to match test server
	oauthSrv.ExternalURL = ts.URL

	// --- Step 1: DCR ---
	dcrBody := fmt.Sprintf(`{"redirect_uris":["%s/callback"],"client_name":"Test"}`, ts.URL)
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(dcrBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("DCR: expected 201, got %d", resp.StatusCode)
	}
	var dcrResp struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	json.NewDecoder(resp.Body).Decode(&dcrResp)
	t.Logf("DCR: client_id=%s", dcrResp.ClientID)

	// --- Step 2: Authorize (should redirect to SF) ---
	verifier := "test-verifier-that-is-long-enough-for-pkce-purposes"
	challenge := oauth.ComputeS256Challenge(verifier)

	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s/callback&state=mystate&code_challenge=%s&code_challenge_method=S256",
		ts.URL, dcrResp.ClientID, ts.URL, challenge)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	}}

	resp2, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 302 {
		t.Fatalf("Authorize: expected 302, got %d", resp2.StatusCode)
	}
	location := resp2.Header.Get("Location")
	if !strings.Contains(location, "services/oauth2/authorize") {
		t.Fatalf("Authorize: expected redirect to SF, got %s", location)
	}
	t.Logf("Authorize: redirects to SF login")

	// Extract the session ID from the SF redirect's state parameter
	locURL, _ := url.Parse(location)
	sessionID := locURL.Query().Get("state")

	// --- Step 3: Simulate SF callback (as if user logged in) ---
	callbackURL := fmt.Sprintf("%s/oauth/sf-callback?code=sf-auth-code-xyz&state=%s", ts.URL, sessionID)
	resp3, err := client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != 302 {
		t.Fatalf("SF Callback: expected 302, got %d", resp3.StatusCode)
	}
	callbackLocation := resp3.Header.Get("Location")
	if !strings.Contains(callbackLocation, "callback") {
		t.Fatalf("SF Callback: expected redirect to our callback, got %s", callbackLocation)
	}

	// Extract our auth code from the redirect
	cbURL, _ := url.Parse(callbackLocation)
	ourCode := cbURL.Query().Get("code")
	cbState := cbURL.Query().Get("state")
	if ourCode == "" {
		t.Fatal("SF Callback: no code in redirect")
	}
	if cbState != "mystate" {
		t.Fatalf("SF Callback: state mismatch: %s", cbState)
	}
	t.Logf("SF Callback: got auth code, state preserved")

	// --- Step 4: Token exchange ---
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {ourCode},
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
		"code_verifier": {verifier},
		"redirect_uri":  {ts.URL + "/callback"},
	}
	resp4, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != 200 {
		t.Fatalf("Token: expected 200, got %d", resp4.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	json.NewDecoder(resp4.Body).Decode(&tokenResp)

	if tokenResp.AccessToken == "" {
		t.Fatal("Token: empty access_token")
	}
	if tokenResp.RefreshToken == "" {
		t.Fatal("Token: empty refresh_token")
	}
	t.Logf("Token: got access_token (Bearer), expires_in=%d", tokenResp.ExpiresIn)

	// --- Verify: user tokens stored in DB ---
	userTokens, err := db.GetUserTokens(context.Background(), "005testuser")
	if err != nil {
		t.Fatal(err)
	}
	if userTokens == nil {
		t.Fatal("user tokens not found in DB")
	}
	if userTokens.SFInstanceURL != sfServer.URL {
		t.Errorf("unexpected instance URL: %s", userTokens.SFInstanceURL)
	}

	// Decrypt and verify
	accessPlain, err := store.Decrypt(userTokens.SFAccessTokenCrypt, encKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(accessPlain) != "sf-access-token-123" {
		t.Errorf("unexpected decrypted access token: %s", accessPlain)
	}
	t.Logf("DB: SF tokens stored and encrypted correctly")

	// --- Step 5: Refresh token exchange ---
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
	}
	resp5, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(refreshForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != 200 {
		t.Fatalf("Refresh: expected 200, got %d", resp5.StatusCode)
	}

	var refreshResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp5.Body).Decode(&refreshResp)
	if refreshResp.AccessToken == "" || refreshResp.RefreshToken == "" {
		t.Fatal("Refresh: missing tokens in response")
	}
	t.Logf("Refresh: got new access_token and refresh_token")

	// Old refresh token should be revoked (rotation)
	oldHash := oauth.HashToken(tokenResp.RefreshToken)
	oldRT, _ := db.GetMCPRefreshToken(context.Background(), oldHash)
	if oldRT == nil || !oldRT.Revoked {
		t.Error("Refresh: old refresh token should be revoked")
	}
	t.Logf("Refresh: old token revoked (rotation works)")

	// --- Step 6: Validate JWT claims ---
	claims, err := oauth.ValidateAccessToken(jwtKey, refreshResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "005testuser" {
		t.Errorf("JWT: expected sub=005testuser, got %s", claims.Sub)
	}
	t.Logf("JWT: sub=%s, exp=%s", claims.Sub, time.Unix(claims.Exp, 0).Format(time.RFC3339))

	t.Log("--- Full OAuth flow passed ---")
}
