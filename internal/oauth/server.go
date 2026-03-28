package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/perbu/soquery/internal/audit"
	"github.com/perbu/soquery/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Server implements the OAuth 2.1 Authorization Server.
type Server struct {
	ExternalURL   string // Public URL of this server
	SFInstanceURL string // Salesforce instance URL
	SFClientID    string // SF Connected App consumer key
	SFClientSecret string // SF Connected App consumer secret

	Store         store.Store
	EncryptionKey []byte // 32-byte AES key for token encryption
	JWTSigningKey []byte // 32-byte HMAC key for JWT signing
	AuditLog      *audit.Logger
}

const (
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour
	authSessionTTL  = 10 * time.Minute
)

// HandleMetadata handles GET /.well-known/oauth-authorization-server.
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                             s.ExternalURL,
		"authorization_endpoint":             s.ExternalURL + "/oauth/authorize",
		"token_endpoint":                     s.ExternalURL + "/oauth/token",
		"registration_endpoint":              s.ExternalURL + "/oauth/register",
		"response_types_supported":           []string{"code"},
		"grant_types_supported":              []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":   []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// HandleProtectedResource handles GET /.well-known/oauth-protected-resource.
func (s *Server) HandleProtectedResource(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"resource":              s.ExternalURL,
		"authorization_servers": []string{s.ExternalURL},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// HandleAuthorize handles GET /oauth/authorize — the authorization endpoint.
// It validates the request and redirects the user to Salesforce for login.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	responseType := q.Get("response_type")

	if responseType != "code" {
		writeJSONError(w, "unsupported_response_type", "only 'code' is supported", http.StatusBadRequest)
		return
	}

	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		writeJSONError(w, "invalid_request", "missing required parameters", http.StatusBadRequest)
		return
	}

	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallengeMethod != "S256" {
		writeJSONError(w, "invalid_request", "only S256 code_challenge_method is supported", http.StatusBadRequest)
		return
	}

	// Verify the client exists and the redirect URI is registered.
	client, err := s.Store.GetDCRClient(r.Context(), clientID)
	if err != nil || client == nil {
		writeJSONError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return
	}

	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeJSONError(w, "invalid_request", "redirect_uri not registered", http.StatusBadRequest)
		return
	}

	// Create an auth session to correlate this flow.
	sessionID, err := RandomCode(32)
	if err != nil {
		writeJSONError(w, "server_error", "failed to generate session", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	sess := &store.AuthSession{
		SessionID:        sessionID,
		MCPClientID:      clientID,
		MCPRedirectURI:   redirectURI,
		MCPState:         state,
		MCPCodeChallenge: codeChallenge,
		MCPCodeMethod:    codeChallengeMethod,
		CreatedAt:        now,
		ExpiresAt:        now.Add(authSessionTTL),
	}
	if err := s.Store.SaveAuthSession(r.Context(), sess); err != nil {
		writeJSONError(w, "server_error", "failed to save session", http.StatusInternalServerError)
		return
	}

	s.AuditLog.LogAuth(r.Context(), "auth_start", "", nil)

	// Redirect to Salesforce login.
	sfAuthURL := fmt.Sprintf("%s/services/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=%s",
		s.SFInstanceURL,
		url.QueryEscape(s.SFClientID),
		url.QueryEscape(s.ExternalURL+"/oauth/sf-callback"),
		url.QueryEscape(sessionID),
		url.QueryEscape("api refresh_token"),
	)

	http.Redirect(w, r, sfAuthURL, http.StatusFound)
}

// HandleToken handles POST /oauth/token — the token endpoint.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSONError(w, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthCodeExchange(w, r)
	case "refresh_token":
		s.handleRefreshTokenExchange(w, r)
	default:
		writeJSONError(w, "unsupported_grant_type", "unsupported grant_type", http.StatusBadRequest)
	}
}

func (s *Server) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || clientID == "" || codeVerifier == "" {
		writeJSONError(w, "invalid_request", "missing required parameters", http.StatusBadRequest)
		return
	}

	// Verify client credentials.
	client, err := s.Store.GetDCRClient(r.Context(), clientID)
	if err != nil || client == nil {
		writeJSONError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)); err != nil {
		writeJSONError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Look up and validate the authorization code.
	authCode, err := s.Store.GetAuthCode(r.Context(), code)
	if err != nil {
		writeJSONError(w, "server_error", "failed to load auth code", http.StatusInternalServerError)
		return
	}
	if authCode == nil || authCode.Used || time.Now().After(authCode.ExpiresAt) {
		writeJSONError(w, "invalid_grant", "invalid or expired code", http.StatusBadRequest)
		return
	}
	if authCode.MCPClientID != clientID {
		writeJSONError(w, "invalid_grant", "code was issued to a different client", http.StatusBadRequest)
		return
	}
	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		writeJSONError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// Verify PKCE.
	if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeMethod) {
		writeJSONError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	// Mark the code as used.
	if err := s.Store.MarkAuthCodeUsed(r.Context(), code); err != nil {
		writeJSONError(w, "server_error", "failed to mark code used", http.StatusInternalServerError)
		return
	}

	// Issue tokens.
	s.issueTokens(w, r, authCode.UserID, clientID)
}

func (s *Server) handleRefreshTokenExchange(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if refreshToken == "" || clientID == "" {
		writeJSONError(w, "invalid_request", "missing required parameters", http.StatusBadRequest)
		return
	}

	// Verify client credentials.
	client, err := s.Store.GetDCRClient(r.Context(), clientID)
	if err != nil || client == nil {
		writeJSONError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)); err != nil {
		writeJSONError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Validate refresh token.
	tokenHash := HashToken(refreshToken)
	storedToken, err := s.Store.GetMCPRefreshToken(r.Context(), tokenHash)
	if err != nil {
		writeJSONError(w, "server_error", "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if storedToken == nil || storedToken.Revoked || time.Now().After(storedToken.ExpiresAt) {
		writeJSONError(w, "invalid_grant", "invalid or expired refresh token", http.StatusBadRequest)
		return
	}
	if storedToken.MCPClientID != clientID {
		writeJSONError(w, "invalid_grant", "token was issued to a different client", http.StatusBadRequest)
		return
	}

	// Revoke the old refresh token (rotation).
	_ = s.Store.RevokeMCPRefreshToken(r.Context(), tokenHash)

	// Issue new tokens.
	s.issueTokens(w, r, storedToken.UserID, clientID)
}

func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, userID, clientID string) {
	accessToken, err := CreateAccessToken(s.JWTSigningKey, userID, clientID, s.ExternalURL, accessTokenTTL)
	if err != nil {
		writeJSONError(w, "server_error", "failed to create access token", http.StatusInternalServerError)
		return
	}

	refreshToken, refreshHash, err := CreateRefreshToken()
	if err != nil {
		writeJSONError(w, "server_error", "failed to create refresh token", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	mcpRT := &store.MCPRefreshToken{
		TokenHash:   refreshHash,
		UserID:      userID,
		MCPClientID: clientID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(refreshTokenTTL),
	}
	if err := s.Store.SaveMCPRefreshToken(r.Context(), mcpRT); err != nil {
		writeJSONError(w, "server_error", "failed to save refresh token", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RegisterRoutes registers all OAuth routes on the given mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.HandleMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.HandleProtectedResource)
	mux.HandleFunc("POST /oauth/register", s.HandleDCR)
	mux.HandleFunc("GET /oauth/authorize", s.HandleAuthorize)
	mux.HandleFunc("GET /oauth/sf-callback", s.HandleSFCallback)
	mux.HandleFunc("POST /oauth/token", s.HandleToken)
}

// writeJSONError writes a standard OAuth error response.
func writeJSONError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

