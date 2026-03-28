package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/perbu/soquery/internal/store"
)

// sfTokenResponse represents the Salesforce OAuth token response.
type sfTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	InstanceURL  string `json:"instance_url"`
	ID           string `json:"id"` // e.g., https://login.salesforce.com/id/00Dxx.../005xxx...
}

// HandleSFCallback handles GET /oauth/sf-callback after the user authenticates with Salesforce.
func (s *Server) HandleSFCallback(w http.ResponseWriter, r *http.Request) {
	sfCode := r.URL.Query().Get("code")
	sessionID := r.URL.Query().Get("state")

	if sfCode == "" || sessionID == "" {
		writeJSONError(w, "invalid_request", "missing code or state", http.StatusBadRequest)
		return
	}

	// Check for SF errors.
	if sfErr := r.URL.Query().Get("error"); sfErr != "" {
		desc := r.URL.Query().Get("error_description")
		s.AuditLog.LogAuth(r.Context(), "auth_fail", "", fmt.Errorf("SF error: %s: %s", sfErr, desc))
		writeJSONError(w, "access_denied", "Salesforce login failed: "+desc, http.StatusForbidden)
		return
	}

	// Look up the auth session.
	sess, err := s.Store.GetAuthSession(r.Context(), sessionID)
	if err != nil {
		writeJSONError(w, "server_error", "failed to load session", http.StatusInternalServerError)
		return
	}
	if sess == nil || time.Now().After(sess.ExpiresAt) {
		writeJSONError(w, "invalid_request", "session expired or not found", http.StatusBadRequest)
		return
	}

	// Exchange SF authorization code for tokens.
	sfTokens, err := s.exchangeSFCode(sfCode)
	if err != nil {
		s.AuditLog.LogAuth(r.Context(), "auth_fail", "", err)
		writeJSONError(w, "server_error", "failed to exchange SF token", http.StatusInternalServerError)
		return
	}

	// Extract user ID from the identity URL.
	userID, err := extractUserID(sfTokens.ID)
	if err != nil {
		s.AuditLog.LogAuth(r.Context(), "auth_fail", "", err)
		writeJSONError(w, "server_error", "failed to identify user", http.StatusInternalServerError)
		return
	}

	// Encrypt and store SF tokens.
	now := time.Now()
	encAccess, err := store.Encrypt([]byte(sfTokens.AccessToken), s.EncryptionKey)
	if err != nil {
		writeJSONError(w, "server_error", "encryption failed", http.StatusInternalServerError)
		return
	}
	encRefresh, err := store.Encrypt([]byte(sfTokens.RefreshToken), s.EncryptionKey)
	if err != nil {
		writeJSONError(w, "server_error", "encryption failed", http.StatusInternalServerError)
		return
	}

	userTokens := &store.UserTokens{
		UserID:              userID,
		SFInstanceURL:       sfTokens.InstanceURL,
		SFAccessTokenCrypt:  encAccess,
		SFRefreshTokenCrypt: encRefresh,
		SFTokenIssuedAt:     now,
		UpdatedAt:           now,
	}
	if err := s.Store.SaveUserTokens(r.Context(), userTokens); err != nil {
		writeJSONError(w, "server_error", "failed to save tokens", http.StatusInternalServerError)
		return
	}

	// Generate our authorization code.
	code, err := RandomCode(32)
	if err != nil {
		writeJSONError(w, "server_error", "failed to generate code", http.StatusInternalServerError)
		return
	}

	authCode := &store.AuthCode{
		Code:          code,
		UserID:        userID,
		MCPClientID:   sess.MCPClientID,
		RedirectURI:   sess.MCPRedirectURI,
		CodeChallenge: sess.MCPCodeChallenge,
		CodeMethod:    sess.MCPCodeMethod,
		CreatedAt:     now,
		ExpiresAt:     now.Add(60 * time.Second),
	}
	if err := s.Store.SaveAuthCode(r.Context(), authCode); err != nil {
		writeJSONError(w, "server_error", "failed to save auth code", http.StatusInternalServerError)
		return
	}

	// Clean up the session.
	_ = s.Store.DeleteAuthSession(r.Context(), sessionID)

	s.AuditLog.LogAuth(r.Context(), "auth_complete", userID, nil)

	// Redirect to Claude.ai callback with our auth code.
	redirectURL, _ := url.Parse(sess.MCPRedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", sess.MCPState)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// exchangeSFCode exchanges a Salesforce authorization code for access + refresh tokens.
func (s *Server) exchangeSFCode(code string) (*sfTokenResponse, error) {
	tokenURL := s.SFInstanceURL + "/services/oauth2/token"

	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {s.SFClientID},
		"client_secret": {s.SFClientSecret},
		"redirect_uri":  {s.ExternalURL + "/oauth/sf-callback"},
	})
	if err != nil {
		return nil, fmt.Errorf("requesting SF token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading SF token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SF token exchange failed (HTTP %d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	var tok sfTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parsing SF token response: %w", err)
	}

	return &tok, nil
}

// extractUserID extracts the Salesforce user ID from the identity URL.
// The identity URL looks like: https://login.salesforce.com/id/00Dxxxx/005xxxx
func extractUserID(identityURL string) (string, error) {
	u, err := url.Parse(identityURL)
	if err != nil {
		return "", fmt.Errorf("parsing identity URL: %w", err)
	}
	// Path is /id/{orgID}/{userID}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "id" {
		return "", fmt.Errorf("unexpected identity URL format: %s", identityURL)
	}
	return parts[2], nil // userID
}

// truncate returns at most n bytes of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
