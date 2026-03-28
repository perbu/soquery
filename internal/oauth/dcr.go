package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/perbu/soquery/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// DCRRequest represents a Dynamic Client Registration request.
type DCRRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	GrantTypes   []string `json:"grant_types"`
}

// DCRResponse represents a Dynamic Client Registration response.
type DCRResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	GrantTypes   []string `json:"grant_types"`
}

// HandleDCR handles POST /oauth/register for Dynamic Client Registration.
func (s *Server) HandleDCR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.DCRRateLimit != nil && !s.DCRRateLimit.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, "too_many_requests", "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid_request", "invalid JSON body", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeJSONError(w, "invalid_request", "redirect_uris required", http.StatusBadRequest)
		return
	}

	clientID, err := generateClientID()
	if err != nil {
		writeJSONError(w, "server_error", "failed to generate client ID", http.StatusInternalServerError)
		return
	}

	clientSecret, err := generateClientSecret()
	if err != nil {
		writeJSONError(w, "server_error", "failed to generate client secret", http.StatusInternalServerError)
		return
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		writeJSONError(w, "server_error", "failed to hash secret", http.StatusInternalServerError)
		return
	}

	client := &store.DCRClient{
		ClientID:     clientID,
		ClientSecret: string(hashedSecret),
		RedirectURIs: req.RedirectURIs,
		ClientName:   req.ClientName,
		CreatedAt:    time.Now(),
	}

	if err := s.Store.SaveDCRClient(r.Context(), client); err != nil {
		writeJSONError(w, "server_error", "failed to save client", http.StatusInternalServerError)
		return
	}

	s.AuditLog.LogDCR(r.Context(), clientID, req.ClientName)

	resp := DCRResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		ClientName:   req.ClientName,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func generateClientID() (string, error) {
	hex, err := randomHex(16)
	if err != nil {
		return "", err
	}
	return "mcp_" + hex, nil
}

func generateClientSecret() (string, error) {
	hex, err := randomHex(32)
	if err != nil {
		return "", err
	}
	return "secret_" + hex, nil
}
