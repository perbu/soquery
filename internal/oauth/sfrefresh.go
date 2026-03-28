package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RefreshSFToken exchanges a Salesforce refresh token for a new access token.
// Returns (newAccessToken, instanceURL, error).
func RefreshSFToken(instanceURL, clientID, clientSecret, refreshToken string) (string, string, error) {
	tokenURL := instanceURL + "/services/oauth2/token"

	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return "", "", fmt.Errorf("requesting SF token refresh: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("reading SF refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("SF token refresh failed (HTTP %d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parsing SF refresh response: %w", err)
	}

	return result.AccessToken, result.InstanceURL, nil
}
