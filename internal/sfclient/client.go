package sfclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const APIVersion = "v62.0"

const defaultTimeout = 30 * time.Second

// Client is a Salesforce REST API client.
type Client struct {
	instanceURL string
	accessToken string
	httpClient  *http.Client
}

// NewClient creates a new Salesforce client. If httpClient is nil, a client with a 30s timeout is used.
func NewClient(instanceURL, accessToken string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{
		instanceURL: instanceURL,
		accessToken: accessToken,
		httpClient:  httpClient,
	}
}

// InstanceURL returns the Salesforce instance URL.
func (c *Client) InstanceURL() string { return c.instanceURL }

func (c *Client) doRequest(ctx context.Context, req *http.Request) ([]byte, int, error) {
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	return body, resp.StatusCode, nil
}

// SFError represents a Salesforce API error response.
type SFError struct {
	StatusCode int
	Body       string
}

func (e *SFError) Error() string {
	return fmt.Sprintf("salesforce API error (HTTP %d): %s", e.StatusCode, e.Body)
}

// IsUnauthorized returns true if the error is a 401 Unauthorized response.
func IsUnauthorized(err error) bool {
	if sfErr, ok := err.(*SFError); ok {
		return sfErr.StatusCode == http.StatusUnauthorized
	}
	return false
}

func checkStatus(body []byte, statusCode int, expected ...int) error {
	for _, exp := range expected {
		if statusCode == exp {
			return nil
		}
	}
	return &SFError{StatusCode: statusCode, Body: string(body)}
}

// parseJSON unmarshals body into dest and wraps any error.
func parseJSON(body []byte, dest interface{}) error {
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	return nil
}
