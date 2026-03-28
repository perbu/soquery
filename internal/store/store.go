package store

import (
	"context"
	"time"
)

// DCRClient represents a dynamically registered OAuth client.
type DCRClient struct {
	ClientID     string
	ClientSecret string // bcrypt hash
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
}

// AuthSession represents an in-flight OAuth authorization session.
type AuthSession struct {
	SessionID        string
	MCPClientID      string
	MCPRedirectURI   string
	MCPState         string
	MCPCodeChallenge string
	MCPCodeMethod    string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// AuthCode represents an issued authorization code.
type AuthCode struct {
	Code          string
	UserID        string
	MCPClientID   string
	RedirectURI   string
	CodeChallenge string
	CodeMethod    string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Used          bool
}

// UserTokens holds encrypted Salesforce tokens for a user.
type UserTokens struct {
	UserID              string
	SFInstanceURL       string
	SFAccessTokenCrypt  []byte // AES-GCM encrypted
	SFRefreshTokenCrypt []byte // AES-GCM encrypted
	SFTokenIssuedAt     time.Time
	UpdatedAt           time.Time
}

// MCPRefreshToken represents an issued MCP refresh token.
type MCPRefreshToken struct {
	TokenHash   string // SHA-256 of the raw token
	UserID      string
	MCPClientID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Revoked     bool
}

// Store defines the persistence interface for the OAuth/MCP server.
type Store interface {
	// DCR clients
	SaveDCRClient(ctx context.Context, client *DCRClient) error
	GetDCRClient(ctx context.Context, clientID string) (*DCRClient, error)

	// Auth sessions (short-lived, during OAuth flow)
	SaveAuthSession(ctx context.Context, session *AuthSession) error
	GetAuthSession(ctx context.Context, sessionID string) (*AuthSession, error)
	DeleteAuthSession(ctx context.Context, sessionID string) error

	// Auth codes (short-lived, after SF auth completes)
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	MarkAuthCodeUsed(ctx context.Context, code string) error

	// Per-user Salesforce tokens
	SaveUserTokens(ctx context.Context, tokens *UserTokens) error
	GetUserTokens(ctx context.Context, userID string) (*UserTokens, error)

	// MCP refresh tokens
	SaveMCPRefreshToken(ctx context.Context, token *MCPRefreshToken) error
	GetMCPRefreshToken(ctx context.Context, tokenHash string) (*MCPRefreshToken, error)
	RevokeMCPRefreshToken(ctx context.Context, tokenHash string) error

	// Lifecycle
	Close() error
}
