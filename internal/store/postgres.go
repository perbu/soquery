package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

const pgSchema = `
CREATE TABLE IF NOT EXISTS dcr_clients (
	client_id     TEXT PRIMARY KEY,
	client_secret TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	client_name   TEXT,
	created_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
	session_id         TEXT PRIMARY KEY,
	mcp_client_id      TEXT NOT NULL,
	mcp_redirect_uri   TEXT NOT NULL,
	mcp_state          TEXT NOT NULL,
	mcp_code_challenge TEXT NOT NULL,
	mcp_code_method    TEXT NOT NULL DEFAULT 'S256',
	created_at         TIMESTAMPTZ NOT NULL,
	expires_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
	code            TEXT PRIMARY KEY,
	user_id         TEXT NOT NULL,
	mcp_client_id   TEXT NOT NULL,
	redirect_uri    TEXT NOT NULL,
	code_challenge  TEXT NOT NULL,
	code_method     TEXT NOT NULL DEFAULT 'S256',
	created_at      TIMESTAMPTZ NOT NULL,
	expires_at      TIMESTAMPTZ NOT NULL,
	used            BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS user_tokens (
	user_id             TEXT PRIMARY KEY,
	sf_instance_url     TEXT NOT NULL,
	sf_access_token     BYTEA NOT NULL,
	sf_refresh_token    BYTEA NOT NULL,
	sf_token_issued_at  TIMESTAMPTZ NOT NULL,
	updated_at          TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
	token_hash    TEXT PRIMARY KEY,
	user_id       TEXT NOT NULL,
	mcp_client_id TEXT NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL,
	expires_at    TIMESTAMPTZ NOT NULL,
	revoked       BOOLEAN NOT NULL DEFAULT FALSE
);
`

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres opens a PostgreSQL database and runs migrations.
func NewPostgres(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	if _, err := db.Exec(pgSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// --- DCR Clients ---

func (s *PostgresStore) SaveDCRClient(ctx context.Context, c *DCRClient) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO dcr_clients (client_id, client_secret, redirect_uris, client_name, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (client_id) DO UPDATE SET
		   client_secret = EXCLUDED.client_secret,
		   redirect_uris = EXCLUDED.redirect_uris,
		   client_name = EXCLUDED.client_name,
		   created_at = EXCLUDED.created_at`,
		c.ClientID, c.ClientSecret, string(uris), c.ClientName, c.CreatedAt)
	return err
}

func (s *PostgresStore) GetDCRClient(ctx context.Context, clientID string) (*DCRClient, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_secret, redirect_uris, client_name, created_at FROM dcr_clients WHERE client_id = $1`,
		clientID)

	var c DCRClient
	var urisJSON string
	if err := row.Scan(&c.ClientID, &c.ClientSecret, &urisJSON, &c.ClientName, &c.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("parsing redirect_uris: %w", err)
	}
	return &c, nil
}

// --- Auth Sessions ---

func (s *PostgresStore) SaveAuthSession(ctx context.Context, sess *AuthSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_sessions (session_id, mcp_client_id, mcp_redirect_uri, mcp_state, mcp_code_challenge, mcp_code_method, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		sess.SessionID, sess.MCPClientID, sess.MCPRedirectURI, sess.MCPState,
		sess.MCPCodeChallenge, sess.MCPCodeMethod,
		sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *PostgresStore) GetAuthSession(ctx context.Context, sessionID string) (*AuthSession, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_id, mcp_client_id, mcp_redirect_uri, mcp_state, mcp_code_challenge, mcp_code_method, created_at, expires_at
		 FROM auth_sessions WHERE session_id = $1`, sessionID)

	var sess AuthSession
	if err := row.Scan(&sess.SessionID, &sess.MCPClientID, &sess.MCPRedirectURI, &sess.MCPState,
		&sess.MCPCodeChallenge, &sess.MCPCodeMethod, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &sess, nil
}

func (s *PostgresStore) DeleteAuthSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE session_id = $1`, sessionID)
	return err
}

// --- Auth Codes ---

func (s *PostgresStore) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes (code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at, used)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE)`,
		code.Code, code.UserID, code.MCPClientID, code.RedirectURI,
		code.CodeChallenge, code.CodeMethod,
		code.CreatedAt, code.ExpiresAt)
	return err
}

func (s *PostgresStore) GetAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at, used
		 FROM auth_codes WHERE code = $1`, code)

	var ac AuthCode
	if err := row.Scan(&ac.Code, &ac.UserID, &ac.MCPClientID, &ac.RedirectURI,
		&ac.CodeChallenge, &ac.CodeMethod, &ac.CreatedAt, &ac.ExpiresAt, &ac.Used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ac, nil
}

func (s *PostgresStore) ClaimAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`UPDATE auth_codes SET used = TRUE
		 WHERE code = $1 AND used = FALSE AND expires_at > $2
		 RETURNING code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at, used`,
		code, time.Now())

	var ac AuthCode
	if err := row.Scan(&ac.Code, &ac.UserID, &ac.MCPClientID, &ac.RedirectURI,
		&ac.CodeChallenge, &ac.CodeMethod, &ac.CreatedAt, &ac.ExpiresAt, &ac.Used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("claiming auth code: %w", err)
	}
	return &ac, nil
}

// --- User Tokens ---

func (s *PostgresStore) SaveUserTokens(ctx context.Context, t *UserTokens) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_tokens (user_id, sf_instance_url, sf_access_token, sf_refresh_token, sf_token_issued_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (user_id) DO UPDATE SET
		   sf_instance_url = EXCLUDED.sf_instance_url,
		   sf_access_token = EXCLUDED.sf_access_token,
		   sf_refresh_token = EXCLUDED.sf_refresh_token,
		   sf_token_issued_at = EXCLUDED.sf_token_issued_at,
		   updated_at = EXCLUDED.updated_at`,
		t.UserID, t.SFInstanceURL, t.SFAccessTokenCrypt, t.SFRefreshTokenCrypt,
		t.SFTokenIssuedAt, t.UpdatedAt)
	return err
}

func (s *PostgresStore) GetUserTokens(ctx context.Context, userID string) (*UserTokens, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, sf_instance_url, sf_access_token, sf_refresh_token, sf_token_issued_at, updated_at
		 FROM user_tokens WHERE user_id = $1`, userID)

	var t UserTokens
	if err := row.Scan(&t.UserID, &t.SFInstanceURL, &t.SFAccessTokenCrypt, &t.SFRefreshTokenCrypt,
		&t.SFTokenIssuedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// --- MCP Refresh Tokens ---

func (s *PostgresStore) SaveMCPRefreshToken(ctx context.Context, token *MCPRefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO mcp_refresh_tokens (token_hash, user_id, mcp_client_id, created_at, expires_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, FALSE)`,
		token.TokenHash, token.UserID, token.MCPClientID,
		token.CreatedAt, token.ExpiresAt)
	return err
}

func (s *PostgresStore) GetMCPRefreshToken(ctx context.Context, tokenHash string) (*MCPRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, mcp_client_id, created_at, expires_at, revoked
		 FROM mcp_refresh_tokens WHERE token_hash = $1`, tokenHash)

	var t MCPRefreshToken
	if err := row.Scan(&t.TokenHash, &t.UserID, &t.MCPClientID, &t.CreatedAt, &t.ExpiresAt, &t.Revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (s *PostgresStore) ClaimMCPRefreshToken(ctx context.Context, tokenHash string) (*MCPRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`UPDATE mcp_refresh_tokens SET revoked = TRUE
		 WHERE token_hash = $1 AND revoked = FALSE AND expires_at > $2
		 RETURNING token_hash, user_id, mcp_client_id, created_at, expires_at, revoked`,
		tokenHash, time.Now())

	var t MCPRefreshToken
	if err := row.Scan(&t.TokenHash, &t.UserID, &t.MCPClientID, &t.CreatedAt, &t.ExpiresAt, &t.Revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("revoking refresh token: %w", err)
	}
	return &t, nil
}
