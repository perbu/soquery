package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// This should never happen with data we wrote, but return zero time
		// rather than panicking.
		return time.Time{}
	}
	return t
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS dcr_clients (
	client_id     TEXT PRIMARY KEY,
	client_secret TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	client_name   TEXT,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
	session_id         TEXT PRIMARY KEY,
	mcp_client_id      TEXT NOT NULL,
	mcp_redirect_uri   TEXT NOT NULL,
	mcp_state          TEXT NOT NULL,
	mcp_code_challenge TEXT NOT NULL,
	mcp_code_method    TEXT NOT NULL DEFAULT 'S256',
	created_at         TEXT NOT NULL,
	expires_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
	code            TEXT PRIMARY KEY,
	user_id         TEXT NOT NULL,
	mcp_client_id   TEXT NOT NULL,
	redirect_uri    TEXT NOT NULL,
	code_challenge  TEXT NOT NULL,
	code_method     TEXT NOT NULL DEFAULT 'S256',
	created_at      TEXT NOT NULL,
	expires_at      TEXT NOT NULL,
	used            INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_tokens (
	user_id             TEXT PRIMARY KEY,
	sf_instance_url     TEXT NOT NULL,
	sf_access_token     BLOB NOT NULL,
	sf_refresh_token    BLOB NOT NULL,
	sf_token_issued_at  TEXT NOT NULL,
	updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
	token_hash    TEXT PRIMARY KEY,
	user_id       TEXT NOT NULL,
	mcp_client_id TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	expires_at    TEXT NOT NULL,
	revoked       INTEGER NOT NULL DEFAULT 0
);
`

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLite opens a SQLite database and runs migrations.
func NewSQLite(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// --- DCR Clients ---

func (s *SQLiteStore) SaveDCRClient(ctx context.Context, c *DCRClient) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO dcr_clients (client_id, client_secret, redirect_uris, client_name, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		c.ClientID, c.ClientSecret, string(uris), c.ClientName, c.CreatedAt.Format(time.RFC3339))
	return err
}

func (s *SQLiteStore) GetDCRClient(ctx context.Context, clientID string) (*DCRClient, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_secret, redirect_uris, client_name, created_at FROM dcr_clients WHERE client_id = ?`,
		clientID)

	var c DCRClient
	var urisJSON, createdAt string
	if err := row.Scan(&c.ClientID, &c.ClientSecret, &urisJSON, &c.ClientName, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("parsing redirect_uris: %w", err)
	}
	c.CreatedAt = mustParseTime(createdAt)
	return &c, nil
}

// --- Auth Sessions ---

func (s *SQLiteStore) SaveAuthSession(ctx context.Context, sess *AuthSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_sessions (session_id, mcp_client_id, mcp_redirect_uri, mcp_state, mcp_code_challenge, mcp_code_method, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.SessionID, sess.MCPClientID, sess.MCPRedirectURI, sess.MCPState,
		sess.MCPCodeChallenge, sess.MCPCodeMethod,
		sess.CreatedAt.Format(time.RFC3339), sess.ExpiresAt.Format(time.RFC3339))
	return err
}

func (s *SQLiteStore) GetAuthSession(ctx context.Context, sessionID string) (*AuthSession, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_id, mcp_client_id, mcp_redirect_uri, mcp_state, mcp_code_challenge, mcp_code_method, created_at, expires_at
		 FROM auth_sessions WHERE session_id = ?`, sessionID)

	var sess AuthSession
	var createdAt, expiresAt string
	if err := row.Scan(&sess.SessionID, &sess.MCPClientID, &sess.MCPRedirectURI, &sess.MCPState,
		&sess.MCPCodeChallenge, &sess.MCPCodeMethod, &createdAt, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sess.CreatedAt = mustParseTime(createdAt)
	sess.ExpiresAt = mustParseTime(expiresAt)
	return &sess, nil
}

func (s *SQLiteStore) DeleteAuthSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE session_id = ?`, sessionID)
	return err
}

// --- Auth Codes ---

func (s *SQLiteStore) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes (code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at, used)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		code.Code, code.UserID, code.MCPClientID, code.RedirectURI,
		code.CodeChallenge, code.CodeMethod,
		code.CreatedAt.Format(time.RFC3339), code.ExpiresAt.Format(time.RFC3339))
	return err
}

func (s *SQLiteStore) GetAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at, used
		 FROM auth_codes WHERE code = ?`, code)

	var ac AuthCode
	var createdAt, expiresAt string
	var used int
	if err := row.Scan(&ac.Code, &ac.UserID, &ac.MCPClientID, &ac.RedirectURI,
		&ac.CodeChallenge, &ac.CodeMethod, &createdAt, &expiresAt, &used); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	ac.CreatedAt = mustParseTime(createdAt)
	ac.ExpiresAt = mustParseTime(expiresAt)
	ac.Used = used != 0
	return &ac, nil
}

func (s *SQLiteStore) ClaimAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE auth_codes SET used = 1 WHERE code = ? AND used = 0 AND expires_at > ?`,
		code, time.Now().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("claiming auth code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return nil, nil // already used, expired, or not found
	}

	row := tx.QueryRowContext(ctx,
		`SELECT code, user_id, mcp_client_id, redirect_uri, code_challenge, code_method, created_at, expires_at
		 FROM auth_codes WHERE code = ?`, code)

	var ac AuthCode
	var createdAt, expiresAt string
	if err := row.Scan(&ac.Code, &ac.UserID, &ac.MCPClientID, &ac.RedirectURI,
		&ac.CodeChallenge, &ac.CodeMethod, &createdAt, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading claimed code: %w", err)
	}
	ac.CreatedAt = mustParseTime(createdAt)
	ac.ExpiresAt = mustParseTime(expiresAt)
	ac.Used = true

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}
	return &ac, nil
}

// --- User Tokens ---

func (s *SQLiteStore) SaveUserTokens(ctx context.Context, t *UserTokens) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO user_tokens (user_id, sf_instance_url, sf_access_token, sf_refresh_token, sf_token_issued_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.UserID, t.SFInstanceURL, t.SFAccessTokenCrypt, t.SFRefreshTokenCrypt,
		t.SFTokenIssuedAt.Format(time.RFC3339), t.UpdatedAt.Format(time.RFC3339))
	return err
}

func (s *SQLiteStore) GetUserTokens(ctx context.Context, userID string) (*UserTokens, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, sf_instance_url, sf_access_token, sf_refresh_token, sf_token_issued_at, updated_at
		 FROM user_tokens WHERE user_id = ?`, userID)

	var t UserTokens
	var issuedAt, updatedAt string
	if err := row.Scan(&t.UserID, &t.SFInstanceURL, &t.SFAccessTokenCrypt, &t.SFRefreshTokenCrypt,
		&issuedAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t.SFTokenIssuedAt = mustParseTime(issuedAt)
	t.UpdatedAt = mustParseTime(updatedAt)
	return &t, nil
}

// --- MCP Refresh Tokens ---

func (s *SQLiteStore) SaveMCPRefreshToken(ctx context.Context, token *MCPRefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO mcp_refresh_tokens (token_hash, user_id, mcp_client_id, created_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 0)`,
		token.TokenHash, token.UserID, token.MCPClientID,
		token.CreatedAt.Format(time.RFC3339), token.ExpiresAt.Format(time.RFC3339))
	return err
}

func (s *SQLiteStore) GetMCPRefreshToken(ctx context.Context, tokenHash string) (*MCPRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, mcp_client_id, created_at, expires_at, revoked
		 FROM mcp_refresh_tokens WHERE token_hash = ?`, tokenHash)

	var t MCPRefreshToken
	var createdAt, expiresAt string
	var revoked int
	if err := row.Scan(&t.TokenHash, &t.UserID, &t.MCPClientID, &createdAt, &expiresAt, &revoked); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t.CreatedAt = mustParseTime(createdAt)
	t.ExpiresAt = mustParseTime(expiresAt)
	t.Revoked = revoked != 0
	return &t, nil
}

func (s *SQLiteStore) ClaimMCPRefreshToken(ctx context.Context, tokenHash string) (*MCPRefreshToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE mcp_refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0 AND expires_at > ?`,
		tokenHash, time.Now().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("revoking refresh token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("checking rows affected: %w", err)
	}
	if n == 0 {
		return nil, nil // already revoked, expired, or not found
	}

	row := tx.QueryRowContext(ctx,
		`SELECT token_hash, user_id, mcp_client_id, created_at, expires_at
		 FROM mcp_refresh_tokens WHERE token_hash = ?`, tokenHash)

	var t MCPRefreshToken
	var createdAt, expiresAt string
	if err := row.Scan(&t.TokenHash, &t.UserID, &t.MCPClientID, &createdAt, &expiresAt); err != nil {
		return nil, fmt.Errorf("reading claimed token: %w", err)
	}
	t.CreatedAt = mustParseTime(createdAt)
	t.ExpiresAt = mustParseTime(expiresAt)
	t.Revoked = true

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}
	return &t, nil
}

// OpenStore opens a store based on the DSN. Supports "sqlite:" prefix for SQLite
// and "postgres://" prefix for PostgreSQL.
func OpenStore(dsn string) (Store, error) {
	switch {
	case strings.HasPrefix(dsn, "sqlite:"):
		return NewSQLite(strings.TrimPrefix(dsn, "sqlite:"))
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		return nil, fmt.Errorf("PostgreSQL support not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported database DSN: %s", dsn)
	}
}
