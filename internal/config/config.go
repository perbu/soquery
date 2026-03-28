package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Config holds the server configuration loaded from environment variables.
type Config struct {
	Port        string
	ExternalURL string // Public URL of this server (for OAuth redirects)

	SFDomain       string // Salesforce domain (e.g., varnish.my.salesforce.com)
	SFClientID     string // Connected App consumer key
	SFClientSecret string // Connected App consumer secret

	DatabaseURL string // postgres:// or sqlite: connection string

	TokenEncryptionKey []byte // 32-byte AES-256 key
	JWTSigningKey      []byte // 32-byte HMAC-SHA256 key
}

// Load reads configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	c := &Config{
		Port:           getEnvDefault("PORT", "8080"),
		ExternalURL:    os.Getenv("EXTERNAL_URL"),
		SFDomain:       os.Getenv("SF_DOMAIN"),
		SFClientID:     os.Getenv("SF_CLIENT_ID"),
		SFClientSecret: os.Getenv("SF_CLIENT_SECRET"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
	}

	// Trim trailing slash from external URL.
	c.ExternalURL = strings.TrimRight(c.ExternalURL, "/")

	var missing []string
	if c.ExternalURL == "" {
		missing = append(missing, "EXTERNAL_URL")
	}
	if c.SFDomain == "" {
		missing = append(missing, "SF_DOMAIN")
	}
	if c.SFClientID == "" {
		missing = append(missing, "SF_CLIENT_ID")
	}
	if c.SFClientSecret == "" {
		missing = append(missing, "SF_CLIENT_SECRET")
	}
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}

	encKey, err := loadBase64Key("TOKEN_ENCRYPTION_KEY", 32)
	if err != nil {
		return nil, err
	}
	c.TokenEncryptionKey = encKey

	jwtKey, err := loadBase64Key("JWT_SIGNING_KEY", 32)
	if err != nil {
		return nil, err
	}
	c.JWTSigningKey = jwtKey

	if encKey == nil {
		missing = append(missing, "TOKEN_ENCRYPTION_KEY")
	}
	if jwtKey == nil {
		missing = append(missing, "JWT_SIGNING_KEY")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return c, nil
}

// SFInstanceURL returns the full Salesforce instance URL.
func (c *Config) SFInstanceURL() string {
	return "https://" + c.SFDomain
}

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func loadBase64Key(envVar string, expectedLen int) ([]byte, error) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid base64: %w", envVar, err)
	}
	if len(key) < expectedLen {
		return nil, fmt.Errorf("%s: expected at least %d bytes, got %d", envVar, expectedLen, len(key))
	}
	key = key[:expectedLen]
	return key, nil
}
