package mcptools

import (
	"context"
	"net/http"
	"strings"

	"github.com/perbu/soquery/internal/oauth"
)

// extractUserID validates the Bearer JWT from the request and returns the user ID.
// Returns empty string if auth fails.
func extractUserID(jwtSigningKey []byte, r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := oauth.ValidateAccessToken(jwtSigningKey, tokenStr)
	if err != nil {
		return ""
	}
	return claims.Sub
}

// AuthMiddleware validates Bearer JWT tokens on MCP requests
// and injects the user ID into the context.
func AuthMiddleware(jwtSigningKey []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := extractUserID(jwtSigningKey, r)
		if userID == "" {
			http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
			return
		}
		ctx := ContextWithUserID(r.Context(), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HTTPContextFunc returns a function suitable for mcp-go's WithHTTPContextFunc option.
// It reads the user ID already set by AuthMiddleware from the context.
func HTTPContextFunc(_ []byte) func(ctx context.Context, r *http.Request) context.Context {
	return func(ctx context.Context, r *http.Request) context.Context {
		// User ID was already set by AuthMiddleware on the request context.
		if userID := UserIDFromContext(r.Context()); userID != "" {
			return ContextWithUserID(ctx, userID)
		}
		return ctx
	}
}
