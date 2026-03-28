package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perbu/soquery/internal/audit"
	"github.com/perbu/soquery/internal/config"
	"github.com/perbu/soquery/internal/mcptools"
	oauthpkg "github.com/perbu/soquery/internal/oauth"
	"github.com/perbu/soquery/internal/store"
)

func main() {
	// Load .env for local development (ignored in production).
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	auditLog := audit.New()

	// Open database.
	db, err := store.OpenStore(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	defer db.Close()

	// Create OAuth server.
	dcrLimiter := oauthpkg.NewIPRateLimiter(10, 1*time.Minute)
	oauthServer := &oauthpkg.Server{
		ExternalURL:    cfg.ExternalURL,
		SFInstanceURL:  cfg.SFInstanceURL(),
		SFClientID:     cfg.SFClientID,
		SFClientSecret: cfg.SFClientSecret,
		Store:          db,
		EncryptionKey:  cfg.TokenEncryptionKey,
		JWTSigningKey:  cfg.JWTSigningKey,
		AuditLog:       auditLog,
		DCRRateLimit:   dcrLimiter,
	}

	// Periodically clean up stale rate-limiter entries.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			dcrLimiter.Cleanup()
		}
	}()

	// Create MCP server.
	mcpServer := server.NewMCPServer(
		"soquery",
		"2.0.0",
		server.WithToolCapabilities(true),
		server.WithInstructions(mcpInstructions),
	)

	// Register tools.
	deps := &mcptools.Dependencies{
		Store:          db,
		EncryptionKey:  cfg.TokenEncryptionKey,
		JWTSigningKey:  cfg.JWTSigningKey,
		AuditLog:       auditLog,
		SFClientID:     cfg.SFClientID,
		SFClientSecret: cfg.SFClientSecret,
	}
	mcptools.RegisterTools(mcpServer, deps)

	// Create Streamable HTTP transport for MCP.
	mcpHTTP := server.NewStreamableHTTPServer(mcpServer,
		server.WithEndpointPath("/mcp"),
		server.WithHTTPContextFunc(mcptools.HTTPContextFunc(cfg.JWTSigningKey)),
	)

	// Build the HTTP mux.
	mux := http.NewServeMux()

	// OAuth endpoints (no auth required).
	oauthServer.RegisterRoutes(mux)

	// MCP endpoint (auth required via HTTPContextFunc).
	mux.Handle("/mcp", mcptools.AuthMiddleware(cfg.JWTSigningKey, mcpHTTP))

	// Health endpoints.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Start HTTP server with graceful shutdown.
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("server starting", "port", cfg.Port, "external_url", cfg.ExternalURL)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	slog.Info("server stopped")
}

const mcpInstructions = `You are connected to a Salesforce MCP server. Available tools:

- query: Execute SOQL queries (e.g., "SELECT Id, Name FROM Account LIMIT 10")
- describe: Get field metadata for any SObject (e.g., describe Account)
- list_objects: List all available Salesforce objects
- create_record: Create new records (specify sobject and fields)
- update_record: Update records by ID (specify sobject, id, and fields)
- delete_record: Delete records by ID (specify sobject and id)

Use 'describe' to discover available fields before writing queries.
Use 'list_objects' to discover what objects are available.
Always use SOQL syntax for queries (similar to SQL but with Salesforce-specific features).`

// Ensure mcp import is used (for WithInstructions which uses mcp types internally).
var _ = mcp.LATEST_PROTOCOL_VERSION
