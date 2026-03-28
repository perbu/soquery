package audit

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Logger wraps slog for structured audit logging.
type Logger struct {
	logger *slog.Logger
}

// New creates an audit logger that writes structured JSON to stdout.
func New() *Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return &Logger{logger: slog.New(handler)}
}

// LogToolCall logs an MCP tool invocation.
func (l *Logger) LogToolCall(ctx context.Context, userID, tool string, recordCount int, duration time.Duration, err error) {
	attrs := []slog.Attr{
		slog.String("event", "tool_call"),
		slog.String("user_id", userID),
		slog.String("tool", tool),
		slog.Int("record_count", recordCount),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.Bool("success", err == nil),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, "tool_call", attrs...)
}

// LogAuth logs an authentication event.
func (l *Logger) LogAuth(ctx context.Context, event, userID string, err error) {
	attrs := []slog.Attr{
		slog.String("event", event),
		slog.String("user_id", userID),
		slog.Bool("success", err == nil),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, event, attrs...)
}

// LogDCR logs a dynamic client registration event.
func (l *Logger) LogDCR(ctx context.Context, clientID, clientName string) {
	l.logger.LogAttrs(ctx, slog.LevelInfo, "dcr_register",
		slog.String("event", "dcr_register"),
		slog.String("client_id", clientID),
		slog.String("client_name", clientName),
	)
}

// LogTokenRefresh logs a Salesforce token refresh event.
func (l *Logger) LogTokenRefresh(ctx context.Context, userID string, err error) {
	attrs := []slog.Attr{
		slog.String("event", "token_refresh"),
		slog.String("user_id", userID),
		slog.Bool("success", err == nil),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, "token_refresh", attrs...)
}
