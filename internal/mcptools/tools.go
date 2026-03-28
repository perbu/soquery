package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perbu/soquery/internal/audit"
	"github.com/perbu/soquery/internal/oauth"
	"github.com/perbu/soquery/internal/sfclient"
	"github.com/perbu/soquery/internal/store"
)

// contextKey is used for storing user info in context.
type contextKey string

const userIDKey contextKey = "user_id"

// UserIDFromContext retrieves the user ID from context.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(userIDKey).(string); ok {
		return v
	}
	return ""
}

// ContextWithUserID returns a context with the user ID set.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// Dependencies holds shared dependencies for tool handlers.
type Dependencies struct {
	Store         store.Store
	EncryptionKey []byte
	JWTSigningKey []byte
	AuditLog      *audit.Logger

	// SF OAuth config for token refresh
	SFClientID     string
	SFClientSecret string
}

// RegisterTools registers all MCP tools on the given server.
func RegisterTools(s *server.MCPServer, deps *Dependencies) {
	s.AddTool(queryTool(), deps.makeHandler("query", handleQuery))
	s.AddTool(describeTool(), deps.makeHandler("describe", handleDescribe))
	s.AddTool(listObjectsTool(), deps.makeHandler("list_objects", handleListObjects))
	s.AddTool(createRecordTool(), deps.makeHandler("create_record", handleCreateRecord))
	s.AddTool(updateRecordTool(), deps.makeHandler("update_record", handleUpdateRecord))
	s.AddTool(deleteRecordTool(), deps.makeHandler("delete_record", handleDeleteRecord))
}

// --- Tool Definitions ---

func queryTool() mcp.Tool {
	return mcp.NewTool("query",
		mcp.WithDescription("Execute a SOQL query against Salesforce and return records as JSON"),
		mcp.WithString("soql", mcp.Description("The SOQL query to execute"), mcp.Required()),
	)
}

func describeTool() mcp.Tool {
	return mcp.NewTool("describe",
		mcp.WithDescription("Describe the fields of a Salesforce SObject"),
		mcp.WithString("sobject", mcp.Description("The SObject API name (e.g., Account, Contact)"), mcp.Required()),
	)
}

func listObjectsTool() mcp.Tool {
	return mcp.NewTool("list_objects",
		mcp.WithDescription("List available Salesforce SObjects with their capabilities"),
	)
}

func createRecordTool() mcp.Tool {
	return mcp.NewTool("create_record",
		mcp.WithDescription("Create a new Salesforce record"),
		mcp.WithString("sobject", mcp.Description("The SObject API name (e.g., Account)"), mcp.Required()),
		mcp.WithObject("fields", mcp.Description("Field name-value pairs for the new record"), mcp.Required()),
	)
}

func updateRecordTool() mcp.Tool {
	return mcp.NewTool("update_record",
		mcp.WithDescription("Update an existing Salesforce record by ID"),
		mcp.WithString("sobject", mcp.Description("The SObject API name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("The record ID to update"), mcp.Required()),
		mcp.WithObject("fields", mcp.Description("Field name-value pairs to update"), mcp.Required()),
	)
}

func deleteRecordTool() mcp.Tool {
	return mcp.NewTool("delete_record",
		mcp.WithDescription("Delete a Salesforce record by ID"),
		mcp.WithString("sobject", mcp.Description("The SObject API name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("The record ID to delete"), mcp.Required()),
	)
}

// --- Tool handler wrapper ---

type toolFunc func(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// makeHandler wraps a tool function with auth, SF client creation, token refresh, and audit logging.
func (d *Dependencies) makeHandler(toolName string, fn toolFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		userID := UserIDFromContext(ctx)
		if userID == "" {
			return errorResult("authentication required"), nil
		}

		client, err := d.getSFClient(ctx, userID)
		if err != nil {
			d.AuditLog.LogToolCall(ctx, userID, toolName, 0, time.Since(start), err)
			return errorResult("failed to create Salesforce client: " + err.Error()), nil
		}

		result, err := fn(ctx, client, request)

		// If we got a 401 from SF, try refreshing the token and retrying once.
		if err != nil && sfclient.IsUnauthorized(err) {
			if refreshErr := d.refreshSFToken(ctx, userID); refreshErr == nil {
				client, err = d.getSFClient(ctx, userID)
				if err == nil {
					result, err = fn(ctx, client, request)
				}
			}
		}

		duration := time.Since(start)
		recordCount := 0
		if result != nil {
			recordCount = len(result.Content)
		}
		d.AuditLog.LogToolCall(ctx, userID, toolName, recordCount, duration, err)

		if err != nil {
			return errorResult(err.Error()), nil
		}
		return result, nil
	}
}

func (d *Dependencies) getSFClient(ctx context.Context, userID string) (*sfclient.Client, error) {
	tokens, err := d.Store.GetUserTokens(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("loading tokens: %w", err)
	}
	if tokens == nil {
		return nil, fmt.Errorf("no Salesforce tokens found for user (re-authentication required)")
	}

	accessToken, err := store.Decrypt(tokens.SFAccessTokenCrypt, d.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting access token: %w", err)
	}

	return sfclient.NewClient(tokens.SFInstanceURL, string(accessToken), nil), nil
}

func (d *Dependencies) refreshSFToken(ctx context.Context, userID string) error {
	tokens, err := d.Store.GetUserTokens(ctx, userID)
	if err != nil || tokens == nil {
		return fmt.Errorf("no tokens to refresh")
	}

	refreshToken, err := store.Decrypt(tokens.SFRefreshTokenCrypt, d.EncryptionKey)
	if err != nil {
		return fmt.Errorf("decrypting refresh token: %w", err)
	}

	newAccess, newInstance, err := oauth.RefreshSFToken(
		tokens.SFInstanceURL, d.SFClientID, d.SFClientSecret, string(refreshToken),
	)
	if err != nil {
		d.AuditLog.LogTokenRefresh(ctx, userID, err)
		return err
	}

	encAccess, err := store.Encrypt([]byte(newAccess), d.EncryptionKey)
	if err != nil {
		return err
	}

	now := time.Now()
	tokens.SFAccessTokenCrypt = encAccess
	tokens.SFInstanceURL = newInstance
	tokens.SFTokenIssuedAt = now
	tokens.UpdatedAt = now

	if err := d.Store.SaveUserTokens(ctx, tokens); err != nil {
		return err
	}

	d.AuditLog.LogTokenRefresh(ctx, userID, nil)
	return nil
}

// --- Tool Handlers ---

func handleQuery(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	soql, err := request.RequireString("soql")
	if err != nil {
		return errorResult("soql parameter is required"), nil
	}

	records, err := client.Query(ctx, soql)
	if err != nil {
		return nil, err
	}

	return jsonResult(records)
}

func handleDescribe(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sobject, err := request.RequireString("sobject")
	if err != nil {
		return errorResult("sobject parameter is required"), nil
	}

	fields, err := client.Describe(ctx, sobject)
	if err != nil {
		return nil, err
	}

	return jsonResult(fields)
}

func handleListObjects(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	objects, err := client.ListObjects(ctx)
	if err != nil {
		return nil, err
	}

	// Filter to only queryable objects for a cleaner list.
	var result []map[string]interface{}
	for _, obj := range objects {
		result = append(result, map[string]interface{}{
			"name":       obj.Name,
			"label":      obj.Label,
			"queryable":  obj.Queryable,
			"createable": obj.Createable,
			"updateable": obj.Updateable,
			"deletable":  obj.Deletable,
		})
	}

	return jsonResult(result)
}

func handleCreateRecord(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sobject, err := request.RequireString("sobject")
	if err != nil {
		return errorResult("sobject parameter is required"), nil
	}

	fields, ok := request.GetArguments()["fields"].(map[string]interface{})
	if !ok {
		return errorResult("fields parameter must be an object"), nil
	}

	result, err := client.CreateRecord(ctx, sobject, fields)
	if err != nil {
		return nil, err
	}

	return jsonResult(result)
}

func handleUpdateRecord(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sobject, err := request.RequireString("sobject")
	if err != nil {
		return errorResult("sobject parameter is required"), nil
	}
	id, err := request.RequireString("id")
	if err != nil {
		return errorResult("id parameter is required"), nil
	}

	fields, ok := request.GetArguments()["fields"].(map[string]interface{})
	if !ok {
		return errorResult("fields parameter must be an object"), nil
	}

	if err := client.UpdateRecord(ctx, sobject, id, fields); err != nil {
		return nil, err
	}

	return textResult(fmt.Sprintf("Record %s updated successfully", id)), nil
}

func handleDeleteRecord(ctx context.Context, client *sfclient.Client, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sobject, err := request.RequireString("sobject")
	if err != nil {
		return errorResult("sobject parameter is required"), nil
	}
	id, err := request.RequireString("id")
	if err != nil {
		return errorResult("id parameter is required"), nil
	}

	if err := client.DeleteRecord(ctx, sobject, id); err != nil {
		return nil, err
	}

	return textResult(fmt.Sprintf("Record %s deleted successfully", id)), nil
}

// --- Result helpers ---

func jsonResult(data interface{}) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling result: %w", err)
	}
	return textResult(string(b)), nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: text,
			},
		},
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: msg,
			},
		},
	}
}
