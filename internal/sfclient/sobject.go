package sfclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// SObjectListResult represents the response from listing available SObjects.
type SObjectListResult struct {
	SObjects []SObjectInfo `json:"sobjects"`
}

// SObjectInfo contains basic metadata about a Salesforce SObject.
type SObjectInfo struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	Queryable  bool   `json:"queryable"`
	Createable bool   `json:"createable"`
	Updateable bool   `json:"updateable"`
	Deletable  bool   `json:"deletable"`
}

// CreateResult represents the response from creating a record.
type CreateResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
}

func (c *Client) apiURL(path string) string {
	return fmt.Sprintf("%s/services/data/%s/%s", c.instanceURL, APIVersion, path)
}

// ListObjects returns available SObjects in the org.
func (c *Client) ListObjects(ctx context.Context) ([]SObjectInfo, error) {
	req, err := http.NewRequest("GET", c.apiURL("sobjects/"), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	body, statusCode, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(body, statusCode, http.StatusOK); err != nil {
		return nil, err
	}

	var result SObjectListResult
	if err := parseJSON(body, &result); err != nil {
		return nil, err
	}

	return result.SObjects, nil
}

// CreateRecord creates a new record of the given SObject type.
func (c *Client) CreateRecord(ctx context.Context, sobject string, fields map[string]interface{}) (*CreateResult, error) {
	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("marshalling fields: %w", err)
	}

	req, err := http.NewRequest("POST", c.apiURL("sobjects/"+url.PathEscape(sobject)+"/"), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	body, statusCode, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(body, statusCode, http.StatusCreated); err != nil {
		return nil, err
	}

	var result CreateResult
	if err := parseJSON(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateRecord updates an existing record by ID.
func (c *Client) UpdateRecord(ctx context.Context, sobject, id string, fields map[string]interface{}) error {
	payload, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("marshalling fields: %w", err)
	}

	req, err := http.NewRequest("PATCH", c.apiURL("sobjects/"+url.PathEscape(sobject)+"/"+url.PathEscape(id)), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	body, statusCode, err := c.doRequest(ctx, req)
	if err != nil {
		return err
	}
	return checkStatus(body, statusCode, http.StatusNoContent)
}

// DeleteRecord deletes a record by ID.
func (c *Client) DeleteRecord(ctx context.Context, sobject, id string) error {
	req, err := http.NewRequest("DELETE", c.apiURL("sobjects/"+url.PathEscape(sobject)+"/"+url.PathEscape(id)), nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	body, statusCode, err := c.doRequest(ctx, req)
	if err != nil {
		return err
	}
	return checkStatus(body, statusCode, http.StatusNoContent)
}
