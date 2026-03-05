package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const apiVersion = "v62.0"

type QueryResult struct {
	TotalSize      int                      `json:"totalSize"`
	Done           bool                     `json:"done"`
	NextRecordsURL string                   `json:"nextRecordsUrl"`
	Records        []map[string]interface{} `json:"records"`
}

type Client struct {
	instanceURL string
	accessToken string
	httpClient  *http.Client
}

func NewClient(instanceURL, accessToken string) *Client {
	return &Client{
		instanceURL: instanceURL,
		accessToken: accessToken,
		httpClient:  &http.Client{},
	}
}

// Query executes a SOQL query and returns all records, handling pagination.
func (c *Client) Query(soql string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/services/data/%s/query?q=%s",
		c.instanceURL, apiVersion, url.QueryEscape(soql))

	var allRecords []map[string]interface{}

	for endpoint != "" {
		result, err := c.fetchPage(endpoint)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, result.Records...)

		if result.Done {
			break
		}
		endpoint = c.instanceURL + result.NextRecordsURL
	}

	return allRecords, nil
}

// Describe returns the fields of an SObject as a slice of maps suitable for FormatMarkdown.
func (c *Client) Describe(sobject string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/services/data/%s/sobjects/%s/describe",
		c.instanceURL, apiVersion, url.PathEscape(sobject))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("salesforce API error (HTTP %d): %s", resp.StatusCode, body)
	}

	var result struct {
		Fields []map[string]interface{} `json:"fields"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Return a simplified view of each field.
	var rows []map[string]interface{}
	for _, f := range result.Fields {
		rows = append(rows, map[string]interface{}{
			"Name":     f["name"],
			"Type":     f["type"],
			"Label":    f["label"],
			"Nillable": f["nillable"],
		})
	}

	return rows, nil
}

func (c *Client) fetchPage(endpoint string) (*QueryResult, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("salesforce API error (HTTP %d): %s", resp.StatusCode, body)
	}

	var result QueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &result, nil
}
