package sfclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// QueryResult represents the response from a Salesforce SOQL query.
type QueryResult struct {
	TotalSize      int                      `json:"totalSize"`
	Done           bool                     `json:"done"`
	NextRecordsURL string                   `json:"nextRecordsUrl"`
	Records        []map[string]interface{} `json:"records"`
}

// MaxQueryRecords is the maximum number of records returned by Query to prevent OOM.
const MaxQueryRecords = 10_000

// Query executes a SOQL query and returns all records, handling pagination.
// Returns at most MaxQueryRecords records.
func (c *Client) Query(ctx context.Context, soql string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/services/data/%s/query?q=%s",
		c.instanceURL, APIVersion, url.QueryEscape(soql))

	var allRecords []map[string]interface{}

	for endpoint != "" {
		result, err := c.fetchPage(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, result.Records...)

		if len(allRecords) >= MaxQueryRecords {
			break
		}
		if result.Done {
			break
		}
		endpoint = c.instanceURL + result.NextRecordsURL
	}

	return allRecords, nil
}

// Describe returns the fields of an SObject as a slice of maps.
func (c *Client) Describe(ctx context.Context, sobject string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/services/data/%s/sobjects/%s/describe",
		c.instanceURL, APIVersion, url.PathEscape(sobject))

	req, err := http.NewRequest("GET", endpoint, nil)
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

	var result struct {
		Fields []map[string]interface{} `json:"fields"`
	}
	if err := parseJSON(body, &result); err != nil {
		return nil, err
	}

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

func (c *Client) fetchPage(ctx context.Context, endpoint string) (*QueryResult, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
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

	var result QueryResult
	if err := parseJSON(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
