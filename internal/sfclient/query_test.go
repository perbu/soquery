package sfclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQuery_SinglePage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing or wrong Authorization header")
		}
		json.NewEncoder(w).Encode(QueryResult{
			TotalSize: 2,
			Done:      true,
			Records: []map[string]interface{}{
				{"Id": "001", "Name": "Acme"},
				{"Id": "002", "Name": "Globex"},
			},
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	records, err := c.Query(context.Background(), "SELECT Id, Name FROM Account")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestQuery_Pagination(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(QueryResult{
				TotalSize:      2,
				Done:           false,
				NextRecordsURL: "/services/data/v62.0/query/next-page",
				Records:        []map[string]interface{}{{"Id": "001"}},
			})
		} else {
			json.NewEncoder(w).Encode(QueryResult{
				TotalSize: 2,
				Done:      true,
				Records:   []map[string]interface{}{{"Id": "002"}},
			})
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	records, err := c.Query(context.Background(), "SELECT Id FROM Account")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if callCount != 2 {
		t.Fatalf("expected 2 API calls, got %d", callCount)
	}
}

func TestQuery_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`[{"message":"bad query"}]`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	_, err := c.Query(context.Background(), "BAD QUERY")
	if err == nil {
		t.Fatal("expected error")
	}
	sfErr, ok := err.(*SFError)
	if !ok {
		t.Fatalf("expected SFError, got %T", err)
	}
	if sfErr.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", sfErr.StatusCode)
	}
}

func TestDescribe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"fields": []map[string]interface{}{
				{"name": "Id", "type": "id", "label": "Record ID", "nillable": false},
				{"name": "Name", "type": "string", "label": "Account Name", "nillable": false},
			},
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	rows, err := c.Describe(context.Background(), "Account")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0]["Name"] != "Id" {
		t.Errorf("expected field name Id, got %v", rows[0]["Name"])
	}
}

func TestIsUnauthorized(t *testing.T) {
	err := &SFError{StatusCode: 401, Body: "expired"}
	if !IsUnauthorized(err) {
		t.Error("expected IsUnauthorized to return true for 401")
	}
	err2 := &SFError{StatusCode: 400, Body: "bad"}
	if IsUnauthorized(err2) {
		t.Error("expected IsUnauthorized to return false for 400")
	}
}
