package sfclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListObjects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(SObjectListResult{
			SObjects: []SObjectInfo{
				{Name: "Account", Label: "Account", Queryable: true, Createable: true},
				{Name: "Contact", Label: "Contact", Queryable: true, Createable: true},
			},
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	objs, err := c.ListObjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objs))
	}
	if objs[0].Name != "Account" {
		t.Errorf("expected Account, got %s", objs[0].Name)
	}
}

func TestCreateRecord(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var fields map[string]interface{}
		json.Unmarshal(body, &fields)
		if fields["Name"] != "Test Account" {
			t.Errorf("expected Name=Test Account, got %v", fields["Name"])
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CreateResult{ID: "001new", Success: true})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	result, err := c.CreateRecord(context.Background(), "Account", map[string]interface{}{"Name": "Test Account"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "001new" {
		t.Errorf("expected ID 001new, got %s", result.ID)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestUpdateRecord(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	err := c.UpdateRecord(context.Background(), "Account", "001abc", map[string]interface{}{"Name": "Updated"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRecord(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	err := c.DeleteRecord(context.Background(), "Account", "001abc")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateRecord_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`[{"message":"required field missing"}]`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token", ts.Client())
	_, err := c.CreateRecord(context.Background(), "Account", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}
