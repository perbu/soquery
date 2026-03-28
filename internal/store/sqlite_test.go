package store

import (
	"path/filepath"
	"testing"
)

func testSQLiteStore(t *testing.T) Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLite(t *testing.T) {
	runStoreConformanceTests(t, testSQLiteStore(t))
}
