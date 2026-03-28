package store

import (
	"os"
	"testing"
)

func testPostgresStore(t *testing.T) Store {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_URL")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping PostgreSQL tests")
	}
	s, err := NewPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up test data before closing.
		pg := s
		pg.db.Exec("DELETE FROM mcp_refresh_tokens")
		pg.db.Exec("DELETE FROM auth_codes")
		pg.db.Exec("DELETE FROM auth_sessions")
		pg.db.Exec("DELETE FROM user_tokens")
		pg.db.Exec("DELETE FROM dcr_clients")
		s.Close()
	})
	return s
}

func TestPostgres(t *testing.T) {
	runStoreConformanceTests(t, testPostgresStore(t))
}
