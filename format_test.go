package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatMarkdown_basic(t *testing.T) {
	records := []map[string]interface{}{
		{
			"attributes": map[string]interface{}{"type": "Account"},
			"Id":         "001xx000003DGbY",
			"Name":       "Acme Corp",
		},
		{
			"attributes": map[string]interface{}{"type": "Account"},
			"Id":         "001xx000003DGbZ",
			"Name":       "Globex",
		},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(&buf, records)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d:\n%s", len(lines), out)
	}

	// Header should contain Id and Name, not attributes.
	if !strings.Contains(lines[0], "Id") || !strings.Contains(lines[0], "Name") {
		t.Errorf("header missing columns: %s", lines[0])
	}
	if strings.Contains(lines[0], "attributes") {
		t.Errorf("header should not contain attributes: %s", lines[0])
	}

	// Separator row.
	if !strings.Contains(lines[1], "---") {
		t.Errorf("expected separator row: %s", lines[1])
	}

	// Data rows.
	if !strings.Contains(lines[2], "Acme Corp") {
		t.Errorf("expected Acme Corp in row: %s", lines[2])
	}
	if !strings.Contains(lines[3], "Globex") {
		t.Errorf("expected Globex in row: %s", lines[3])
	}
}

func TestFormatMarkdown_nested(t *testing.T) {
	records := []map[string]interface{}{
		{
			"attributes": map[string]interface{}{"type": "Contact"},
			"Name":       "John Doe",
			"Account": map[string]interface{}{
				"attributes": map[string]interface{}{"type": "Account"},
				"Name":       "Acme Corp",
			},
		},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(&buf, records)
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "Account.Name") {
		t.Errorf("expected flattened column Account.Name: %s", out)
	}
	if !strings.Contains(out, "Acme Corp") {
		t.Errorf("expected nested value Acme Corp: %s", out)
	}
}

func TestFormatMarkdown_empty(t *testing.T) {
	var buf bytes.Buffer
	err := FormatMarkdown(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No records found") {
		t.Errorf("expected no records message, got: %s", buf.String())
	}
}

func TestFormatMarkdown_nullValues(t *testing.T) {
	records := []map[string]interface{}{
		{
			"attributes": map[string]interface{}{"type": "Account"},
			"Id":         "001",
			"Name":       nil,
		},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(&buf, records)
	if err != nil {
		t.Fatal(err)
	}

	// Should not panic, nil renders as empty string.
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), out)
	}
}

func TestEscapeCell(t *testing.T) {
	if got := escapeCell("a|b"); got != "a\\|b" {
		t.Errorf("expected escaped pipe, got: %s", got)
	}
	if got := escapeCell("line1\nline2"); got != "line1 line2" {
		t.Errorf("expected newline replaced, got: %s", got)
	}
}
