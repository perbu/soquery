package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// FormatMarkdown writes records as a markdown table to w.
// Returns an error if records is empty.
func FormatMarkdown(w io.Writer, records []map[string]interface{}) error {
	if len(records) == 0 {
		fmt.Fprintln(w, "No records found.")
		return nil
	}

	// Extract and flatten columns from the first record.
	columns := extractColumns(records[0])

	// Header row.
	fmt.Fprintf(w, "| %s |\n", strings.Join(columns, " | "))

	// Separator row.
	seps := make([]string, len(columns))
	for i := range seps {
		seps[i] = "---"
	}
	fmt.Fprintf(w, "| %s |\n", strings.Join(seps, " | "))

	// Data rows.
	for _, rec := range records {
		vals := make([]string, len(columns))
		for i, col := range columns {
			vals[i] = escapeCell(resolveValue(rec, col))
		}
		fmt.Fprintf(w, "| %s |\n", strings.Join(vals, " | "))
	}

	return nil
}

// extractColumns returns sorted column names from a record,
// skipping the "attributes" metadata key and flattening nested objects.
func extractColumns(record map[string]interface{}) []string {
	var columns []string
	for key, val := range record {
		if key == "attributes" {
			continue
		}
		if nested, ok := val.(map[string]interface{}); ok {
			// Flatten nested relationship objects (e.g. Account.Name).
			for nestedKey := range nested {
				if nestedKey == "attributes" {
					continue
				}
				columns = append(columns, key+"."+nestedKey)
			}
		} else {
			columns = append(columns, key)
		}
	}
	sort.Strings(columns)
	return columns
}

// resolveValue gets a potentially nested value using dot notation.
func resolveValue(record map[string]interface{}, key string) string {
	parts := strings.SplitN(key, ".", 2)
	val, ok := record[parts[0]]
	if !ok || val == nil {
		return ""
	}
	if len(parts) == 2 {
		if nested, ok := val.(map[string]interface{}); ok {
			return resolveValue(nested, parts[1])
		}
		return ""
	}
	return fmt.Sprintf("%v", val)
}

// escapeCell escapes pipe characters in cell values.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
