package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

var testRenderer = Renderer{
	Headers: []string{"Timestamp", "Message", "Tags", "Author", "ID", "Title"},
	Row: func(r ScanResult) []string {
		return []string{r.Timestamp, r.Message, TagString(r.Tags), r.Author, r.RuleID, r.Title}
	},
}

var sampleResults = []ScanResult{
	{
		Timestamp: "2023-01-01T00:00:00Z",
		Message:   "test message",
		User:      "1000",
		Tags:      []string{"attack.execution", "attack.t1059"},
		Author:    "Test Author",
		RuleID:    "abc-123",
		Title:     "Test Rule",
	},
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sampleResults, testRenderer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out []ScanResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	if out[0].Title != "Test Rule" {
		t.Errorf("expected Title=Test Rule, got %q", out[0].Title)
	}
	if out[0].RuleID != "abc-123" {
		t.Errorf("expected RuleID=abc-123, got %q", out[0].RuleID)
	}
	if len(out[0].Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(out[0].Tags))
	}
}

func TestWriteJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", []ScanResult{}, testRenderer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	trimmed := strings.TrimSpace(buf.String())
	if trimmed != "[]" {
		t.Errorf("expected [] for empty results, got %q", trimmed)
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "csv", sampleResults, testRenderer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 data row, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "Timestamp") {
		t.Errorf("CSV header missing Timestamp: %q", lines[0])
	}
	if !strings.Contains(lines[1], "Test Rule") {
		t.Errorf("CSV row missing title: %q", lines[1])
	}
	// Tags should be joined with dash
	if !strings.Contains(lines[1], "attack.execution-attack.t1059") {
		t.Errorf("CSV tags not joined with dash: %q", lines[1])
	}
}

func TestWriteCSVEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "csv", []ScanResult{}, testRenderer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should at minimum write the header
	if !strings.Contains(buf.String(), "Timestamp") {
		t.Errorf("empty CSV should still contain header, got: %q", buf.String())
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sampleResults, testRenderer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TIMESTAMP") {
		t.Errorf("table missing TIMESTAMP header, got: %q", out)
	}
	if !strings.Contains(out, "Test Rule") {
		t.Errorf("table missing rule title, got: %q", out)
	}
}

func TestWriteUnknownTypeDefaultsToTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "unknown", sampleResults, testRenderer); err != nil {
		t.Fatalf("unexpected error for unknown output type: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output for unknown type (should render table)")
	}
}

func TestTagString(t *testing.T) {
	if TagString([]string{"a", "b", "c"}) != "a-b-c" {
		t.Error("TagString should join with dash")
	}
	if TagString([]string{}) != "" {
		t.Error("TagString of empty slice should return empty string")
	}
	if TagString([]string{"only"}) != "only" {
		t.Error("TagString of single element should return that element")
	}
}
