package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// ScanResult is the common result produced by all log mappers after evaluating Sigma rules.
type ScanResult struct {
	Timestamp string   `json:"Timestamp"`
	Message   string   `json:"Message,omitempty"`
	User      string   `json:"User,omitempty"`
	Exe       string   `json:"Exe,omitempty"`
	Terminal  string   `json:"Terminal,omitempty"`
	PID       string   `json:"PID,omitempty"`
	Tags      []string `json:"Tags"`
	Author    string   `json:"Author"`
	RuleID    string   `json:"ID"`
	Title     string   `json:"Title"`
}

// Renderer defines the table/CSV columns for a specific log type.
// JSON output always serialises the full ScanResult struct.
type Renderer struct {
	Headers []string
	Row     func(ScanResult) []string
}

// Write renders results in the requested format to w.
// outputType must be "json", "csv", or any other value for a table.
func Write(w io.Writer, outputType string, results []ScanResult, r Renderer) error {
	switch outputType {
	case "json":
		return writeJSON(w, results)
	case "csv":
		return writeCSV(w, results, r)
	default:
		writeTable(w, results, r)
		return nil
	}
}

func writeJSON(w io.Writer, results []ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func writeCSV(w io.Writer, results []ScanResult, r Renderer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(r.Headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}
	for _, res := range results {
		if err := cw.Write(r.Row(res)); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeTable(w io.Writer, results []ScanResult, r Renderer) {
	table := tablewriter.NewWriter(w)
	table.SetHeader(r.Headers)
	for _, res := range results {
		table.Append(r.Row(res))
	}
	table.Render()
}

// TagString joins tags with a dash, matching the original output format.
func TagString(tags []string) string {
	return strings.Join(tags, "-")
}
