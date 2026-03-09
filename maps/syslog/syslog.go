package syslog

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	sigma "github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/M00NLIG7/ChopChopGo/maps/mapping"
	"github.com/M00NLIG7/ChopChopGo/maps/output"
	"github.com/schollz/progressbar/v3"
)

func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// parseSyslogTimestamp extracts the leading timestamp from a syslog line without
// regex, eliminating the []string submatch allocation on every line.
// It recognises two formats:
//
//   - BSD syslog: "Mon DD HH:MM:SS" (exactly 15 bytes, space-padded day)
//   - rsyslog/ISO8601: "YYYY-…" terminated by the first space
//
// Returns the timestamp substring and its byte length. Returns ("", 0) when
// the line does not match either format.
func parseSyslogTimestamp(line string) (ts string, n int) {
	// BSD syslog: "Mon DD HH:MM:SS" — 15 bytes, fixed structure.
	if len(line) >= 15 &&
		isAlpha(line[0]) && isAlpha(line[1]) && isAlpha(line[2]) && // Mon
		line[3] == ' ' &&
		(line[4] == ' ' || isDigit(line[4])) && isDigit(line[5]) && // DD (space-padded)
		line[6] == ' ' &&
		isDigit(line[7]) && isDigit(line[8]) && line[9] == ':' && // HH:
		isDigit(line[10]) && isDigit(line[11]) && line[12] == ':' && // MM:
		isDigit(line[13]) && isDigit(line[14]) { // SS
		return line[:15], 15
	}
	// rsyslog/ISO8601: starts with four digits and a '-' (YYYY-).
	// The timestamp ends at the first space.
	if len(line) >= 5 &&
		isDigit(line[0]) && isDigit(line[1]) && isDigit(line[2]) && isDigit(line[3]) &&
		line[4] == '-' {
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			return line[:idx], idx
		}
	}
	return "", 0
}

// SyslogEvent represents a parsed syslog entry.
type SyslogEvent struct {
	Facility  string // hostname (closest available field without <PRI>)
	Severity  string // not available in on-disk syslog format; kept for interface compat
	Message   string // process[pid]: message text
	Timestamp string
}

// Keywords satisfies the sigma.Event interface.
func (e SyslogEvent) Keywords() ([]string, bool) {
	return []string{e.Facility, e.Severity, e.Message}, true
}

// Select satisfies the sigma.Event interface.
func (e SyslogEvent) Select(name string) (interface{}, bool) {
	switch name {
	case "facility":
		return e.Facility, true
	case "severity":
		return e.Severity, true
	case "message":
		return e.Message, true
	default:
		return nil, false
	}
}

// MappedSyslogEvent wraps a SyslogEvent with field-name translation so that
// Sigma rules written with generic field names (e.g. Message, Hostname) are
// resolved to syslog-native names before Select is called.
type MappedSyslogEvent struct {
	SyslogEvent
	m *mapping.Mapping
}

func (e MappedSyslogEvent) Keywords() ([]string, bool) { return e.SyslogEvent.Keywords() }

func (e MappedSyslogEvent) Select(name string) (interface{}, bool) {
	return e.SyslogEvent.Select(e.m.Resolve(name))
}

// ParseEvents reads a syslog file and returns the parsed events.
// Lines that do not match a recognised timestamp format are skipped rather than
// causing an error, so mixed or partial logs are handled gracefully.
func ParseEvents(logFile string) ([]SyslogEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []SyslogEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		timestamp, n := parseSyslogTimestamp(line)
		if timestamp == "" {
			// Skip lines we cannot parse — don't abort the whole scan.
			continue
		}

		// Everything after the timestamp is "hostname proc[pid]: message".
		// We store the hostname in Facility and the rest in Message so that
		// keyword-based Sigma rules can match against process/message content.
		rest := strings.TrimSpace(line[n:])
		var facility, message string
		if idx := strings.IndexByte(rest, ' '); idx >= 0 {
			facility = rest[:idx]
			message = strings.TrimSpace(rest[idx+1:])
		} else {
			message = rest
		}

		events = append(events, SyslogEvent{
			Facility:  facility,
			Severity:  "",
			Message:   message,
			Timestamp: timestamp,
		})
	}
	return events, scanner.Err()
}

// FindLog returns filePath when non-empty, otherwise falls back to the
// standard syslog locations.
func FindLog(file string) (string, error) {
	if file != "" {
		if _, err := os.Stat(file); err != nil {
			return "", fmt.Errorf("failed to find provided file %v", file)
		}
		return file, nil
	}

	for _, path := range []string{"/var/log/syslog", "/var/log/messages"} {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no syslog file found at /var/log/syslog or /var/log/messages")
}

var syslogRenderer = output.Renderer{
	Headers: []string{"Timestamp", "Message", "Tags", "Author"},
	Row: func(r output.ScanResult) []string {
		return []string{r.Timestamp, r.Message, output.TagString(r.Tags), r.Author}
	},
}

// Chop scans the syslog against Sigma rules and writes results to stdout.
// mappingPath overrides the default mappings/syslog.yml when non-empty.
func Chop(rulePath, outputType, filePath, mappingPath string) error {
	syslogPath, err := FindLog(filePath)
	if err != nil {
		return fmt.Errorf("finding syslog: %w", err)
	}

	events, err := ParseEvents(syslogPath)
	if err != nil {
		return fmt.Errorf("parsing syslog: %w", err)
	}

	ruleset, err := sigma.NewRuleset(sigma.Config{Directory: []string{rulePath}})
	if err != nil {
		return fmt.Errorf("loading ruleset: %w", err)
	}

	showProgress := outputType != "json" && outputType != "csv"
	var bar *progressbar.ProgressBar
	if showProgress {
		bar = progressbar.Default(int64(len(events)))
	}

	if mappingPath == "" {
		mappingPath = "mappings/syslog.yml"
	}
	m := mapping.LoadOrIdentity(mappingPath, "syslog")

	var results []output.ScanResult
	for _, event := range events {
		mapped := MappedSyslogEvent{event, m}
		if res, match := ruleset.EvalAll(mapped); match {
			results = append(results, output.ScanResult{
				Timestamp: event.Timestamp,
				Message:   event.Message,
				Tags:      res[0].Tags,
				Author:    res[0].Author,
				RuleID:    res[0].ID,
				Title:     res[0].Title,
			})
		}
		if showProgress {
			bar.Add(1)
		}
	}

	if err := output.Write(os.Stdout, outputType, results, syslogRenderer); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if showProgress {
		fmt.Printf("Processed %d syslog events\n", len(events))
	}
	return nil
}

// ChopToLog is like Chop but calls log.Fatalf on error, for use from main.
func ChopToLog(rulePath, outputType, filePath, mappingPath string) {
	if err := Chop(rulePath, outputType, filePath, mappingPath); err != nil {
		log.Fatalf("syslog: %v", err)
	}
}
