package syslog

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	sigma "github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/M00NLIG7/ChopChopGo/maps/mapping"
	"github.com/M00NLIG7/ChopChopGo/maps/output"
	"github.com/schollz/progressbar/v3"
)

// Compiled once at package level to avoid per-line overhead.
var (
	syslogRe  = regexp.MustCompile(`^([a-zA-Z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
	rsyslogRe = regexp.MustCompile(`^((-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?)`)
)

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

		var timestamp string
		if m := syslogRe.FindStringSubmatch(line); m != nil {
			timestamp = m[1]
		} else if m := rsyslogRe.FindStringSubmatch(line); m != nil {
			timestamp = m[1]
		} else {
			// Skip lines we cannot parse — don't abort the whole scan.
			continue
		}

		// Everything after the timestamp is "hostname proc[pid]: message".
		// We store the hostname in Facility and the rest in Message so that
		// keyword-based Sigma rules can match against process/message content.
		rest := strings.TrimSpace(line[len(timestamp):])
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
