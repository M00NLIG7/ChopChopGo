package syslog

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
)

// Representation of syslog event
type SyslogEvent struct {
	Facility  string
	Severity  string
	Message   string
	Timestamp string
}

/*
	Keywords is a function required for a sigma.Event
	to be passed to sigma.Rulset.EvalAll

	Keywords returns a list of the differnt keys in our
	SyslogEvent struct.
*/
func (e SyslogEvent) Keywords() ([]string, bool) {
	return []string{e.Facility, e.Severity, e.Message}, true
}

/*
	Select is a function required for a sigma.Event
	to be passed to sigma.Rulset.EvalAll

	Select returns the value for a specified key
*/
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

/*
	ParseEvents interprets and parses the log file
	and builds a slice of SyslogEvent structs
*/
func ParseEvents(logFile string) ([]SyslogEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]SyslogEvent, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		r := regexp.MustCompile(`^([a-zA-Z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)

		matches := r.FindStringSubmatch(line)

		if matches == nil {
			fmt.Println("Failed to match timestamp")
		}

		timestamp := matches[1]

		parts := strings.SplitN(line, " ", 5)
		if len(parts) != 5 {
			continue
		}

		facility := strings.TrimSuffix(parts[0], ":")
		severity := parts[1]
		message := strings.TrimSpace(parts[4])
		events = append(events, SyslogEvent{
			Facility:  facility,
			Severity:  severity,
			Message:   message,
			Timestamp: timestamp,
		})
	}
	return events, nil
}

func FindLog() string {
	syslogPath := "/var/log/syslog"
	if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
		syslogPath = "/var/log/messages"
	}
	return syslogPath
}

func Chop(rulePath string, outputType ...string) interface{} {
	// Find the syslog file
	syslogPath := FindLog()

	fmt.Printf("Using syslog file: %s\n", syslogPath)

	// Parse the syslog events
	events, err := ParseEvents(syslogPath)

	// Load the Sigma ruleset
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{rulePath},
	})
	if err != nil {
		log.Fatalf("Failed to load ruleset: %v", err)
	}

	bar := progressbar.Default(int64(len(events)))
	// Make a list of sigma.Results called results
	results := make([]sigma.Results, 0)

	if outputType[0] == "json" {
		var jsonResults []map[string]interface{}
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				jsonResult := make(map[string]interface{})
				jsonResult["timestamp"] = event.Timestamp
				jsonResult["message"] = event.Message
				jsonResult["tags"] = result[0].Tags
				jsonResults = append(jsonResults, jsonResult)
			}

			bar.Add(1)
		}

		jsonBytes, err := json.MarshalIndent(jsonResults, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal results to JSON: %v", err)
		}
		fmt.Printf("Processed %d syslog events\n", len(events))
		return string(jsonBytes)
	} else if outputType[0] == "csv" {
		var csvResults [][]string
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				csvResult := []string{event.Timestamp, event.Message, strings.Join(result[0].Tags, "-")}
				csvResults = append(csvResults, csvResult)
			}
			bar.Add(1)
		}
		csvBytes := bytes.Buffer{}
		csvWriter := csv.NewWriter(&csvBytes)
		err := csvWriter.WriteAll(csvResults)
		if err != nil {
			log.Fatalf("Failed to write CSV results: %v", err)
		}
		fmt.Printf("Processed %d syslog events\n", len(events))
		return csvBytes.String()
	} else {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"timestamp", "message", "tags"})
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				table.Append([]string{event.Timestamp, event.Message, strings.Join(result[0].Tags, "-")})
			}
			bar.Add(1)
		}
		table.Render()
		fmt.Printf("Processed %d syslog events\n", len(events))
		return results
	}
}
