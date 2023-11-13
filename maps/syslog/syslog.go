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

	"github.com/M00NLIG7/go-sigma-rule-engine"
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

Keywords returns a list of the different keys in our
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

		syslogRegex := regexp.MustCompile(`^([a-zA-Z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
		rsyslogRegex := regexp.MustCompile(`^((-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?)`) // ISO 8601 timestamp written by rsyslog

		syslogMatches := syslogRegex.FindStringSubmatch(line)
		rsyslogMatches := rsyslogRegex.FindStringSubmatch(line)

		var timestamp string
		switch {
		case syslogMatches != nil:
			timestamp = syslogMatches[1]
		case rsyslogMatches != nil:
			timestamp = rsyslogMatches[1]
		default:
			return nil, fmt.Errorf("Failed to match timestamp")
		}

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

func FindLog(file string) (string, error) {
	var syslogPath string
	if file != "" {
		_, err := os.Stat(file) // stat the given path; we are interested in the possible error, focusing on an ErrNotExist
		if err != nil {
			return "", fmt.Errorf("Failed to find provided file %v", file)
		}
		syslogPath = file
	} else {
		syslogPath = "/var/log/syslog"
		if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
			syslogPath = "/var/log/messages"
		}
	}
	return syslogPath, nil
}

func Chop(rulePath string, outputType string, filePath string) interface{} {
	// find the log file
	syslogPath, err := FindLog(filePath)
	if err != nil {
		log.Fatalf("Failed to get syslog: %v", err)
	}

	// Parse the syslog events
	events, err := ParseEvents(syslogPath)
	if err != nil {
		log.Fatalf("Failed to parse events: %v", err)
	}

	// Load the Sigma ruleset
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{rulePath},
	})
	if err != nil {
		log.Fatalf("Failed to load ruleset: %v", err)
	}

	// Make a list of sigma.Results called results
	results := make([]sigma.Results, 0)

	if outputType == "json" {
		var jsonResults []map[string]interface{}
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				jsonResult := make(map[string]interface{})
				jsonResult["Timestamp"] = event.Timestamp
				jsonResult["Message"] = event.Message
				jsonResult["Tags"] = result[0].Tags
				jsonResult["Author"] = result[0].Author
				jsonResult["ID"] = result[0].ID
				jsonResult["Title"] = result[0].Title
				jsonResults = append(jsonResults, jsonResult)
			}

		}

		jsonBytes, err := json.MarshalIndent(jsonResults, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal results to JSON: %v", err)
		}

		fmt.Println(string(jsonBytes))
		return string(jsonBytes)
	} else if outputType == "csv" {
		var csvData [][]string
		csvHeader := []string{"Timestamp", "Message", "Tags", "Author", "ID", "Title"}
		csvData = append(csvData, csvHeader)

		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				csvData = append(csvData, []string{
					event.Timestamp,
					event.Message,
					strings.Join(result[0].Tags, "-"),
					result[0].Author,
					result[0].ID,
					result[0].Title,
				})
			}
		}
		csvBytes := bytes.Buffer{}
		csvWriter := csv.NewWriter(&csvBytes)
		err := csvWriter.WriteAll(csvData)
		if err != nil {
			log.Fatalf("Failed to write CSV results: %v", err)
		}
		fmt.Println(csvBytes.String())
		return csvBytes.String()
	} else {
		bar := progressbar.Default(int64(len(events)))

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Timestamp", "Message", "Tags", "Author"})
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				table.Append([]string{
					event.Timestamp,
					event.Message,
					strings.Join(result[0].Tags, "-"),
					result[0].Author,
				})
			}
			bar.Add(1)
		}
		table.Render()

		fmt.Printf("Processed %d syslog events\n", len(events))
		return results
	}
}
