package auditd

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
)

// AuditEvent represents an Audit log event
type AuditEvent struct {
	Type string
	Data map[string]string
}

// Keywords returns the keywords for an AuditEvent
func (e AuditEvent) Keywords() ([]string, bool) {
	keywords := []string{e.Type}
	for k := range e.Data {
		keywords = append(keywords, k)
	}
	return keywords, true
}

// Select returns the value of the given field for an AuditEvent
func (e AuditEvent) Select(name string) (interface{}, bool) {
	if name == "type" {
		return e.Type, true
	}
	if value, ok := e.Data[name]; ok {
		return value, true
	}
	return nil, false
}

func ParseEvents(logFile string) ([]AuditEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]AuditEvent, 0)
	scanner := bufio.NewScanner(file)
	event := make(map[string]string) // create a single map outside the loop
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "type=") {
			continue
		}

		parts := strings.Split(line, " ")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				if kv[0] == "msg" && strings.HasPrefix(kv[1], "audit(") {
					// we got the entry containing the timestamp and id of the audit event
					timestampRegex := regexp.MustCompile(`audit\(([\d]+)\.\d*:\d*\):`)
					timestampString := (timestampRegex.FindStringSubmatch(kv[1]))[1]
					unixTime, _ := strconv.ParseInt(timestampString, 10, 64)
					timestamp := time.Unix(unixTime, 0)
					event["timestamp"] = timestamp.UTC().Format(time.RFC3339)
				} else {
					// some other entry
					event[kv[0]] = kv[1]
				}
			}
		}

		if len(event) > 0 {
			events = append(events, AuditEvent{
				Type: event["type"],
				Data: event,
			})
			event = make(map[string]string) // clear the map for the next event
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// FindLog takes the file from the given path or finds the location of the audit log file by parsing the auditd.conf file
func FindLog(file string) (string, error) {
	if file != "" {
		_, err := os.Stat(file) // stat the given path; we are interested in the possible error, focusing on an ErrNotExist
		if err != nil {
			return "", fmt.Errorf("Failed to find provided file %v", file)
		}
		return file, nil
	} else {
		// Open the auditd.conf file
		file, err := os.Open("/etc/audit/auditd.conf")
		if err != nil {
			return "", fmt.Errorf("failed to open auditd.conf: %v", err)
		}
		defer file.Close()

		// Scan the file line by line
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Look for the log_file option
			if strings.HasPrefix(line, "log_file ") {
				path := strings.TrimSpace(strings.TrimPrefix(line, "log_file = "))
				return path, nil
			}
		}
	}
	// If the log_file option is not found, return an error
	return "", fmt.Errorf("log_file option not found in auditd.conf")
}

func Chop(rulePath string, outputType string, filePath string) interface{} {
	// Find the auditd file
	auditdLogPath, err := FindLog(filePath)
	if err != nil {
		log.Fatalf("failed to find audit log: %v", err)
	}

	// Parse the auditd events
	events, err := ParseEvents(auditdLogPath)
	if err != nil {
		log.Fatalf("failed to parse audit log: %v", err)
	}

	// Load the Sigma ruleset
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{rulePath},
	})
	if err != nil {
		log.Fatalf("failed to load ruleset: %v", err)
	}

	// Make a list of sigma.Results called results
	results := make([]sigma.Results, 0)

	if outputType == "json" {
		var jsonResults []map[string]interface{}
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				jsonResult := make(map[string]interface{})
				jsonResult["Timestamp"] = event.Data["timestamp"]
				jsonResult["AUID"] = event.Data["AUID"]
				jsonResult["Exe"] = event.Data["exe"]
				jsonResult["Terminal"] = event.Data["terminal"]
				jsonResult["Pid"] = event.Data["pid"]
				jsonResult["Tags"] = strings.Join(result[0].Tags, "-")
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
		csvHeader := []string{"Timestamp", "User", "Exe", "Terminal", "PID", "Tags", "Author", "ID", "Titles"}
		csvData = append(csvData, csvHeader)

		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				csvData = append(csvData, []string{
					event.Data["timestamp"],
					event.Data["AUID"],
					event.Data["exe"],
					event.Data["terminal"],
					event.Data["pid"],
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
		table.SetHeader([]string{"Timestamp", "User", "Exe", "Terminal", "PID", "Tags", "Author"})
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				table.Append([]string{
					event.Data["timestamp"],
					event.Data["AUID"],
					event.Data["exe"],
					event.Data["terminal"],
					event.Data["pid"],
					strings.Join(result[0].Tags, "-"),
					result[0].Author,
				})
			}
			bar.Add(1)
		}
		table.Render()
		fmt.Printf("Processed %d auditd events\n", len(events))
		return results
	}
}
