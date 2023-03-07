package auditd

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/markuskont/go-sigma-rule-engine"
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
                event[kv[0]] = kv[1]
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



// FindLog finds the location of the audit log file by parsing the auditd.conf file
func FindLog() (string, error) {
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

    // If the log_file option is not found, return an error
    return "", fmt.Errorf("log_file option not found in auditd.conf")
}

func Chop(rulePath string, outputType string) (interface{}, error) {
    // Find the auditd file
    auditdLogPath, err := FindLog()
    if err != nil {
        return nil, fmt.Errorf("failed to find audit log: %v", err)
    }

    fmt.Printf("Using auditd file: %s\n", auditdLogPath)

    // Parse the auditd events
    events, err := ParseEvents(auditdLogPath)
    if err != nil {
        return nil, fmt.Errorf("failed to parse audit log: %v", err)
    }

    // Load the Sigma ruleset
    ruleset, err := sigma.NewRuleset(sigma.Config{
        Directory: []string{rulePath},
    })
    if err != nil {
        return nil, fmt.Errorf("failed to load ruleset: %v", err)
    }

    bar := progressbar.Default(int64(len(events)))
    // Make a list of sigma.Results called results
    results := make([]sigma.Results, 0)

    if outputType == "json" {
        var jsonResults []map[string]interface{}
        for _, event := range events {
            if result, match := ruleset.EvalAll(event); match {
                results = append(results, result)
                jsonResult := make(map[string]interface{})
                jsonResult["AUID"] = event.Data["AUID"]
                jsonResult["exe"] = event.Data["exe"]
                jsonResult["terminal"] = event.Data["terminal"]
                jsonResult["pid"] = event.Data["pid"]
                jsonResult["hostname"] = event.Data["hostname"]
                jsonResult["Tags"] = strings.Join(result[0].Tags, "-")
                jsonResults = append(jsonResults, jsonResult)
            }
            bar.Add(1)
        }
		
        jsonBytes, err := json.MarshalIndent(jsonResults, "", "  ")
        if err != nil {
            log.Fatalf("Failed to marshal results to JSON: %v", err)
        }
        fmt.Printf("Processed %d auditd events\n", len(events))
        
        fmt.Println(string(jsonBytes))
        return string(jsonBytes), nil
    } else if outputType == "csv" {
        var csvData [][]string
        for _, event := range events {
            if result, match := ruleset.EvalAll(event); match {
                results = append(results, result)
                csvData = append(csvData, []string{
                    event.Data["AUID"],
                    event.Data["exe"],
                    event.Data["terminal"],
                    event.Data["pid"],
                    event.Data["hostname"],
                    strings.Join(result[0].Tags, "-"),
                })
            }
            bar.Add(1)
        }
        csvBytes := bytes.Buffer{}
        csvWriter := csv.NewWriter(&csvBytes)
        err := csvWriter.WriteAll(csvData)
        if err != nil {
            log.Fatalf("Failed to write CSV results: %v", err)
        }
        fmt.Printf("Processed %d auditd events\n", len(events))

        fmt.Println(csvBytes.String())
        return csvBytes.String(), nil
    } else {
        table := tablewriter.NewWriter(os.Stdout)
        table.SetHeader([]string{"User", "Exe", "Terminal", "PID", "Hostname", "Tags"})
        for _, event := range events {
            if result, match := ruleset.EvalAll(event); match {
                results = append(results, result)
                table.Append([]string{
                    event.Data["AUID"],
                    event.Data["exe"],
                    event.Data["terminal"],
                    event.Data["pid"],
                    event.Data["hostname"],
                    strings.Join(result[0].Tags, "-"),
                })
            }
            bar.Add(1)
        }
        table.Render()
        fmt.Printf("Processed %d auditd events\n", len(events))
        return results, nil
    }
}
