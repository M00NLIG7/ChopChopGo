package syslog

import (
	"bufio"
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
    Facility string
    Severity string
    Message  string
    Timestamp string
}

func (e SyslogEvent) Keywords() ([]string, bool) {
    return []string{e.Facility, e.Severity, e.Message}, true
}

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

func ParseEvents(logBytes []byte) ([]SyslogEvent) {
    log := string(logBytes)
    events := make([]SyslogEvent, 0)

    for _, line := range strings.Split(log, "\n") {
        if len(line) == 0 {
            continue
        }

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
        // fmt.Println(parts)

        
        facility := strings.TrimSuffix(parts[0], ":")
        severity := parts[1]
        message := strings.TrimSpace(parts[4])
        events = append(events, SyslogEvent{
            Facility: facility,
            Severity: severity,
            Message:  message,
            Timestamp: timestamp,
        })
    }
    return events
}

func FindLog() (string) {
    syslogPath := "/var/log/syslog"
    if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
        syslogPath = "/var/log/messages"
    }
    return syslogPath
}

func Chop(rulePath string) {
    // Find the syslog file
    syslogPath := FindLog()

    fmt.Printf("Using syslog file: %s\n", syslogPath)

    // Read the syslog file
    syslogFile, err := os.Open(syslogPath)
    if err != nil {
        log.Fatalf("Failed to open syslog file: %v", err)
    }
    defer syslogFile.Close()
    syslogScanner := bufio.NewScanner(syslogFile)
    var syslogLines []string
    for syslogScanner.Scan() {
        syslogLines = append(syslogLines, syslogScanner.Text())
    }

    // Parse the syslog events
    syslogBytes := []byte(strings.Join(syslogLines, "\n"))
    events := ParseEvents(syslogBytes)

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

    table := tablewriter.NewWriter(os.Stdout)
    table.SetHeader([]string{"timestamp", "message", "tags"})

    // list to string
    for _, event := range events {
        if result, match := ruleset.EvalAll(event); match {
            results = append(results, result)
            
            table.Append([]string{event.Timestamp, event.Message, strings.Join(result[0].Tags, "-")})

        }
        bar.Add(1)
        // time.Sleep(1 * time.Millisecond)
    }
    // fmt.Println(results)
    table.Render()
    fmt.Printf("Processed %d syslog events\n", len(events))
}

