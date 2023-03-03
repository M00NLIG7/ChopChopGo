package syslog

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/markuskont/go-sigma-rule-engine"
)

// Representation of syslog event
type SyslogEvent struct {
    Facility string
    Severity string
    Message  string
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
        parts := strings.SplitN(line, " ", 5)
        if len(parts) != 5 {
            continue
        }
        facility := strings.TrimSuffix(parts[0], ":")
        severity := parts[1]
        message := strings.TrimSpace(parts[4])
        events = append(events, SyslogEvent{
            Facility: facility,
            Severity: severity,
            Message:  message,
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
    // fmt.Printf("Unsupported %v", ruleset.Unsupported)

    // Evaluate the events against the Sigma ruleset
    for _, event := range events {
        // See if iptables is in event.Message
        if strings.Contains(event.Message, "iptables") {
            // fmt.Println(event.Severity) 
        }
        if result, match := ruleset.EvalAll(event); match {
            fmt.Println(result)
        }
    }
    fmt.Printf("Processed %d syslog events\n", len(events))
}

