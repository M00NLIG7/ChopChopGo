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
    return []string{e.Facility, e.Severity}, true
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

func ParseSyslog(logBytes []byte) ([]SyslogEvent) {
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

func SyslogSigma() {
    // Find the syslog file
    syslogPath := "/var/log/syslog"
    if _, err := os.Stat(syslogPath); os.IsNotExist(err) {
        syslogPath = "/var/log/messages"
    }
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
    events := ParseSyslog(syslogBytes)

    // Load the Sigma ruleset
    ruleset, err := sigma.NewRuleset(sigma.Config{
        Directory: []string{"./linux/syslog"},
    })
    if err != nil {
        log.Fatalf("Failed to load ruleset: %v", err)
    }
    fmt.Println(ruleset.Unsupported)

    // Evaluate the events against the Sigma ruleset
    for _, event := range events {
        if result, match := ruleset.EvalAll(event); match {
            fmt.Println(result)
        }
    }
    fmt.Printf("Processed %d syslog events\n", len(events))
}