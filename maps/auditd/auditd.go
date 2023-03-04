package auditd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
)

// Representation of Audit log event
type AuditEvent struct {
    Type string
    Data map[string]string
}

func (e AuditEvent) Keywords() ([]string, bool) {
    keywords := []string{e.Type}
    for k := range e.Data {
        keywords = append(keywords, k)
    }
    return keywords, true
}

func (e AuditEvent) Select(name string) (interface{}, bool) {
    if name == "type" {
        return e.Type, true
    }
    if value, ok := e.Data[name]; ok {
        return value, true
    }
    return nil, false
}

func ParseEvents(logBytes []byte) ([]AuditEvent) {
    log := string(logBytes)
    events := make([]AuditEvent, 0)

    for _, line := range strings.Split(log, "\n") {
        event := make(map[string]string)
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
        }
    }
    return events
}

// FindAuditLog finds the location of the audit log file by parsing the auditd.conf file
func FindLog() (string, error) {
	// Open the auditd.conf file
	file, err := os.Open("/etc/audit/auditd.conf")
	if err != nil {
		return "", err
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

	// If the log_file option is not found, return the default path
	return "/var/log/audit/audit.log", nil
}

func Chop(rulePath string) {
    auditdLogPath, _ := FindLog()

    outputBytes, err := os.ReadFile(auditdLogPath)
    if err != nil {
        log.Fatalf("Failed to read audit log: %v", err)
    }
    fmt.Printf("Using Auditd file: %s\n", auditdLogPath)
    
    events := ParseEvents(outputBytes)

    path := [1]string{rulePath}
    ruleset, err := sigma.NewRuleset(sigma.Config{
        Directory: path[:],
    })
    if err != nil {
        log.Fatalf("Failed to load ruleset: %v", err)
    }

    bar := progressbar.Default(int64(len(events)))
    // Make a list of sigma.Results called results
    results := make([]sigma.Results, 0)

    table := tablewriter.NewWriter(os.Stdout)
    table.SetHeader([]string{"AUID", "exe", "terminal", "pid", "hostname", "tags"})

    // list to string
    for _, event := range events {
        if result, match := ruleset.EvalAll(event); match {
            results = append(results, result)
            
            table.Append([]string{event.Data["AUID"], event.Data["exe"], event.Data["terminal"], event.Data["pid"], event.Data["hostname"], strings.Join(result[0].Tags,"-")})

        }
        bar.Add(1)
        // time.Sleep(1 * time.Millisecond)
    }
    // fmt.Println(results)
    table.Render() // Send output

    
    
    // print length of events
    fmt.Printf("Processed %d auditd events\n", len(events))

}

    