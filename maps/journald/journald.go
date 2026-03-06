//go:build linux

package journald

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	sigma "github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/M00NLIG7/ChopChopGo/maps/output"
	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/schollz/progressbar/v3"
)

// JournaldEvent represents a single entry from the systemd journal.
type JournaldEvent struct {
	Message   string
	Timestamp string
}

// Keywords satisfies the sigma.Event interface.
func (e JournaldEvent) Keywords() ([]string, bool) {
	return []string{e.Message}, true
}

// Select satisfies the sigma.Event interface.
func (e JournaldEvent) Select(name string) (interface{}, bool) {
	switch name {
	case "message":
		return e.Message, true
	case "timestamp":
		return e.Timestamp, true
	default:
		return nil, false
	}
}

// ParseEvents reads all entries from the live systemd journal.
// Journald uses a binary format that requires the systemd API; reading from
// an arbitrary file path is not supported.
func ParseEvents() ([]JournaldEvent, error) {
	j, err := sdjournal.NewJournal()
	if err != nil {
		return nil, fmt.Errorf("opening journal: %w", err)
	}
	defer j.Close()

	if err := j.SeekHead(); err != nil {
		return nil, fmt.Errorf("seeking journal head: %w", err)
	}

	var events []JournaldEvent
	for {
		n, err := j.Next()
		if err != nil {
			return nil, fmt.Errorf("reading journal entry: %w", err)
		}
		if n == 0 {
			break
		}

		message, _ := j.GetData("MESSAGE")
		// Strip the "MESSAGE=" prefix that sdjournal includes in the value.
		message = strings.TrimPrefix(message, "MESSAGE=")

		usec, err := j.GetRealtimeUsec()
		if err != nil {
			return nil, fmt.Errorf("reading entry timestamp: %w", err)
		}
		ts := time.Unix(0, int64(usec)*int64(time.Microsecond)).UTC().Format(time.RFC3339)

		events = append(events, JournaldEvent{
			Message:   message,
			Timestamp: ts,
		})
	}
	return events, nil
}

var journaldRenderer = output.Renderer{
	Headers: []string{"Timestamp", "Message", "Tags", "Author"},
	Row: func(r output.ScanResult) []string {
		return []string{r.Timestamp, r.Message, output.TagString(r.Tags), r.Author}
	},
}

// Chop scans the live systemd journal against Sigma rules and writes results
// to stdout. Passing a file path is not supported because the journal uses a
// binary format that requires the systemd API.
func Chop(rulePath, outputType string) error {
	events, err := ParseEvents()
	if err != nil {
		return fmt.Errorf("reading journal: %w", err)
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

	var results []output.ScanResult
	for _, event := range events {
		if res, match := ruleset.EvalAll(event); match {
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

	if err := output.Write(os.Stdout, outputType, results, journaldRenderer); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if showProgress {
		fmt.Printf("Processed %d journald events\n", len(events))
	}
	return nil
}

// ChopToLog is like Chop but calls log.Fatalf on error, for use from main.
func ChopToLog(rulePath, outputType string) {
	if err := Chop(rulePath, outputType); err != nil {
		log.Fatalf("journald: %v", err)
	}
}
