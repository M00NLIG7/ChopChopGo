package journald

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/markuskont/go-sigma-rule-engine"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
)

type JournaldEvent struct {
	Message   string
	Timestamp uint64
}

func (e JournaldEvent) Keywords() ([]string, bool) {
	return []string{e.Message}, true
}

func (e JournaldEvent) Select(name string) (interface{}, bool) {
	switch name {
	case "message":
		return e.Message, true
	default:
		return nil, false
	}
}


func ParseEvents() []JournaldEvent {
	j, err := sdjournal.NewJournal()

	if err != nil {
		log.Fatal("Failed to open journal:", err)
	}
	defer j.Close()

	err = j.SeekHead()
	if err != nil {
		log.Fatal("Failed to seek to end of journal:", err)
	}

	events := make([]JournaldEvent, 0)

	for {
		n, err := j.Next()
		if err != nil {
			log.Fatal("Failed to read journal entry:", err)
		}
		if n == 0 {
			break
		}
		message, _ := j.GetData("MESSAGE")
		timestamp, _ := j.GetRealtimeUsec()

		events = append(events, JournaldEvent{
			Message:   message,
			Timestamp: timestamp,
		})

		if err != nil {
			log.Fatal("Failed to get journal entry data:", err)
		}
		// Do something with the journal entry data...
	}

	return events
}

func Chop(rulePath string, outputType string) (interface{}, error) {
	events := ParseEvents()
	
	path := [1]string{rulePath}
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: path[:],
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to load ruleset: %v", err)
	}

    bar := progressbar.Default(int64(len(events)))
	results := make([]sigma.Results, 0)
	
	if outputType == "json" {
		var jsonResults []map[string]interface{}
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				jsonResult := make(map[string]interface{})
				jsonResult["message"] = event.Message
				jsonResult["timestamp"] = event.Timestamp
				jsonResult["Tags"] = result[0].Tags
				jsonResults = append(jsonResults, jsonResult)
			}
			bar.Add(1)
		}
        jsonBytes, err := json.MarshalIndent(jsonResults, "", "  ")
		if err != nil {
            log.Fatalf("Failed to marshal results to JSON: %v", err)
        }
		return string(jsonBytes), nil
	} else if outputType == "csv" {
		var csvData [][]string
        for _, event := range events {
            if result, match := ruleset.EvalAll(event); match {
                results = append(results, result)
                csvData = append(csvData, []string{
                    event.Message,
					strconv.FormatUint(event.Timestamp, 10),
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
        fmt.Printf("Processed %d journald events\n", len(events))
        return csvBytes.String(), nil
	} else {
		table := tablewriter.NewWriter(os.Stdout)
        table.SetHeader([]string{"timestamp", "message", "tags"})
        for _, event := range events {
            if result, match := ruleset.EvalAll(event); match {
                results = append(results, result)
                table.Append([]string{
                    event.Message,
					strconv.FormatUint(event.Timestamp, 10),
                    strings.Join(result[0].Tags, "-"),
                })
            }
            bar.Add(1)
        }
        table.Render()
        fmt.Printf("Processed %d journald events\n", len(events))
        return results, nil
	}
}
