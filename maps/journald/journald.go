//go:build linux

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

	"github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/coreos/go-systemd/v22/sdjournal"
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

func Chop(rulePath string, outputType string) interface{} {
	events := ParseEvents()

	path := [1]string{rulePath}
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: path[:],
	})
	if err != nil {
		log.Fatalf("Failed to load ruleset: %v", err)
	}

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
					event.Message,
					strconv.FormatUint(event.Timestamp, 10),
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
		table.SetHeader([]string{"timestamp", "message", "tags", "author"})
		for _, event := range events {
			if result, match := ruleset.EvalAll(event); match {
				results = append(results, result)
				table.Append([]string{
					event.Message,
					strconv.FormatUint(event.Timestamp, 10),
					strings.Join(result[0].Tags, "-"),
					result[0].Author,
				})
			}
			bar.Add(1)
		}
		table.Render()
		fmt.Printf("Processed %d journald events\n", len(events))
		return results
	}
}
