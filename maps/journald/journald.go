package journald

import (
	"fmt"
	"log"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/markuskont/go-sigma-rule-engine"
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

func Chop(rulePath string) []sigma.Results {

	events := ParseEvents()

	path := [1]string{rulePath}
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: path[:],
	})
	if err != nil {
		log.Fatalf("Failed to load ruleset: %v", err)
	}

	results := make([]sigma.Results, 0)
	for _, event := range events {
		if result, match := ruleset.EvalAll(event); match {
			results = append(results, result)
		}
	}
	// print length of events
	fmt.Printf("Processed %d auditd events\n", len(events))
	return results
}
