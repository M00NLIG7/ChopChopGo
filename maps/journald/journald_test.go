//go:build linux

package journald

import (
	"strings"
	"testing"
)

func TestJournaldEventSelectMessage(t *testing.T) {
	e := JournaldEvent{
		Message:   "Started Network Manager.",
		Timestamp: "2023-03-01T10:00:00Z",
	}

	v, ok := e.Select("message")
	if !ok {
		t.Fatal("Select(message) should return true")
	}
	if v != "Started Network Manager." {
		t.Errorf("unexpected message value: %v", v)
	}
}

func TestJournaldEventSelectTimestamp(t *testing.T) {
	e := JournaldEvent{
		Message:   "test",
		Timestamp: "2023-03-01T10:00:00Z",
	}

	v, ok := e.Select("timestamp")
	if !ok {
		t.Fatal("Select(timestamp) should return true")
	}
	if v != "2023-03-01T10:00:00Z" {
		t.Errorf("unexpected timestamp value: %v", v)
	}
}

func TestJournaldEventSelectUnknown(t *testing.T) {
	e := JournaldEvent{Message: "test", Timestamp: "2023-03-01T10:00:00Z"}
	if _, ok := e.Select("nonexistent"); ok {
		t.Error("Select(nonexistent) should return false")
	}
}

func TestJournaldEventKeywords(t *testing.T) {
	e := JournaldEvent{
		Message:   "kernel: EXT4-fs error on device sda1",
		Timestamp: "2023-03-01T10:00:00Z",
	}

	keywords, ok := e.Keywords()
	if !ok {
		t.Error("Keywords() should return true")
	}
	found := false
	for _, k := range keywords {
		if strings.Contains(k, "EXT4-fs") {
			found = true
		}
	}
	if !found {
		t.Errorf("Keywords() should contain message content; got %v", keywords)
	}
}
