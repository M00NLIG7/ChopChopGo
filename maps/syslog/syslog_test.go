package syslog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdataDir = "../../testdata"

func TestParseEventsStandardFormat(t *testing.T) {
	events, err := ParseEvents(filepath.Join(testdataDir, "syslog.log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 4 {
		t.Errorf("expected 4 events, got %d", len(events))
	}
	if events[0].Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if events[0].Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestParseEventsRsyslogFormat(t *testing.T) {
	events, err := ParseEvents(filepath.Join(testdataDir, "rsyslog.log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
	// ISO 8601 timestamp should be preserved
	if !strings.HasPrefix(events[0].Timestamp, "2023-03-01T") {
		t.Errorf("unexpected rsyslog timestamp: %q", events[0].Timestamp)
	}
}

func TestParseEventsSkipsMalformedLines(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mixed.log")
	content := "this line has no timestamp and should be skipped\n" +
		"another bad line\n" +
		"Mar  1 10:00:01 hostname sshd[1]: message here and more content\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Must not return an error; bad lines are skipped
	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error parsing file with malformed lines: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 valid event, got %d", len(events))
	}
}

func TestParseEventsEmptyFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "empty.log")
	if err := os.WriteFile(f, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestParseEventsMessageContent(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "syslog")
	line := "Mar  4 09:00:00 host cron[5678]: (root) CMD (rm /var/log/syslog)\n"
	if err := os.WriteFile(f, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !strings.Contains(events[0].Message, "cron") {
		t.Errorf("message should contain process info, got: %q", events[0].Message)
	}
}

func TestSyslogEventSelect(t *testing.T) {
	e := SyslogEvent{
		Facility:  "host1",
		Severity:  "",
		Message:   "sshd[1]: test message",
		Timestamp: "Mar  1 10:00:01",
	}

	if v, ok := e.Select("message"); !ok || v != "sshd[1]: test message" {
		t.Errorf("Select(message): got %v, ok=%v", v, ok)
	}
	if v, ok := e.Select("facility"); !ok || v != "host1" {
		t.Errorf("Select(facility): got %v, ok=%v", v, ok)
	}
	if v, ok := e.Select("severity"); !ok || v != "" {
		t.Errorf("Select(severity): got %v, ok=%v", v, ok)
	}
	if _, ok := e.Select("unknown"); ok {
		t.Error("Select(unknown) should return false")
	}
}

func TestSyslogEventKeywords(t *testing.T) {
	e := SyslogEvent{
		Facility: "myhost",
		Severity: "",
		Message:  "disk full warning",
	}

	keywords, ok := e.Keywords()
	if !ok {
		t.Error("Keywords() should return true")
	}

	found := false
	for _, k := range keywords {
		if strings.Contains(k, "disk full") {
			found = true
		}
	}
	if !found {
		t.Errorf("Keywords() should include message content; got %v", keywords)
	}
}

func TestFindLogWithExistingFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "syslog")
	if err := os.WriteFile(f, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := FindLog(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != f {
		t.Errorf("expected %q, got %q", f, result)
	}
}

func TestFindLogMissingFile(t *testing.T) {
	_, err := FindLog("/nonexistent/path/syslog")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

const bsdLine = "Mar  1 10:00:01 hostname sshd[1234]: Accepted publickey for user from 192.168.1.1 port 22"
const rsyslogLine = "2023-03-01T10:00:01.123456+00:00 hostname sshd[1234]: Accepted publickey for user from 192.168.1.1 port 22"

func BenchmarkParseEventsBSD(b *testing.B) {
	const n = 100_000
	tmp := b.TempDir()
	f := filepath.Join(tmp, "bsd.log")
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "Mar %2d 10:00:01 hostname sshd[%d]: message number %d\n", (i%28)+1, i+1000, i)
	}
	if err := os.WriteFile(f, []byte(sb.String()), 0600); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseEvents(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseEventsRsyslog(b *testing.B) {
	const n = 100_000
	tmp := b.TempDir()
	f := filepath.Join(tmp, "rsyslog.log")
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "2023-03-01T10:%02d:%02d.000000+00:00 hostname sshd[%d]: message number %d\n", (i/60)%60, i%60, i+1000, i)
	}
	if err := os.WriteFile(f, []byte(sb.String()), 0600); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseEvents(f); err != nil {
			b.Fatal(err)
		}
	}
}
