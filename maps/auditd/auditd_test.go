package auditd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdataDir = "../../testdata"

func TestParseEventsStandard(t *testing.T) {
	events, err := ParseEvents(filepath.Join(testdataDir, "auditd.log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File has 5 type= lines; non-type lines must be skipped
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}

	first := events[0]
	if first.Type != "SYSCALL" {
		t.Errorf("expected type SYSCALL, got %q", first.Type)
	}
	if first.Data["exe"] != "/bin/cat" {
		t.Errorf("expected exe=/bin/cat, got %q", first.Data["exe"])
	}
	if first.Data["pid"] != "3538" {
		t.Errorf("expected pid=3538, got %q", first.Data["pid"])
	}
	if first.Data["auid"] != "1000" {
		t.Errorf("expected auid=1000, got %q", first.Data["auid"])
	}
	if first.Data["timestamp"] == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestParseEventsSkipsNonTypeLines(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.log")
	content := "not a type line\nsome other content\n" +
		"type=SYSCALL msg=audit(1364481363.243:1): arch=c000003e syscall=2 pid=100 exe=/bin/sh auid=0\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestParseEventsEmpty(t *testing.T) {
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

func TestParseEventsBadTimestampDoesNotPanic(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "bad.log")
	// msg field does not contain an audit(...) timestamp
	content := "type=SYSCALL msg=notaudit(bad): arch=c000003e\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseEvents panicked on bad timestamp: %v", r)
		}
	}()

	// Must not panic; the line with a bad timestamp is skipped
	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The SYSCALL line has no valid audit(...) timestamp — it should be
	// handled without panicking (event will be stored without a timestamp).
	_ = events
}

func TestParseEventsTimestampConversion(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "ts.log")
	// Unix timestamp 0 should become 1970-01-01T00:00:00Z
	content := "type=SYSCALL msg=audit(0.000:1): arch=c000003e syscall=2 pid=1 auid=0\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected 1 event")
	}
	if events[0].Data["timestamp"] != "1970-01-01T00:00:00Z" {
		t.Errorf("unexpected timestamp: %q", events[0].Data["timestamp"])
	}
}

func TestAuditEventSelect(t *testing.T) {
	e := AuditEvent{
		Type: "SYSCALL",
		Data: map[string]string{
			"exe": "/bin/bash",
			"pid": "1234",
		},
	}

	if v, ok := e.Select("type"); !ok || v != "SYSCALL" {
		t.Errorf("Select(type): got %v, ok=%v", v, ok)
	}
	if v, ok := e.Select("exe"); !ok || v != "/bin/bash" {
		t.Errorf("Select(exe): got %v, ok=%v", v, ok)
	}
	if v, ok := e.Select("pid"); !ok || v != "1234" {
		t.Errorf("Select(pid): got %v, ok=%v", v, ok)
	}
	if _, ok := e.Select("nonexistent"); ok {
		t.Error("Select(nonexistent) should return false")
	}
}

func TestAuditEventKeywords(t *testing.T) {
	e := AuditEvent{
		Type: "EXECVE",
		Data: map[string]string{"exe": "/bin/bash", "pid": "1234"},
	}

	keywords, ok := e.Keywords()
	if !ok {
		t.Error("Keywords() should return true")
	}

	found := false
	for _, k := range keywords {
		if k == "EXECVE" {
			found = true
		}
	}
	if !found {
		t.Errorf("Keywords() should contain the event type; got %v", keywords)
	}

	// Data keys should also appear
	foundKey := false
	for _, k := range keywords {
		if strings.Contains(k, "exe") {
			foundKey = true
		}
	}
	if !foundKey {
		t.Errorf("Keywords() should contain data keys; got %v", keywords)
	}
}

func TestUnquote(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"/bin/cat"`, "/bin/cat"},
		{`"sshd_config"`, "sshd_config"},
		{`(null)`, "(null)"},
		{`1000`, "1000"},
		{`""`, ""},
		{`"`, `"`},
		{``, ``},
	}
	for _, c := range cases {
		if got := unquote(c.in); got != c.want {
			t.Errorf("unquote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseEventsStripsQuotes(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "audit.log")
	// exe and comm are quoted in real auditd logs
	content := "type=SYSCALL msg=audit(1364481363.243:1): arch=c000003e syscall=59 pid=100 auid=0 exe=\"/bin/bash\" comm=\"bash\" key=\"susp_activity\"\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Data["exe"] != "/bin/bash" {
		t.Errorf("exe: got %q, want /bin/bash", e.Data["exe"])
	}
	if e.Data["comm"] != "bash" {
		t.Errorf("comm: got %q, want bash", e.Data["comm"])
	}
	if e.Data["key"] != "susp_activity" {
		t.Errorf("key: got %q, want susp_activity", e.Data["key"])
	}
}

func TestFindLogWithExistingFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "audit.log")
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
	_, err := FindLog("/nonexistent/path/to/audit.log")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
