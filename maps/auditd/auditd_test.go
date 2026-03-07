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

	// 5 type= lines but lines 1-3 share seq 24287 and are merged into one.
	// Expected logical events: seq 24287, 24288, 24289 → 3 total.
	if len(events) != 3 {
		t.Errorf("expected 3 correlated events, got %d", len(events))
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
	// Fields from the correlated CWD and PATH records should be merged in.
	if first.Data["cwd"] != "/home/user" {
		t.Errorf("expected cwd=/home/user (merged from CWD record), got %q", first.Data["cwd"])
	}
	if first.Data["name"] != "/etc/ssh/sshd_config" {
		t.Errorf("expected name=/etc/ssh/sshd_config (merged from PATH record), got %q", first.Data["name"])
	}
}

func TestParseEventsCorrelation(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "corr.log")
	// Three records sharing seq 99 — fields from later records fill in gaps.
	content := "" +
		"type=SYSCALL msg=audit(1000000000.000:99): pid=42 auid=1000 exe=\"/bin/bash\"\n" +
		"type=EXECVE  msg=audit(1000000000.000:99): argc=2 a0=\"bash\" a1=\"-i\"\n" +
		"type=CWD     msg=audit(1000000000.000:99): cwd=\"/root\"\n" +
		// Unrelated record with a different seq.
		"type=SYSCALL msg=audit(1000000001.000:100): pid=7 auid=0 exe=\"/usr/bin/id\"\n"
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	events, err := ParseEvents(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 correlated events, got %d", len(events))
	}

	e := events[0]
	if e.Type != "SYSCALL" {
		t.Errorf("first event type: got %q, want SYSCALL", e.Type)
	}
	if e.Data["exe"] != "/bin/bash" {
		t.Errorf("exe: got %q, want /bin/bash", e.Data["exe"])
	}
	if e.Data["argc"] != "2" {
		t.Errorf("argc (from EXECVE): got %q, want 2", e.Data["argc"])
	}
	if e.Data["cwd"] != "/root" {
		t.Errorf("cwd (from CWD): got %q, want /root", e.Data["cwd"])
	}
	// SYSCALL exe must win over any exe on later records.
	if events[1].Data["exe"] != "/usr/bin/id" {
		t.Errorf("second event exe: got %q, want /usr/bin/id", events[1].Data["exe"])
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

func TestParseLineQuoting(t *testing.T) {
	cases := []struct {
		line string
		key  string
		want string
	}{
		// double-quoted value
		{`type=SYSCALL msg=audit(0.000:1): exe="/bin/cat"`, "exe", "/bin/cat"},
		// single-quoted value (USER_AUTH style)
		{`type=USER_AUTH msg=audit(0.000:1): msg='op=PAM acct="root" res=failed'`, "msg", `op=PAM acct="root" res=failed`},
		// unquoted value
		{`type=SYSCALL msg=audit(0.000:1): pid=1234`, "pid", "1234"},
		// bare parens — not a quote
		{`type=SYSCALL msg=audit(0.000:1): exit=(null)`, "exit", "(null)"},
	}
	for _, c := range cases {
		event := parseLine(c.line)
		if got := event[c.key]; got != c.want {
			t.Errorf("parseLine key %q: got %q, want %q", c.key, got, c.want)
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

// representativeLine is a realistic auditd SYSCALL line with quoted fields and
// a long argument list — the kind of line the parser sees most often.
const representativeLine = `type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=7f5678 a2=7f9abc a3=0 items=2 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="susp_exec"`

// BenchmarkTokenizeParseLine measures the tokenizer-based parsing kernel.
func BenchmarkTokenizeParseLine(b *testing.B) {
	line := representativeLine
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseLine(line)
	}
}

// BenchmarkParseEvents measures end-to-end throughput including file I/O on a
// synthetic 10 000-line log so the absolute cost of a real scan is visible.
func BenchmarkParseEvents(b *testing.B) {
	// Build a large log file once outside the timer.
	tmp := b.TempDir()
	f := filepath.Join(tmp, "bench.log")
	var sb strings.Builder
	for i := 0; i < 10_000; i++ {
		sb.WriteString(representativeLine)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(f, []byte(sb.String()), 0600); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseEvents(f); err != nil {
			b.Fatal(err)
		}
	}
}
