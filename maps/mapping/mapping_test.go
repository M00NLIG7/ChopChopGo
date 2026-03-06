package mapping

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempMapping(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.yml")
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadValid(t *testing.T) {
	path := writeTempMapping(t, `
source: auditd
fields:
  CommandLine: exe
  ProcessId: pid
  User: auid
`)
	m, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Source != "auditd" {
		t.Errorf("source: got %q, want auditd", m.Source)
	}
	if len(m.Fields) != 3 {
		t.Errorf("fields count: got %d, want 3", len(m.Fields))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/mapping.yml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	// An unclosed flow mapping is a YAML parse error in yaml.v2.
	path := writeTempMapping(t, "fields: {unclosed")
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadEmptyFields(t *testing.T) {
	path := writeTempMapping(t, "source: syslog\n")
	m, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fields should be initialised to an empty map, not nil
	if m.Fields == nil {
		t.Error("Fields should not be nil after loading empty mapping")
	}
}

func TestResolveKnownField(t *testing.T) {
	m := &Mapping{Fields: map[string]string{"CommandLine": "exe", "ProcessId": "pid"}}

	if got := m.Resolve("CommandLine"); got != "exe" {
		t.Errorf("Resolve(CommandLine): got %q, want exe", got)
	}
	if got := m.Resolve("ProcessId"); got != "pid" {
		t.Errorf("Resolve(ProcessId): got %q, want pid", got)
	}
}

func TestResolveUnknownFieldPassthrough(t *testing.T) {
	m := &Mapping{Fields: map[string]string{"CommandLine": "exe"}}

	// Unknown sigma field names fall through to the original name
	if got := m.Resolve("auid"); got != "auid" {
		t.Errorf("Resolve(auid): got %q, want auid (passthrough)", got)
	}
	if got := m.Resolve("type"); got != "type" {
		t.Errorf("Resolve(type): got %q, want type (passthrough)", got)
	}
}

func TestIdentity(t *testing.T) {
	m := Identity("syslog")
	if m.Source != "syslog" {
		t.Errorf("source: got %q, want syslog", m.Source)
	}
	// Identity mapping is a passthrough for all fields
	if got := m.Resolve("anything"); got != "anything" {
		t.Errorf("identity Resolve(anything): got %q, want anything", got)
	}
}

func TestLoadOrIdentityMissingFile(t *testing.T) {
	m := LoadOrIdentity("/nonexistent/mapping.yml", "auditd")
	if m.Source != "auditd" {
		t.Errorf("source: got %q, want auditd", m.Source)
	}
	// Should behave as identity
	if got := m.Resolve("exe"); got != "exe" {
		t.Errorf("LoadOrIdentity passthrough failed: got %q", got)
	}
}

func TestLoadOrIdentityValidFile(t *testing.T) {
	path := writeTempMapping(t, "source: auditd\nfields:\n  CommandLine: exe\n")
	m := LoadOrIdentity(path, "auditd")
	if got := m.Resolve("CommandLine"); got != "exe" {
		t.Errorf("Resolve after LoadOrIdentity: got %q, want exe", got)
	}
}

func TestRealMappingFiles(t *testing.T) {
	cases := []struct {
		file   string
		source string
	}{
		{"../../mappings/auditd.yml", "auditd"},
		{"../../mappings/syslog.yml", "syslog"},
		{"../../mappings/journald.yml", "journald"},
	}
	for _, c := range cases {
		m, err := Load(c.file)
		if err != nil {
			t.Errorf("Load(%s): %v", c.file, err)
			continue
		}
		if m.Source != c.source {
			t.Errorf("%s source: got %q, want %q", c.file, m.Source, c.source)
		}
	}
}
