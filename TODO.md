# TODO

Author: M00NLIG7

---

## Mapping Layer

### Background

[Chainsaw](https://github.com/WithSecureLabs/chainsaw) separates log parsing from Sigma rule evaluation using a **mapping layer** — a YAML config file that translates log-native field names into the field names that Sigma rules expect.

For example, a Sigma rule might reference `CommandLine`, but a Windows Event Log stores that value under `Event.EventData.CommandLine`. Chainsaw's mapping file bridges the two without touching either the rule or the parser.

ChopChopGo currently hardcodes field names directly in each mapper's `Select()` method. This works when log field names and Sigma rule field names match exactly, but it breaks down when:

- A Sigma rule uses a field name that differs from what the log source calls it
- A new log source is added and its fields don't align with existing rules
- A user wants to run community Sigma rules that were written for a different log schema

### Proposed Design

**Mapping files** live in a `mappings/` directory at the repo root, one per log source:

```
mappings/
  auditd.yml
  syslog.yml
  journald.yml
```

Each file declares a translation table from Sigma field names to log-native field names:

```yaml
# mappings/auditd.yml
source: auditd
fields:
  # sigma field name: auditd native field name
  CommandLine: exe
  Image:       exe
  ProcessId:   pid
  User:        auid
  LogonId:     ses
  EventType:   type
  AuditKey:    key
```

```yaml
# mappings/syslog.yml
source: syslog
fields:
  Message:  message
  Hostname: facility
```

**Mapping package** (`maps/mapping/mapping.go`) loads and resolves these files:

```go
type Mapping struct {
    Source string            `yaml:"source"`
    Fields map[string]string `yaml:"fields"`
}

func Load(path string) (*Mapping, error)

// Resolve translates a sigma field name to the log-native name.
// Falls back to the original name if no mapping exists.
func (m *Mapping) Resolve(sigmaField string) string
```

**Wrapped event types** apply the mapping transparently so the `sigma.Event` interface stays unchanged:

```go
type MappedAuditEvent struct {
    AuditEvent
    m *mapping.Mapping
}

func (e MappedAuditEvent) Select(name string) (interface{}, bool) {
    return e.AuditEvent.Select(e.m.Resolve(name))
}
```

**Auto-discovery** — each `Chop()` function looks for `mappings/<source>.yml` relative to the binary. If the file doesn't exist, a pass-through (identity) mapping is used so existing behaviour is unchanged.

**Optional override** — a `-mapping` CLI flag lets users supply their own mapping file, enabling ChopChopGo to run against custom log schemas or community Sigma rule sets without recompiling.

### Why Not Regex / Full Tokenizer

Separately from the mapping layer, the current split-on-space field extraction in the auditd parser is fragile for values that contain spaces inside quotes (e.g., `comm="my process"`). A proper key-value tokenizer that respects quoting should replace the `strings.Split(line, " ")` approach in `maps/auditd/auditd.go`. This is a parser fix, not a mapping concern, but both should land before a stable release.

### Implementation Checklist

- [ ] `maps/mapping/mapping.go` — `Mapping` struct, `Load`, `Resolve`
- [ ] `maps/mapping/mapping_test.go` — unit tests for load and resolve
- [ ] `mappings/auditd.yml` — field translation table
- [ ] `mappings/syslog.yml` — field translation table
- [ ] `mappings/journald.yml` — field translation table
- [ ] `MappedAuditEvent` wrapper in `maps/auditd/`
- [ ] `MappedSyslogEvent` wrapper in `maps/syslog/`
- [ ] `MappedJournaldEvent` wrapper in `maps/journald/`
- [ ] Auto-discover mapping file in each `Chop()` function
- [ ] `-mapping` CLI flag in `main.go`
- [ ] Update `README.md` with mapping file docs
- [ ] Replace `strings.Split(line, " ")` with a quoted-KV tokenizer in auditd parser
