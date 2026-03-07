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

- [x] `maps/mapping/mapping.go` — `Mapping` struct, `Load`, `Resolve`
- [x] `maps/mapping/mapping_test.go` — unit tests for load and resolve
- [x] `mappings/auditd.yml` — field translation table
- [x] `mappings/syslog.yml` — field translation table
- [x] `mappings/journald.yml` — field translation table
- [x] `MappedAuditEvent` wrapper in `maps/auditd/`
- [x] `MappedSyslogEvent` wrapper in `maps/syslog/`
- [x] `MappedJournaldEvent` wrapper in `maps/journald/`
- [x] Auto-discover mapping file in each `Chop()` function
- [x] Replace `strings.Split(line, " ")` with a quoted-KV tokenizer in auditd parser
- [ ] `-mapping` CLI flag in `main.go`
- [ ] Update `README.md` with mapping file docs

---

## auditd Event Correlation

### Problem

auditd writes multiple records per logical event, all sharing the same sequence
number in the `msg=audit(timestamp:seq):` field:

```
type=SYSCALL msg=audit(1699950000.000:42): exe="/bin/bash" auid=1000 pid=1234
type=EXECVE  msg=audit(1699950000.000:42): argc=2 a0="bash" a1="-c"
type=CWD     msg=audit(1699950000.000:42): cwd="/home/user"
type=PATH    msg=audit(1699950000.000:42): name="/etc/shadow"
```

ChopChopGo currently parses each line as an independent event. When a Sigma
rule matches on the PATH record (e.g., access to `/etc/shadow`), the result
row shows empty `Exe`, `User`, and `Terminal` columns — because those fields
live on the SYSCALL record, not the PATH record.

**This is not a parser bug.** The fields are genuinely absent from the PATH
record type. However, it produces confusing output with blank columns and
creates duplicate alerts (the same logical event can trigger the rule multiple
times across its correlated records).

### Proposed Fix: Record Grouping

After parsing all lines, group records that share the same sequence number and
merge their fields into a single composite event map before passing to sigma:

```go
// Group by sequence number extracted from msg=audit(ts:seq):
groups := map[string]map[string]string{}
for _, event := range rawEvents {
    seq := event.Data["seq"] // extracted during tokenization
    if groups[seq] == nil {
        groups[seq] = map[string]string{}
    }
    for k, v := range event.Data {
        if _, exists := groups[seq][k]; !exists {
            groups[seq][k] = v // first record wins for duplicate keys
        }
    }
}
```

The merged event has all fields from all correlated records, so Sigma rules
see a complete picture and result rows are fully populated.

### Considerations

- The sequence number must be extracted during tokenization (add `seq` key)
- Within a group, SYSCALL fields (exe, auid, pid) should take precedence over
  EXECVE/PATH fields for duplicate keys — first-record-wins works because
  SYSCALL always appears first in the log
- Memory: grouping buffers the entire file in memory anyway (already the case)
- Multi-event logs with millions of records may need streaming grouping

### Checklist

- [ ] Extract `seq` from `msg=audit(ts:seq):` during tokenization
- [ ] Group raw records by `seq` in `ParseEvents`
- [ ] Merge field maps within each group (SYSCALL fields win on collision)
- [ ] Evaluate sigma rules against merged composite events
- [ ] Update `toScanResult` to read fields from merged event
- [ ] Add test: multi-record event yields single merged result with all fields
