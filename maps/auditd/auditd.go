package auditd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	sigma "github.com/M00NLIG7/go-sigma-rule-engine"
	"github.com/M00NLIG7/ChopChopGo/maps/mapping"
	"github.com/M00NLIG7/ChopChopGo/maps/output"
	"github.com/schollz/progressbar/v3"
)

// msgRe extracts the Unix second and sequence number from an audit(SSSS.mmm:SEQ) token.
// Both captures are used: the timestamp for display and the seq for event correlation.
// Compiled once at package level to avoid per-line overhead.
var msgRe = regexp.MustCompile(`audit\((\d+)\.\d*:(\d+)\)`)

// AuditEvent represents a single record from the auditd log.
type AuditEvent struct {
	Type string
	Data map[string]string
}

// Keywords satisfies the sigma.Event interface.
func (e AuditEvent) Keywords() ([]string, bool) {
	keywords := []string{e.Type}
	for k := range e.Data {
		keywords = append(keywords, k)
	}
	return keywords, true
}

// Select satisfies the sigma.Event interface.
func (e AuditEvent) Select(name string) (interface{}, bool) {
	if name == "type" {
		return e.Type, true
	}
	if value, ok := e.Data[name]; ok {
		return value, true
	}
	return nil, false
}

// MappedAuditEvent wraps an AuditEvent with a field-name mapping so that
// Sigma rules written with non-native field names (e.g. CommandLine → exe)
// are resolved transparently before Select is called.
type MappedAuditEvent struct {
	AuditEvent
	m *mapping.Mapping
}

func (e MappedAuditEvent) Keywords() ([]string, bool) { return e.AuditEvent.Keywords() }

func (e MappedAuditEvent) Select(name string) (interface{}, bool) {
	return e.AuditEvent.Select(e.m.Resolve(name))
}

// parseLine tokenizes a single auditd log line into a key-value map.
//
// It walks the line once, character by character, respecting both double-quoted
// and single-quoted values so fields like:
//
//	proctitle="bash -c rm -rf /"
//	msg='op=PAM:authentication acct="root" res=failed'
//
// are stored correctly. This avoids the allocation overhead of strings.Split
// and correctly handles spaces inside quoted values — a bug the old approach
// could not fix without a much more complex regular expression.
func parseLine(line string) map[string]string {
	event := make(map[string]string, 16)
	i, n := 0, len(line)

	for i < n {
		// Skip inter-field spaces.
		for i < n && line[i] == ' ' {
			i++
		}
		if i >= n {
			break
		}

		// Read key (up to '=' or end of token).
		keyStart := i
		for i < n && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= n || line[i] != '=' {
			// No '=' — not a key=value token; skip.
			for i < n && line[i] != ' ' {
				i++
			}
			continue
		}
		key := line[keyStart:i]
		i++ // consume '='

		// Read value: double-quoted, single-quoted, or bare (until space).
		var value string
		if i < n && line[i] == '"' {
			i++ // consume opening '"'
			start := i
			for i < n && line[i] != '"' {
				i++
			}
			value = line[start:i]
			if i < n {
				i++ // consume closing '"'
			}
		} else if i < n && line[i] == '\'' {
			i++ // consume opening '\''
			start := i
			for i < n && line[i] != '\'' {
				i++
			}
			value = line[start:i]
			if i < n {
				i++ // consume closing '\''
			}
		} else {
			start := i
			for i < n && line[i] != ' ' {
				i++
			}
			value = line[start:i]
		}

		// The msg field holds the audit timestamp and sequence number.
		if key == "msg" && len(value) > 6 && value[:6] == "audit(" {
			matches := msgRe.FindStringSubmatch(value)
			if matches == nil {
				continue
			}
			unixTime, _ := strconv.ParseInt(matches[1], 10, 64)
			event["timestamp"] = time.Unix(unixTime, 0).UTC().Format(time.RFC3339)
			event["seq"] = matches[2]
		} else {
			event[key] = value
		}
	}

	return event
}

// windowSize is the maximum number of distinct sequence numbers held in memory
// at once. auditd records for a single event are always written consecutively
// (typically 4–6 records), so 32 is a generous safety margin. Peak memory
// usage is O(windowSize × fields) regardless of log size.
const windowSize = 32

// ParseEvents reads an auditd log file, correlates multi-record events by their
// sequence number, and returns one merged AuditEvent per logical event.
//
// auditd writes several record types (SYSCALL, EXECVE, CWD, PATH, …) for a
// single kernel event, all sharing the same msg=audit(ts:seq) sequence number.
// Merging them gives Sigma rules a complete field set — exe, auid, name, cwd —
// in a single event, eliminating blank columns and duplicate rule hits.
//
// Field precedence within a group: first record wins. SYSCALL is always
// written before EXECVE/CWD/PATH so SYSCALL fields (exe, auid, pid) take
// priority over the same-named fields on later record types.
//
// Streaming sliding-window: at most windowSize groups are kept in memory at
// once. When the window is full and a new sequence number arrives, the oldest
// group is flushed immediately. This reduces peak memory from O(total records)
// to O(windowSize × fields), making multi-GB log scanning practical.
func ParseEvents(logFile string) ([]AuditEvent, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []AuditEvent
	standalone := 0

	// window is a fixed-capacity queue of seq strings in insertion order.
	// We keep it at most windowSize long; copy+reslice keeps the backing
	// array capped at windowSize+1 so memory stays O(windowSize).
	window := make([]string, 0, windowSize+1)
	// groups maps seq → merged field map; only window entries are present.
	groups := make(map[string]map[string]string, windowSize)

	// soloKey is a stack-allocated scratch buffer for formatting __solo_N keys,
	// avoiding the interface boxing that fmt.Sprintf would cause.
	var soloKey [32]byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "type=") {
			continue
		}

		data := parseLine(line)
		if len(data) == 0 {
			continue
		}

		seq := data["seq"]
		if seq == "" {
			// Record has no parseable sequence — treat as its own event.
			// Use a stack buffer + strconv to avoid fmt.Sprintf's interface boxing.
			b := append(soloKey[:0], "__solo_"...)
			b = strconv.AppendInt(b, int64(standalone), 10)
			seq = string(b)
			standalone++
		}

		if _, exists := groups[seq]; !exists {
			// New seq: evict oldest group if the window is full.
			if len(window) >= windowSize {
				// Inline flush: avoids closure allocation and indirect call.
				oldest := window[0]
				copy(window, window[1:])
				window = window[:len(window)-1]
				g := groups[oldest]
				delete(groups, oldest)
				events = append(events, AuditEvent{Type: g["type"], Data: g})
			}
			window = append(window, seq)
			groups[seq] = make(map[string]string, len(data))
		}

		g := groups[seq]
		for k, v := range data {
			if _, exists := g[k]; !exists {
				g[k] = v // first record wins
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Flush all remaining groups in insertion order.
	for _, seq := range window {
		g := groups[seq]
		events = append(events, AuditEvent{Type: g["type"], Data: g})
	}
	return events, nil
}

// FindLog returns filePath when non-empty, otherwise reads /etc/audit/auditd.conf
// to locate the active log file.
func FindLog(file string) (string, error) {
	if file != "" {
		if _, err := os.Stat(file); err != nil {
			return "", fmt.Errorf("failed to find provided file %v", file)
		}
		return file, nil
	}

	f, err := os.Open("/etc/audit/auditd.conf")
	if err != nil {
		return "", fmt.Errorf("failed to open auditd.conf: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "log_file") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("log_file option not found in auditd.conf")
}

var auditdRenderer = output.Renderer{
	Headers: []string{"Timestamp", "User", "Exe", "Terminal", "PID", "Tags", "Author"},
	Row: func(r output.ScanResult) []string {
		return []string{
			r.Timestamp,
			r.User,
			r.Exe,
			r.Terminal,
			r.PID,
			output.TagString(r.Tags),
			r.Author,
		}
	},
}

func toScanResult(event AuditEvent, res sigma.Results) output.ScanResult {
	return output.ScanResult{
		Timestamp: event.Data["timestamp"],
		// auditd logs use lowercase "auid", not "AUID"
		User:     event.Data["auid"],
		Exe:      event.Data["exe"],
		Terminal: event.Data["terminal"],
		PID:      event.Data["pid"],
		Tags:     res[0].Tags,
		Author:   res[0].Author,
		RuleID:   res[0].ID,
		Title:    res[0].Title,
	}
}

// Chop scans the auditd log against Sigma rules and writes results to stdout.
// mappingPath overrides the default mappings/auditd.yml when non-empty.
func Chop(rulePath, outputType, filePath, mappingPath string) error {
	auditdLogPath, err := FindLog(filePath)
	if err != nil {
		return fmt.Errorf("finding audit log: %w", err)
	}

	events, err := ParseEvents(auditdLogPath)
	if err != nil {
		return fmt.Errorf("parsing audit log: %w", err)
	}

	ruleset, err := sigma.NewRuleset(sigma.Config{Directory: []string{rulePath}})
	if err != nil {
		return fmt.Errorf("loading ruleset: %w", err)
	}

	showProgress := outputType != "json" && outputType != "csv"
	var bar *progressbar.ProgressBar
	if showProgress {
		bar = progressbar.Default(int64(len(events)))
	}

	if mappingPath == "" {
		mappingPath = "mappings/auditd.yml"
	}
	m := mapping.LoadOrIdentity(mappingPath, "auditd")

	var results []output.ScanResult
	for _, event := range events {
		mapped := MappedAuditEvent{event, m}
		if res, match := ruleset.EvalAll(mapped); match {
			results = append(results, toScanResult(event, res))
		}
		if showProgress {
			bar.Add(1)
		}
	}

	if err := output.Write(os.Stdout, outputType, results, auditdRenderer); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if showProgress {
		fmt.Printf("Processed %d auditd events\n", len(events))
	}
	return nil
}

// ChopToLog is like Chop but calls log.Fatalf on error, for use from main.
func ChopToLog(rulePath, outputType, filePath, mappingPath string) {
	if err := Chop(rulePath, outputType, filePath, mappingPath); err != nil {
		log.Fatalf("auditd: %v", err)
	}
}
