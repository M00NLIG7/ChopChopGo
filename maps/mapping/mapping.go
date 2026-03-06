// Package mapping loads YAML field-mapping files and translates Sigma rule
// field names into log-source-native field names.
//
// This decouples Sigma rule field references from the actual field names in
// each log format, allowing community rules written for different schemas to
// work without modifying the rules or recompiling the binary.
package mapping

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Mapping holds the translation table for one log source.
type Mapping struct {
	Source string            `yaml:"source"`
	Fields map[string]string `yaml:"fields"`
}

// Load reads and parses a mapping YAML file.
func Load(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading mapping file %q: %w", path, err)
	}
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing mapping file %q: %w", path, err)
	}
	if m.Fields == nil {
		m.Fields = make(map[string]string)
	}
	return &m, nil
}

// Identity returns a pass-through mapping that leaves all field names unchanged.
func Identity(source string) *Mapping {
	return &Mapping{Source: source, Fields: make(map[string]string)}
}

// Resolve translates a Sigma field name to the log-native field name.
// If no translation exists the original name is returned unchanged, so
// rules that already use native field names continue to work.
func (m *Mapping) Resolve(sigmaField string) string {
	if native, ok := m.Fields[sigmaField]; ok {
		return native
	}
	return sigmaField
}

// LoadOrIdentity attempts to load the mapping file at path. If the file does
// not exist it silently returns an identity mapping so callers do not need to
// handle the missing-file case explicitly.
func LoadOrIdentity(path, source string) *Mapping {
	m, err := Load(path)
	if err != nil {
		return Identity(source)
	}
	return m
}
