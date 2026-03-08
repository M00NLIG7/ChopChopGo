//go:build !linux

package journald

import (
	"fmt"
	"log"
)

// Chop is not supported on non-Linux platforms because journald is Linux-only.
func Chop(rulePath, outputType, mappingPath string) error {
	return fmt.Errorf("journald is not supported on this platform")
}

// ChopToLog is like Chop but calls log.Fatalf on error, for use from main.
func ChopToLog(rulePath, outputType, mappingPath string) {
	if err := Chop(rulePath, outputType, mappingPath); err != nil {
		log.Fatalf("journald: %v", err)
	}
}
