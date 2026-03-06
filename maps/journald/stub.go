//go:build !linux

package journald

import (
	"fmt"
	"log"
)

// Chop is not supported on Windows because journald is Linux-only.
func Chop(rulePath, outputType string) error {
	return fmt.Errorf("journald is not supported on Windows")
}

// ChopToLog is like Chop but calls log.Fatalf on error, for use from main.
func ChopToLog(rulePath, outputType string) {
	if err := Chop(rulePath, outputType); err != nil {
		log.Fatalf("journald: %v", err)
	}
}
