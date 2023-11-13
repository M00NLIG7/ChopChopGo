//go:build windows

package journald

import (
	"log"
)

func Chop(rulePath string, outputType string) interface{} {
	log.Fatalf("Access to journald is not supported on Windows!")
	return nil
}
