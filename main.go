package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"

	"github.com/M00NLIG7/ChopChopGo/maps/auditd"
	"github.com/M00NLIG7/ChopChopGo/maps/journald"
	"github.com/M00NLIG7/ChopChopGo/maps/syslog"
)

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

func main() {
	if !isRoot() {
		// depending on the file access permissions, we might not need root rights
		// especially when targeting logs collected from other systems, we might encounter more lax permissions on the files
		fmt.Fprintln(os.Stderr, "Warning: not running as superuser - some accesses might fail!")
	}

	var target string
	var path string
	var outputType string
	var file string
	var mappingPath string

	flag.StringVar(&target, "target", "syslog", "what type of data is to be scanned (auditd, journald, syslog)")
	flag.StringVar(&path, "rules", "rules/linux/builtin/syslog", "where to pull the yaml rules you're applying")
	flag.StringVar(&outputType, "out", "", "what type of output you want (csv, json, or leave empty for table)")
	flag.StringVar(&file, "file", "", "which specific file should be scanned (falls back to target-specific defaults when left empty)")
	flag.StringVar(&mappingPath, "mapping", "", "path to a custom field-mapping YAML file (overrides the built-in mappings/<target>.yml)")

	flag.Parse()

	if outputType != "csv" && outputType != "json" {
		banner := `  ▄████▄   ██░ ██  ▒█████   ██▓███      ▄████▄   ██░ ██  ▒█████   ██▓███       ▄████  ▒█████
 ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒▓██░  ██▒   ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒▓██░  ██▒    ██▒ ▀█▒▒██▒  ██▒
 ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒▓██░ ██▓▒   ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒▓██░ ██▓▒   ▒██░▄▄▄░▒██░  ██▒
 ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░▒██▄█▓▒ ▒   ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░▒██▄█▓▒ ▒   ░▓█  ██▓▒██   ██░
 ▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░▒██▒ ░  ░   ▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░▒██▒ ░  ░   ░▒▓███▀▒░ ████▓▒░
 ░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒▓▒░ ░  ░   ░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒▓▒░ ░  ░    ░▒   ▒ ░ ▒░▒░▒░
   ░  ▒    ▒ ░▒░ ░  ░ ▒ ▒░ ░▒ ░          ░  ▒    ▒ ░▒░ ░  ░ ▒ ▒░ ░▒ ░          ░   ░   ░ ▒ ▒░
 ░         ░  ░░ ░░ ░ ░ ▒  ░░          ░         ░  ░░ ░░ ░ ░ ▒  ░░          ░ ░   ░ ░ ░ ░ ▒
 ░ ░       ░  ░  ░    ░ ░              ░ ░       ░  ░  ░    ░ ░                    ░     ░ ░
 ░                                     ░
			By Keyboard Cowboys (M00NL1G7)
`
		fmt.Println(banner)
	}

	switch target {
	case "auditd":
		auditd.ChopToLog(path, outputType, file, mappingPath)
	case "syslog":
		syslog.ChopToLog(path, outputType, file, mappingPath)
	case "journald":
		if file != "" {
			fmt.Fprintln(os.Stderr, "Error: the journald target does not support -file; journald uses a binary format accessible only via the systemd API.")
			os.Exit(1)
		}
		journald.ChopToLog(path, outputType, mappingPath)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown target %q (must be auditd, journald, or syslog)\n", target)
		os.Exit(1)
	}
}
