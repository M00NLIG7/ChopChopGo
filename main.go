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
	if !(isRoot()) {
		// depending on the file access permissions, we might not need root rights
		// especially when targeting logs collected from other systems, we might encounter more lax permissions on the files
		fmt.Fprintln(os.Stderr, "Warning: not running as superuser - some accesses might fail!")
	}
	var target string
	var path string
	var outputType string
	var file string

	flag.StringVar(&target, "target", "syslog", "what type of data is to be scanned (auditd, journald, syslog)")
	flag.StringVar(&path, "rules", "rules/linux/builtin/syslog", "where to pull the yaml rules youre applying")
	flag.StringVar(&outputType, "out", "", "What type of output you want (csv, json, tables)")
	flag.StringVar(&file, "file", "", "which specific file should be scanned (falls back to target-specific defaults when left empty)")

	flag.Parse()
	if !((outputType == "csv") || (outputType == "json")) {
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
		auditd.Chop(path, outputType, file)
	case "syslog":
		syslog.Chop(path, outputType, file)
	case "journald":
		if file == "" {
			journald.Chop(path, outputType)
		} else {
			fmt.Printf("combination of target %v and giving a file not supported", target)
		}
	default:
		fmt.Printf("Invalid Target Type")
		return
	}
}
