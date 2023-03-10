package main

import (
	"flag"
	"fmt"
	"log"
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
		log.Fatalf("Must run as superuser")
	}
	var target string
	var path string
	var outputType string

	flag.StringVar(&target, "target", "auditd", "where should the scan be conducted")
	flag.StringVar(&path, "rules", "rules/linux/auditd", "where to pull the yaml rules youre applying")
	flag.StringVar(&outputType, "out", "", "What type of output you want (csv, json, tables)")

	flag.Parse()
	if(!((outputType == "csv") || (outputType == "json")))	{
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
		auditd.Chop(path, outputType)
	case "syslog":
		syslog.Chop(path, outputType)
	case "journald":
		journald.Chop(path, outputType)
	default:
		fmt.Printf("Invalid Target Type")
		return
	}
}
