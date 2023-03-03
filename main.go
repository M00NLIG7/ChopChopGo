package main

import (
	"flag"
	"fmt"

	"github.com/M00NLIG7/ChopChopGo/maps/auditd"
	"github.com/M00NLIG7/ChopChopGo/maps/syslog"
)

// type string rules_path

func main(){
	var target string
	var path string


	flag.StringVar(&target, "target", "auditd", "where should the scan be conducted")
	flag.StringVar(&path, "rules", "rules/linux/auditd", "where to pull the yaml rules youre applying")


	flag.Parse()
	fmt.Println(path)

	switch target {
	case "auditd":
		auditd.Chop(path)
	case "syslog":
		syslog.Chop(path)
	default:
		// freebsd, openbsd,
		// plan9, windows...
		fmt.Printf("Invalid Target Type")
		return
	}
}