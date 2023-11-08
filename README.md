[![go report card](https://goreportcard.com/badge/github.com/M00NLIG7/ChopChopGo)](https://goreportcard.com/report/github.com/M00NLIG7/ChopChopGo)

<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Linux Forensics Artifacts
  </h1>
 </p>
</div>

---

ChopChopGo inspired by Chainsaw utilizes Sigma rules for forensics artifact recovery, enabling rapid and comprehensive analysis of logs and other artifacts to identify potential security incidents and threats on Linux.

## Features

- :dart: Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom ChopChopGo detection rules
- :zap: Lightning fast, written in go
- :feather: Clean and lightweight execution and output formats without unnecessary bloat
- :computer: Runs on Linux

---

```
$ ./ChopChopGo -target syslog -rules ./rules/linux/builtin/syslog/
  ▄████▄   ██░ ██  ▒█████   ██▓███      ▄████▄   ██░ ██  ▒█████   ██▓███       ▄████  ▒█████
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

Using syslog file: /var/log/messages
 100% |██████████████████████████████████████████████████████████████████████████████████████████████| (67504/67504, 27840 it/s)
+-----------------+--------------------------------+-----------------------------------------+
|    TIMESTAMP    |            MESSAGE             |                  TAGS                   |
+-----------------+--------------------------------+-----------------------------------------+
| Mar  2 20:04:38 | fedora systemd[1]:             | attack.defense_evasion-attack.t1562.004 |
|                 | iptables.service: Deactivated  |                                         |
|                 | successfully.                  |                                         |
| Mar  4 10:19:03 | DESKTOP-RNL1DBO systemd[1]:    | attack.defense_evasion-attack.t1562.004 |
|                 | iptables.service: Deactivated  |                                         |
|                 | successfully.                  |                                         |
+-----------------+--------------------------------+-----------------------------------------+
Processed 67504 syslog events
```

## Quick Start Guide

### Downloading and Running

For an all-in-one zip container the ChopChopGo binary, and the official sigma rules to go with it, check out the [releases section](https://github.com/M00NLIG7/ChopChopGo/releases) In this releases section you will also find pre-compiled binary-only versions of ChopChopGo.

If you want to compile ChopChopGo yourself, you can clone the ChopChopGo repo:

`git clone https://github.com/M00NLIG7/ChopChopGo.git`

and compile the code yourself by running: `go build`.

You might need to install the development files for systemd (e. g. `apt-get install libsystemd-dev`)

#### Command Examples

```bash
./ChopChopGo # Defaults to searching through syslog 
./ChopChopGo -target auditd -rules ./rules/linux/auditd/ -file /opt/evidence/auditd.log # This searches through auditd log with the official sigma rules
./ChopChopGo -target journald -rules ./rules/linux/builtin/ # This searches through journald with specified rules
```
#### Alternative Output Formats
You may wish to use ChopChopGo in an automated fashion. The CSV and JSON output options are useful for this purpose. With both of these options, the header and progress statistics are not printed to the console.
The alternative output format is written to stdout - you can process it from there (e. g. write it to a file for later use).

Each option can be specified using the `-out` parameter.

##### CSV

```bash
./ChopChopGo -target sylog -rules ./rules/linux/builtin/syslog/ -out csv # This searches through syslog with the official sigma rules, then outputs the data in CSV format
```
##### JSON
```bash
./ChopChopGo -target syslog -rules ./rules/linux/builtin/syslog/ -out json # This searches through syslog with the official sigma rules, then outputs the data as JSON
```

### Updating Sigma Rules

The repository includes a simple script to update the included sigma rules to the newest state from the [Sigma Rules repo](https://github.com/SigmaHQ/sigma/).

```bash
./update-rules.sh
```

