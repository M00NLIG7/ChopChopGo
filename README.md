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

#### Command Examples

```bash
./ChopChopGo -target # Defaults to searching through auditd
./ChopChopGo -target syslog -rules ./rules/linux/builtin/syslog/ # This searches through syslog with the official sigma rules
./ChopChopGo -target journald -rules ./rules/linux/builtin/ # This searches through journald with specified rules
```
