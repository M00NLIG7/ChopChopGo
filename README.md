[![go report card](https://goreportcard.com/badge/github.com/M00NLIG7/ChopChopGo)](https://goreportcard.com/report/github.com/M00NLIG7/ChopChopGo)

<div align="center">
 <p>
  <h1>
   Rapidly Search and Hunt through Linux Forensics Artifacts
  </h1>
 </p>
</div>
```
$ sudo ./ChopChopGo -target syslog -rules ./rules/linux/builtin/syslog/
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
By M00NL1G7

Using syslog file: /var/log/messages
100% |██████████████████████████████████████████████████████████████████████████████████████████████| (66624/66624, 27771 it/s)
+-----------------+--------------------------------+-----------------------------------------+
| TIMESTAMP | MESSAGE | TAGS |
+-----------------+--------------------------------+-----------------------------------------+
| Mar 2 20:04:38 | fedora systemd[1]: | attack.defense_evasion-attack.t1562.004 |
| | iptables.service: Deactivated | |
| | successfully. | |
| Mar 4 10:19:03 | DESKTOP-RNL1DBO systemd[1]: | attack.defense_evasion-attack.t1562.004 |
| | iptables.service: Deactivated | |
| | successfully. | |
+-----------------+--------------------------------+-----------------------------------------+
Processed 66527 syslog events

```

```
