# Contributing

Qinjing grows by cases. New attack shapes, new benign false-positive
probes, and adapters for more HIDS products are the contributions that
matter. This page is the path a case travels from idea to merged corpus.

## What fits

- Attack cases anchored to the signal vocabulary and to a real ATT&CK
  technique. The vocabulary is the class list in `SIGNAL_CLASSES`
  (`tools/parse.py`); the matrix snapshot `data/attack-enterprise.txt`
  is the ground truth for technique ids and tactic tags.
- Benign operations that should stay silent. These form the
  false-positive pool, so they must be ordinary admin work, not
  attack lookalikes.
- Adapters (alert exporters) for HIDS products, following
  `adapters/xiezhi/` as the reference shape.
- Tooling fixes and runner improvements.

## Prepare a case

Every case must:

- Use TEST-NET (`203.0.113.x`), loopback, or the link-local metadata
  endpoint as network targets, and RFC 2606 domains for name lookups.
  Real hosts, real credentials, and real exfiltration endpoints are
  grounds for closing the PR.
- Keep side-effect writes under `/tmp/qinjing-` and record a cleanup
  command, which the runner executes as root before every run.
- Carry a `bin:` field listing every binary the commands need. The
  runner probes them and scores missing ones as NOT-RUN, never as
  misses.
- State an impact rating (`none`, `temporary`, or `destructive`)
  honestly.

The fastest check that a YAML edit is well-formed is
`python tools/parse.py --validate corpus/qinjing.yaml`.

## The merge gate

Proposals are YAML blocks in the corpus shape, not direct corpus edits.

1. Put your proposal file under `proposals/` in your branch.
2. Run the gate. It writes a merged copy and never touches the corpus:

   ```
   python tools/merge_check.py corpus/qinjing.yaml proposals/your-round.yaml --out /tmp/merged.yaml
   ```

3. Open a PR with the proposal file, the gate output, and, for attack
   cases, the ATT&CK technique and signal class you anchor to.

## Review

The maintainer reviews anchors and duplicates, merges accepted blocks
into `corpus/qinjing.yaml`, and re-freezes `benchmark-manifest.json` in
the same commit so the manifest gate stays green. Verdicts are recorded
in a mapping ledger kept by the maintainer outside this repository; the
public repo carries the result, not the deliberation.

## Before you push

The local gate chain (`.githooks/`) runs the full selftest on push. Run
it yourself first:

```
python tools/parse.py --validate corpus/qinjing.yaml
python tools/parse.py --stats corpus/qinjing.yaml
bash tests/selftest.sh
python tools/anchor_lint.py
python tools/family_check.py
python tools/attack_coverage.py corpus/qinjing.yaml --strict
```

`tools/gate.sh` wraps these in three Python steps plus a fourth that
builds, vets, and tests the Go dashboard. Step 4 needs Go 1.26 or newer;
without a Go toolchain it skips loudly, and the dashboard data is still
gated by the selftest in step 3.

## 中文说明

贡献以用例为主。提案是语料同形的 YAML 块，放在分支的 `proposals/` 下，走
`tools/merge_check.py` 合并门（只写合并副本，不动语料本体），PR 附门输出。
用例只准打测试网段、回环与链路本地元数据地址，副作用限定 `/tmp/qinjing-`
并登记清理命令；判决底账由维护者在本仓之外留存，公开仓只承载结果。
