# Security policy

## Scope

Qinjing is a live-executable attack corpus. Its cases simulate intrusion
behavior on the host that runs them, and the corpus is shaped to keep a
run contained:

- Every IPv4 literal in a command must be TEST-NET (`203.0.113.x`),
  loopback, or the link-local metadata endpoint `169.254.169.254`, and
  bare domains must be RFC 2606 names (`example.com`, `.invalid`, ...).
  `tools/parse.py` rejects anything else at validation time.
- Side-effect writes must stay under `/tmp/qinjing-`, and the runner
  executes the recorded cleanup commands as root before every run.
- The runner executes each case under throwaway uids with per-case
  session isolation.

Even with these constraints, running attack cases on a production host
is a bad idea. Run the suite on a disposable VM or container that you
own.

## Report a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Include the case id or file
path and the exact command you ran.

Report these kinds of issues:

- A case that touches real hosts or real credentials, writes outside
  `/tmp/qinjing-` without an honest impact rating, or is destructive
  while rated `impact: none` or `temporary`.
- A runner or scorer defect that lets a case affect the host beyond its
  rating, or that hides a truncated alert read.

## Responsible use

Run qinjing only on systems you own or have written authorization to
test. The project is a measuring instrument for defenders, not an attack
tool.

## 中文说明

本套件是现场执行的攻击语料。用例命令只准出现测试网段、回环与链路本地元
数据地址（`tools/parse.py` 校验期强制），副作用限定在 `/tmp/qinjing-` 下且
runner 每轮以 root 执行清理，逐案用一次性 uid 隔离执行。即便如此也请在自
有的一次性虚机或容器里运行，不要上生产主机。漏洞请走本仓库 Security 标签
页的私有漏洞报告。
