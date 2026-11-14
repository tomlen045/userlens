# userlens

[简体中文](README.md) | [English below](#english)

**账号户口审计镜** —— 你手里有一份 200 个账号的 passwd，但没人能回答：这里面有几个 UID 是 0 却不叫 root？几个密码早就过期？几个是上个月离职同事留下的？

userlens 管的是「账号本身」的生命周期：/etc/passwd + /etc/shadow + /etc/group 三份户口本一次体检，14 条不变量，零依赖单文件 CLI，Python 3.8+ 标准库，拷走就能跑。macOS / Linux 通吃。

[![tests](https://img.shields.io/badge/self--tests-38%2F38-green)]() [![deps](https://img.shields.io/badge/deps-zero-yellow)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

---

## 解决什么问题

* 交接了一台跑了 4 年的服务器 → **没人知道账号名单里有几个雷**。`audit` 一条命令：影子管理员（UID 0 非 root）、空密码、密码超期、孤儿条目、重复 UID、提权组幽灵，一次报完
* 半夜出了事才翻 /etc/passwd → **影子管理员混进来 3 个月没人发现**。`baseline` + `compare` 把账号名单钉住：新账号、shell 被换、UID 变更、锁定状态翻转、进/出提权组——谁动了户口本，退出码非 0 直接接 cron
* 离职处理只做了一半（shell 换了 nologin 但账号还在提权组里）→ **PRIV_JOIN/PRIV_LEAVE 事件按「人」比对组集合**，集合级差分会漏掉的「已在 wheel 的人又加进 sudo」照样抓出来（这是自测里真实逮住过的 bug）
* 每次安全检查都要手工数「有几个能登录的账号」→ `shells` 子命令一条命令出可交互 shell 名单
* 扫描脚本随手写错格式 → **fail-loud**：passwd 行少于 7 字段、UID 非数字，直接报错退出 3，拒绝静默跳过
* 想写自动化又怕工具乱报 → **退出码契约**：audit 0=干净 / 2=有发现 / 3=输入错误；compare 0=无漂移 / 4=有漂移。`--json` 输出机器可读

## 快速使用

```bash
sudo python3 userlens.py audit                 # 全量体检（默认读 /etc/passwd 等）
sudo python3 userlens.py audit --check-home    # 顺带查 home 目录是否存在
python3 userlens.py shells                     # 可交互 shell 账号清单
sudo python3 userlens.py baseline --save base.json   # 钉住当前名单
sudo python3 userlens.py compare base.json     # 漂移比对（有事件退出码 4）
python3 userlens.py demo                       # 内置演示环境（不用 sudo）
python3 userlens.py selftest                   # 38 项自测
```

| 你想 | 你跑 |
| --- | --- |
| 接手老服务器，先看账号有几个雷 | `audit`（CRITICAL/WARN 分级） |
| 数一数谁能登录 | `shells` |
| 每月对账：账号名单动没动 | `baseline --save` → 下月 `compare` |
| 审计影子管理员/空密码 | `audit`，找 `UID0` / `EMPTY_PW` |
| 密码超期台账 | `audit`，找 `PW_EXPIRED`（可 `--warn-expire 30` 调临期窗） |
| 接进 cron/CI | `--json` + 退出码 0/2/3/4 |
| 在测试机/课堂上演示 | `demo`（内置演示数据，判定逻辑与真实一致） |

## 不变量（selftest 逐条锁定，`explain UL-xx` 可单独解释）

* **UL-01** UID=0 且用户名不是 root → CRITICAL（影子管理员）
* **UL-02** shadow 第二字段空串 → CRITICAL（空密码）；`!`/`*`/`!!` 开头是锁定，不是空
* **UL-03** 密码年龄 = today − lastchg；超过 max 报 PW_EXPIRED；距到期 ≤ warn 窗口报 PW_EXP_SOON
* **UL-04** lastchg=0 报 NEVER_SET；锁定/空密码不做年龄推断
* **UL-05** passwd 有而 shadow 无 → ORPHAN（WARN），不猜测远端认证后端
* **UL-06** 重复 UID → DUP_UID，列出全部共享账号
* **UL-07** 可交互 shell 账号列视图；可交互但密码锁定 → INT_LOCKED
* **UL-08** `--check-home` 时 home 不存在 → HOME_MISSING；占位路径跳过
* **UL-09** wheel/sudo/admin/root 成员列视图；组内有而 passwd 无 → PRIV_GHOST
* **UL-10** 基线往返：save→突变→compare 必须给出预期事件类型；无变化报零事件
* **UL-11** `--json` 字段齐全（tool/version/counts/findings/views）
* **UL-12** passwd 字段<7 或 UID 非数字 → fail-loud 退出 3
* **UL-13** 日期可注入（`--today`）；lastchg/max 非数字报 SHADOW_NUM 不崩溃
* **UL-14** 退出码契约：audit 0/2/3；compare 0/4

## 设计取舍（一句大实话）

shadow 第二字段是 `!` 或 `*` 只说明「密码认证被锁」，不排除其他认证通道
（SSH key、LDAP）还在放行——所以可交互 shell + 锁定密码只报 WARN 让你确认，
不报 CRITICAL 吓人。同理，ORPHAN 只说明本机两本户口不一致，账号是否真失效
要看认证后端。userlens 管「户口本写了什么」，不管「门实际从哪儿开」。

另外 macOS 的真实用户在 Directory Services 里，/etc/passwd 只有系统账号——
本机跑出来结果偏少是正常现象，审计 Linux 服务器才是主战场。

## 适合谁

* 接手老服务器、先把账号名单里的雷排完的运维
* 要定期给安全检查交「账号台账」的团队
* 离职流程要复核「账号+提权组都清干净没」的 HRBP/管理员
* 把 userlens 丢进 cron、用退出码接告警链的自动化玩家

## 不适合谁

* 需要 SSH key / LDAP 等其他认证通道审计的场景——用 authkeylens
* sudoers 规则级审计——用 sudolens
* 登录行为分析（谁半夜登了）——用 authguard 类日志工具

## 兄弟工具

[debugkit](https://github.com/tomlen045/debugkit)（调试取证）、
[sshsweep](https://github.com/tomlen045/sshsweep)（SSH 主机活性）、
[authkeylens](https://github.com/tomlen045/authkeylens)（进门名单）、
[sudolens](https://github.com/tomlen045/sudolens)（提权规则）、
[permlens](https://github.com/tomlen045/permlens)（文件权限位）、
[capguard](https://github.com/tomlen045/capguard)（磁盘水位）、
[porteye](https://github.com/tomlen045/porteye)（端口暴露面）——
userlens 补上「账号户口本」这块拼图。

## License

MIT

---

## English

**userlens — Unix account lifecycle auditor** in a single zero-dependency
Python file. It audits `/etc/passwd`, `/etc/shadow` and `/etc/group`:
shadow admins (UID 0, not root), empty password hashes, expired passwords
(lastchg vs max), orphan entries, duplicate UIDs, interactive-shell listing,
privilege-group ghosts, plus a `baseline`/`compare` mode that reports
NEW_ACCOUNT / REMOVED_ACCOUNT / SHELL_CHANGED / UID_CHANGED / LOCK_CHANGED /
SHADOW_APPEARED / SHADOW_LOST / PRIV_JOIN / PRIV_LEAVE events with cron-friendly
exit codes (audit 0/2/3, compare 0/4). 38 built-in self-tests, `--json`
output, fail-loud parsing. Run `python3 userlens.py demo` for a canned demo,
`selftest` for the suite, `explain UL-01` for any invariant.
