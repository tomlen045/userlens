#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
userlens —— 账号户口审计镜 (Unix account lifecycle auditor)

管「账号本身」的生死簿：/etc/passwd + /etc/shadow + /etc/group。
你手里有一份 200 个账号的名单，但没人能回答：
  - 这 200 个里有几个 UID 是 0 但 root 不是它？(影子管理员)
  - 几个账号 shadow 第二个字段是空的？(空密码 = 谁都能登)
  - 几个密码已经超过 max 龄还没换？(超期服役)
  - 几个在 passwd 有、在 shadow 没有？(孤儿条目)
  - 离职同事的账号还在 wheel 组里？(提权组遗留)

与兄弟工具的分工：
  authkeylens 管 authorized_keys(进门名单) —— userlens 管 passwd/shadow(户口本)
  sudolens 管 sudoers(提权规则)        —— userlens 管提权组成员(who 在 wheel/sudo/admin 里)
  permlens 管文件权限位                —— userlens 管账号字段本身
  sshsweep 管主机活性                  —— userlens 管账号活性

零依赖单文件，Python 3.8+ 标准库，拷走就能跑。macOS / Linux 通吃。
(注：macOS 真实用户在 Directory Services，/etc/passwd 只有系统账号——
 本机审计结果偏少是正常现象，审计 Linux 服务器才是主战场。)

退出码契约：audit 0=干净 / 2=有发现 / 3=输入错误；compare 0=无漂移 / 4=有漂移。
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import date, timedelta

VERSION = "1.0.0"
TOOL = "userlens"

NONLOGIN_SHELLS = {
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
    "/bin/true", "/nonexistent", "/dev/null",
    # 系统工具 shell: 只执行单一动作, 不是给人登录用的
    "/bin/sync", "/sbin/sync", "/sbin/shutdown", "/usr/sbin/shutdown",
    "/sbin/halt", "/usr/sbin/halt",
}
PRIV_GROUPS = ("wheel", "sudo", "admin", "root")

EPOCH = date(1970, 1, 1)

# ---------------------------------------------------------------- helpers

def today_or_inject(args_today):
    """测试注入日期；缺省取真实今天。返回 date。"""
    if args_today:
        try:
            y, m, d = args_today.split("-")
            return date(int(y), int(m), int(d))
        except Exception:
            raise SystemExit("userlens: --today 需要 YYYY-MM-DD 格式")
    return date.today()

def days_to_date(days):
    return EPOCH + timedelta(days=int(days))

def is_locked_pw_field(field):
    """shadow 第二个字段锁定判定：! 开头 / * / !! / 空*锁定由 UL-02 管"""
    if field.startswith("!"):
        return True
    if field == "*":
        return True
    return False

def is_empty_pw_field(field):
    return field == ""

def parse_passwd(path):
    """解析 /etc/passwd。行 <7 字段 = 格式错误 fail-loud (退出 3)。
    返回有序 dict 列表。空行跳过，# 注释行跳过。"""
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise SystemExit(f"userlens: 无法读取 passwd 文件 {path}: {e}")
    for ln, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            raise SystemExit(
                f"userlens: {path} 第 {ln} 行只有 {len(parts)} 个字段(需>=7)，"
                f"拒绝猜测(fail-loud): {line[:60]}")
        name, pw, uid, gid, gecos, home, shell = (parts + [""] * 7)[:7]
        try:
            uid_i = int(uid)
            gid_i = int(gid)
        except ValueError:
            raise SystemExit(
                f"userlens: {path} 第 {ln} 行 UID/GID 不是数字: {line[:60]}")
        rows.append({
            "name": name, "uid": uid_i, "gid": gid_i, "gecos": gecos,
            "home": home, "shell": shell, "line": ln,
        })
    return rows

def parse_shadow(path):
    """解析 /etc/shadow。字段宽松：名字+密码字段必须有，其余可缺省。
    返回 dict: name -> record。"""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise SystemExit(f"userlens: 无法读取 shadow 文件 {path}: {e}")
    for ln, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2 or parts[0] == "":
            raise SystemExit(
                f"userlens: {path} 第 {ln} 行格式错误(至少需要 name:passwd): {line[:60]}")
        name = parts[0]
        pw = parts[1]
        def opt(i):
            return parts[i] if len(parts) > i and parts[i] != "" else None
        rec = {
            "passwd": pw,
            "lastchg": opt(2), "min": opt(3), "max": opt(4),
            "warn": opt(5), "inact": opt(6), "expire": opt(7),
            "line": ln,
        }
        out[name] = rec
    return out

def parse_group(path):
    """解析 /etc/group。返回 dict: groupname -> [members]"""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise SystemExit(f"userlens: 无法读取 group 文件 {path}: {e}")
    for ln, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            raise SystemExit(
                f"userlens: {path} 第 {ln} 行字段不足3: {line[:60]}")
        gname, members = parts[0], parts[3] if len(parts) > 3 else ""
        out[gname] = [m for m in members.split(",") if m]
    return out

# ---------------------------------------------------------------- 核心审计

def audit_accounts(passwd_rows, shadow_map, group_map, today,
                   check_home=False, warn_expire=14):
    """全量体检。返回 findings 列表 + 聚合视图。
    每条 finding: {level, code, account, msg}  level ∈ CRITICAL/WARN/INFO
    """
    findings = []
    def add(level, code, account, msg):
        findings.append({"level": level, "code": code,
                         "account": account, "msg": msg})

    shadow_missing = set()
    uid_index = {}
    for row in passwd_rows:
        name = row["name"]
        uid_index.setdefault(row["uid"], []).append(name)

        # UL-01 UID 0 非 root
        if row["uid"] == 0 and name != "root":
            add("CRITICAL", "UID0", name,
                f"UID=0 的非 root 账号(影子管理员)，与 root 同权")

        rec = shadow_map.get(name)
        if rec is None:
            shadow_missing.add(name)
            continue

        pw = rec["passwd"]
        # UL-02 空密码
        if is_empty_pw_field(pw):
            add("CRITICAL", "EMPTY_PW", name, "shadow 密码字段为空(无密码即可认证)")
        elif is_locked_pw_field(pw):
            pass  # 锁定状态在视图里呈现，不算 finding

        # UL-03/04 密码年龄
        lastchg_raw = rec.get("lastchg")
        max_raw = rec.get("max")
        if lastchg_raw is not None and not is_locked_pw_field(pw) and pw != "":
            try:
                lastchg = int(lastchg_raw)
            except ValueError:
                add("WARN", "SHADOW_NUM", name,
                    f"lastchg 字段不是数字: {lastchg_raw!r}")
                lastchg = None
            if lastchg is not None:
                if lastchg <= 0:
                    add("WARN", "NEVER_SET", name,
                        "密码自纪元以来从未设置过(lastchg=0)")
                else:
                    age_days = (today - days_to_date(lastchg)).days
                    if max_raw is not None:
                        try:
                            max_days = int(max_raw)
                        except ValueError:
                            max_days = None
                            add("WARN", "SHADOW_NUM", name,
                                f"max 字段不是数字: {max_raw!r}")
                        if max_days is not None and max_days > 0:
                            if age_days > max_days:
                                add("CRITICAL", "PW_EXPIRED", name,
                                    f"密码已 {age_days} 天未换，超过 max={max_days} "
                                    f"(超期 {age_days - max_days} 天)")
                            else:
                                remain = max_days - age_days
                                if remain <= warn_expire:
                                    add("WARN", "PW_EXP_SOON", name,
                                        f"密码 {remain} 天后到期(max={max_days}, "
                                        f"已 {age_days} 天)")
        elif pw not in ("",) and not is_locked_pw_field(pw) and lastchg_raw is None:
            # 有密码但没写 lastchg —— 信息级
            add("INFO", "NO_LASTCHG", name, "密码字段有效但无 lastchg 记录")

    # UL-05 孤儿条目 (passwd 有 shadow 无)
    for name in sorted(shadow_missing):
        add("WARN", "ORPHAN", name,
            "passwd 有此账号但 shadow 无记录(认证后端不在本机?)")

    # UL-06 重复 UID
    for uid, names in sorted(uid_index.items()):
        if len(names) > 1:
            add("WARN", "DUP_UID", ",".join(names),
                f"UID {uid} 被 {len(names)} 个账号共享: {', '.join(names)}")

    # UL-07 可交互 shell 视图 + 交互但密码锁定
    interactive = []
    for row in passwd_rows:
        sh = row["shell"]
        if sh and sh not in NONLOGIN_SHELLS:
            interactive.append(row["name"])
            rec = shadow_map.get(row["name"])
            if rec is not None and is_locked_pw_field(rec["passwd"]):
                add("WARN", "INT_LOCKED", row["name"],
                    f"shell 可交互({sh}) 但密码字段已锁定——能进门但锁了钥匙?"
                    f"确认是否刻意")
    # 交互账号数量冗余在视图，不逐个报 INFO

    # UL-08 home 目录
    if check_home:
        for row in passwd_rows:
            home = row["home"]
            if home and home not in ("/nonexistent", "/dev/null", "/var/empty"):
                if not os.path.exists(home):
                    add("WARN", "HOME_MISSING", row["name"],
                        f"home 目录不存在: {home}")

    # UL-09 提权组成员
    priv_members = {}
    for g in PRIV_GROUPS:
        for m in group_map.get(g, []):
            priv_members.setdefault(m, set()).add(g)
    for m in sorted(priv_members):
        if m not in {r["name"] for r in passwd_rows}:
            add("WARN", "PRIV_GHOST", m,
                f"在提权组 {sorted(priv_members[m])} 里但 passwd 无此账号")

    findings.sort(key=lambda f: ({"CRITICAL": 0, "WARN": 1, "INFO": 2}[f["level"]],
                                 f["account"], f["code"]))
    views = {
        "interactive": sorted(interactive),
        "priv_members": {m: sorted(g) for m, g in sorted(priv_members.items())},
        "total_accounts": len(passwd_rows),
    }
    return findings, views

# ---------------------------------------------------------------- 基线

def snapshot_state(passwd_rows, shadow_map, group_map):
    """可比对的状态快照(JSON 可序列化)"""
    st = {}
    for r in passwd_rows:
        rec = shadow_map.get(r["name"], {})
        st[r["name"]] = {
            "uid": r["uid"],
            "shell": r["shell"],
            "locked": (is_locked_pw_field(rec.get("passwd", "*"))
                       if rec else None),
            "in_shadow": rec is not None,
        }
    priv = {}
    for g in PRIV_GROUPS:
        for m in group_map.get(g, []):
            priv.setdefault(m, set()).add(g)
    st_priv = {m: sorted(g) for m, g in sorted(priv.items())}
    return {"accounts": st, "priv": st_priv}

def diff_states(base, cur):
    """基线 vs 当前 → 事件列表。
    NEW_ACCOUNT / REMOVED_ACCOUNT / SHELL_CHANGED / UID_CHANGED /
    LOCK_CHANGED / SHADOW_APPEARED / SHADOW_LOST / PRIV_JOIN / PRIV_LEAVE
    """
    events = []
    ba = base.get("accounts", {})
    ca = cur.get("accounts", {})
    bp = base.get("priv", {})
    cp = cur.get("priv", {})
    for name in sorted(set(ba) - set(ca)):
        events.append({"type": "REMOVED_ACCOUNT", "account": name,
                       "detail": "账号已从 passwd 消失"})
    for name in sorted(set(ca) - set(ba)):
        events.append({"type": "NEW_ACCOUNT", "account": name,
                       "detail": f"新账号 uid={ca[name]['uid']} shell={ca[name]['shell']}"})
    for name in sorted(set(ba) & set(ca)):
        b, c = ba[name], ca[name]
        if b["shell"] != c["shell"]:
            events.append({"type": "SHELL_CHANGED", "account": name,
                           "detail": f"shell {b['shell']} -> {c['shell']}"})
        if b["uid"] != c["uid"]:
            events.append({"type": "UID_CHANGED", "account": name,
                           "detail": f"uid {b['uid']} -> {c['uid']}"})
        if b["locked"] != c["locked"]:
            events.append({"type": "LOCK_CHANGED", "account": name,
                           "detail": f"锁定状态 {b['locked']} -> {c['locked']}"})
        if b["in_shadow"] != c["in_shadow"]:
            t = "SHADOW_APPEARED" if c["in_shadow"] else "SHADOW_LOST"
            events.append({"type": t, "account": name,
                           "detail": f"shadow 记录 {'出现' if c['in_shadow'] else '消失'}"})
    # 按人比对组集: 集合级差分会漏掉「已在提权组的人又加入第二个提权组」
    for name in sorted(set(bp) | set(cp)):
        bset = set(bp.get(name, []))
        cset = set(cp.get(name, []))
        joined = sorted(cset - bset)
        left = sorted(bset - cset)
        if joined:
            events.append({"type": "PRIV_JOIN", "account": name,
                           "detail": f"新加入提权组 {joined}"})
        if left:
            events.append({"type": "PRIV_LEAVE", "account": name,
                           "detail": f"离开提权组 {left}"})
    events.sort(key=lambda e: (e["type"], e["account"]))
    return events

# ---------------------------------------------------------------- 输出

def print_audit(findings, views, passwd_rows, json_out=False):
    if json_out:
        print(json.dumps({
            "tool": TOOL, "version": VERSION,
            "total_accounts": views["total_accounts"],
            "counts": {
                "critical": sum(1 for f in findings if f["level"] == "CRITICAL"),
                "warn": sum(1 for f in findings if f["level"] == "WARN"),
                "info": sum(1 for f in findings if f["level"] == "INFO"),
            },
            "interactive": views["interactive"],
            "priv_members": views["priv_members"],
            "findings": findings,
        }, ensure_ascii=False, indent=2))
        return
    print(f"userlens v{VERSION} —— 账号户口审计")
    print("=" * 56)
    print(f"账号总数: {views['total_accounts']}    "
          f"可交互 shell: {len(views['interactive'])}")
    if views["interactive"]:
        print("可交互账号: " + ", ".join(views["interactive"]))
    if views["priv_members"]:
        print("提权组成员: " + "; ".join(
            f"{m}∈{'/'.join(g)}" for m, g in views["priv_members"].items()))
    print("-" * 56)
    if not findings:
        print("[OK] 未发现账号生命周期异常。")
        return
    for f in findings:
        tag = {"CRITICAL": "[!!]", "WARN": "[! ]", "INFO": "[  ]"}[f["level"]]
        print(f"{tag} {f['level']:<8} {f['code']:<14} {f['account']:<18} {f['msg']}")
    n_c = sum(1 for f in findings if f["level"] == "CRITICAL")
    n_w = sum(1 for f in findings if f["level"] == "WARN")
    n_i = sum(1 for f in findings if f["level"] == "INFO")
    print("-" * 56)
    print(f"合计: CRITICAL={n_c}  WARN={n_w}  INFO={n_i}")

def print_events(events, json_out=False, baseline_path=""):
    if json_out:
        print(json.dumps({"tool": TOOL, "version": VERSION,
                          "baseline": baseline_path,
                          "events": events}, ensure_ascii=False, indent=2))
        return
    print(f"userlens v{VERSION} —— 基线比对: {baseline_path}")
    print("=" * 56)
    if not events:
        print("[OK] 与基线零漂移。")
        return
    for e in events:
        print(f"  {e['type']:<16} {e['account']:<18} {e['detail']}")
    print("-" * 56)
    print(f"合计 {len(events)} 个事件")

# ---------------------------------------------------------------- 不变量文档

INVARIANTS = {
    "UL-01": "passwd 中 UID=0 且用户名不是 root 的账号必须报 CRITICAL(影子管理员)",
    "UL-02": "shadow 第二字段为空串必须报 CRITICAL(空密码)；!/*/!! 开头视为锁定而非空",
    "UL-03": "密码年龄 = today - lastchg；超过 max 报 PW_EXPIRED；距到期<=warn 窗口报 PW_EXP_SOON",
    "UL-04": "lastchg=0 且密码字段有效报 NEVER_SET；锁定/空密码不做年龄推断",
    "UL-05": "passwd 有而 shadow 无的账号报 ORPHAN(WARN)，不猜测远端认证后端",
    "UL-06": "重复 UID 报 DUP_UID，列出全部共享账号名",
    "UL-07": "可交互 shell 账号列视图；可交互但密码锁定报 INT_LOCKED",
    "UL-08": "--check-home 时 home 不存在报 HOME_MISSING；/nonexistent 等占位跳过",
    "UL-09": "wheel/sudo/admin/root 组成员列视图；组内有而 passwd 无的报 PRIV_GHOST",
    "UL-10": "基线往返：save→突变→compare 必须给出预期事件类型；无变化报零事件",
    "UL-11": "--json 输出字段齐全(tool/version/counts/findings/views)，可机器解析",
    "UL-12": "passwd 行字段<7 或 UID 非数字 fail-loud 退出 3，拒绝静默跳过",
    "UL-13": "日期运算可注入(--today)；lastchg/max 非数字报 SHADOW_NUM 不崩溃",
    "UL-14": "退出码契约：audit 0/2/3；compare 0/4；--today 非法退出非零",
}

# ---------------------------------------------------------------- 自测

def _wtmp(lines):
    fd, p = tempfile.mkstemp(prefix="ul_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return p

def selftest():
    """内置自测。返回 (总数, 失败列表)。"""
    results = []
    def check(cid, cond, note=""):
        results.append((cid, bool(cond), note))

    T = "2026-11-14"
    td = today_or_inject(T)
    check("UL-DATE", td == date(2026, 11, 14), "日期注入")

    # --- fixture: 健康最小环境
    pw_ok = _wtmp([
        "root:x:0:0:root:/root:/bin/bash",
        "alice:x:1001:1001:Alice:/home/alice:/bin/bash",
        "svc:x:900:900:svc:/nonexistent:/usr/sbin/nologin",
    ])
    sh_ok = _wtmp([
        "root:$6$xyz:20000:0:99999:7:::",
        "alice:$6$abc:20715:0:90:7:::",       # 30 天前换的, max 90 → remain 60, 远离 14 天告警窗
        "svc:!:20000:0:99999:7:::",
    ])
    gr_ok = _wtmp(["wheel:x:10:alice", "sudo:x:27:", "admin:x:80:"])
    try:
        rows = parse_passwd(pw_ok)
        shm = parse_shadow(sh_ok)
        grm = parse_group(gr_ok)
        fnd, vws = audit_accounts(rows, shm, grm, td)

        check("UL-01a", not any(f["code"] == "UID0" for f in fnd),
              "健康环境无 UID0")
        crit = [f for f in fnd if f["level"] == "CRITICAL"]
        check("UL-02a", not any(f["code"] == "EMPTY_PW" for f in fnd),
              "健康环境无空密码")
        check("UL-03a", not any(f["code"] == "PW_EXPIRED" for f in fnd),
              "alice 密码未超期")
        check("UL-03b", not any(f["code"] == "PW_EXP_SOON" for f in fnd),
              "alice 距到期 > 14 天窗口")
        check("UL-05a", not any(f["code"] == "ORPHAN" for f in fnd), "无孤儿")
        check("UL-06a", not any(f["code"] == "DUP_UID" for f in fnd), "无重复UID")
        check("UL-07a", sorted(vws["interactive"]) == ["alice", "root"],
              f"交互名单 {vws['interactive']}")
        check("UL-09a", vws["priv_members"].get("alice") == ["wheel"],
              "alice 在 wheel")

        # 清洁断言: 健康环境 findings 应为空
        check("UL-CLEAN", len(fnd) == 0, f"健康环境 findings={fnd}")

        # --- fixture: 问题环境
        pw_bad = _wtmp([
            "root:x:0:0:root:/root:/bin/bash",
            "ghost:x:0:0:ghost:/root:/bin/bash",          # UL-01 影子管理员
            "nopass:x:1002:1002::/home/nopass:/bin/bash", # UL-02 空密码
            "oldpw:x:1003:1003::/home/oldpw:/bin/bash",   # UL-03 超期
            "soonpw:x:1004:1004::/home/soonpw:/bin/bash", # UL-03 临期
            "orphan:x:1005:1005::/home/orphan:/bin/bash", # UL-05 孤儿
            "dupa:x:1010:1010::/home/dupa:/bin/sh",       # UL-06
            "dupb:x:1010:1010::/home/dupb:/bin/sh",       # UL-06
            "lockint:x:1006:1006::/home/lockint:/bin/zsh",# UL-07 交互但锁
            "sys:x:990:990::/nonexistent:/usr/sbin/nologin",
        ])
        sh_bad = _wtmp([
            "root:$6$r:20000:0:99999:7:::",
            "ghost:$6$g:20000:0:99999:7:::",
            "nopass::20000:0:99999:7:::",
            "oldpw:$6$o:19000:0:60:7:::",     # 2022-01-30; age≈1780 > 60 → EXPIRED
            "soonpw:$6$s:20723:0:60:7:::",    # 2026-09-25; age=50, remain=10 → SOON
            "dupa:$6$a:20700:0:99999:7:::",
            "dupb:$6$b:20700:0:99999:7:::",
            "lockint:!$6$l:20700:0:99999:7:::",
            "sys:*:20000:0:99999:7:::",
            # orphan 无记录
        ])
        gr_bad = _wtmp(["wheel:x:10:ghost,deadmember", "sudo:x:27:nopass",
                        "admin:x:80:"])
        rows_b = parse_passwd(pw_bad)
        shm_b = parse_shadow(sh_bad)
        grm_b = parse_group(gr_bad)
        f2, v2 = audit_accounts(rows_b, shm_b, grm_b, td, check_home=False)
        codes = [f["code"] for f in f2]

        check("UL-01b", any(f["code"] == "UID0" and f["account"] == "ghost"
                            and f["level"] == "CRITICAL" for f in f2), "影子管理员")
        check("UL-02b", any(f["code"] == "EMPTY_PW" and f["account"] == "nopass"
                            for f in f2), "空密码")
        check("UL-03c", any(f["code"] == "PW_EXPIRED" and f["account"] == "oldpw"
                            for f in f2), "密码超期")
        check("UL-03d", any(f["code"] == "PW_EXP_SOON" and f["account"] == "soonpw"
                            for f in f2), "临期告警")
        check("UL-05b", any(f["code"] == "ORPHAN" and f["account"] == "orphan"
                            for f in f2), "孤儿条目")
        check("UL-06b", any(f["code"] == "DUP_UID" and "dupa" in f["account"]
                            for f in f2), "重复UID")
        check("UL-07b", any(f["code"] == "INT_LOCKED" and f["account"] == "lockint"
                            for f in f2), "交互但锁定")
        check("UL-09b", any(f["code"] == "PRIV_GHOST" and f["account"] == "deadmember"
                            for f in f2), "提权组幽灵")

        # 锁定字段不误报空密码/年龄
        check("UL-02c", not any(f["code"] == "EMPTY_PW" and f["account"] == "lockint"
                                for f in f2), "! 前缀≠空密码")
        check("UL-04a", not any(f["account"] == "sys" and f["code"] in
                                ("NEVER_SET", "PW_EXPIRED") for f in f2),
              "锁定账号不做年龄推断")
        check("UL-04b", not any(f["account"] == "sys" and f["code"] == "INT_LOCKED"
                                for f in f2), "nologin 账号不进交互名单")

        # --- UL-08 home
        f3, _ = audit_accounts(rows_b, shm_b, grm_b, td, check_home=True)
        check("UL-08a", any(f["code"] == "HOME_MISSING" for f in f3),
              "home 缺失检测")

        # --- UL-10 基线往返
        st1 = snapshot_state(rows, shm, grm)
        # 突变: alice shell 变 / 加入 sudo / ghost 新账号 / svc 消失
        pw_mut = _wtmp([
            "root:x:0:0:root:/root:/bin/bash",
            "alice:x:1001:1001:Alice:/home/alice:/bin/zsh",
            "ghost:x:6666:6666::/home/ghost:/bin/bash",
        ])
        sh_mut = sh_ok
        gr_mut = _wtmp(["wheel:x:10:alice", "sudo:x:27:alice", "admin:x:80:"])
        rows_m = parse_passwd(pw_mut)
        shm_m = parse_shadow(sh_mut)
        grm_m = parse_group(gr_mut)
        st2 = snapshot_state(rows_m, shm_m, grm_m)
        ev = diff_states(st1, st2)
        types = sorted(e["type"] for e in ev)
        for want in ("NEW_ACCOUNT", "REMOVED_ACCOUNT", "SHELL_CHANGED",
                     "PRIV_JOIN"):
            check(f"UL-10-{want[:6]}", want in types, f"事件 {want} in {types}")
        # 零漂移
        ev0 = diff_states(st1, snapshot_state(rows, shm, grm))
        check("UL-10-zero", len(ev0) == 0, "零漂移=零事件")

        # --- UL-11 json
        import subprocess as _sp
        r = _sp.run([sys.executable, os.path.abspath(__file__), "audit",
                     "--passwd", pw_ok, "--shadow", sh_ok, "--group", gr_ok,
                     "--today", T, "--json"],
                    capture_output=True, text=True)
        try:
            j = json.loads(r.stdout)
            ok11 = all(k in j for k in ("tool", "version", "counts",
                                        "findings", "interactive"))
        except Exception:
            ok11 = False
        check("UL-11a", ok11, "audit --json 字段齐全")
        check("UL-11b", j.get("counts", {}).get("critical") == 0
              if ok11 else False, "健康环境 critical=0")

        # --- UL-12 fail-loud
        pw_mal = _wtmp(["broken:x:1:1"])
        rc = 0
        try:
            parse_passwd(pw_mal)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 3
        check("UL-12a", rc == 3, f"少字段退出码 {rc}")
        pw_nan = _wtmp(["bad:x:abc:1::/home:/bin/sh"])
        rc = 0
        try:
            parse_passwd(pw_nan)
        except SystemExit:
            rc = 3
        check("UL-12b", rc == 3, "UID 非数字退出 3")

        # --- UL-13 非数字 lastchg
        sh_nan = _wtmp([
            "root:$6$x:abc:0:99999:7:::",
            "alice:$6$a:20672:0:90:7:::",
        ])
        rows_c = parse_passwd(pw_ok)
        shm_c = parse_shadow(sh_nan)
        f4, _ = audit_accounts(rows_c, shm_c, grm, td)
        check("UL-13a", any(f["code"] == "SHADOW_NUM" and f["account"] == "root"
                            for f in f4), "非数字 lastchg 报 SHADOW_NUM 不崩溃")

        # --- UL-14 退出码
        r2 = _sp.run([sys.executable, os.path.abspath(__file__), "audit",
                      "--passwd", pw_bad, "--shadow", sh_bad, "--group", gr_bad,
                      "--today", T],
                     capture_output=True, text=True)
        check("UL-14a", r2.returncode == 2, f"问题环境 exit={r2.returncode}")
        r3 = _sp.run([sys.executable, os.path.abspath(__file__), "audit",
                      "--passwd", pw_ok, "--shadow", sh_ok, "--group", gr_ok,
                      "--today", T],
                     capture_output=True, text=True)
        check("UL-14b", r3.returncode == 0, f"健康环境 exit={r3.returncode}")
        r4 = _sp.run([sys.executable, os.path.abspath(__file__), "compare",
                      _wtmp(["__invalid_json__"]), "--passwd", pw_ok,
                      "--shadow", sh_ok, "--group", gr_ok, "--today", T],
                     capture_output=True, text=True)
        check("UL-14c", r4.returncode == 3, f"基线损坏 exit={r4.returncode}")

        # explain 全覆盖
        for cid in ("UL-01", "UL-07", "UL-14"):
            check(f"DOC-{cid}", cid in INVARIANTS, "invariants 文档存在")
    finally:
        for p in (pw_ok, sh_ok, gr_ok, pw_bad, sh_bad, gr_bad, pw_mut,
                  pw_mal, pw_nan, sh_nan):
            try:
                os.unlink(p)
            except OSError:
                pass

    total = len(results)
    failed = [(c, n) for c, ok, n in results if not ok]
    return total, failed

# ---------------------------------------------------------------- 演示

DEMO_PASSWD = [
    "root:x:0:0:root:/root:/bin/bash",
    "bin:x:1:1:bin:/bin:/sbin/nologin",
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin",
    "adm:x:3:4:adm:/var/adm:/sbin/nologin",
    "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin",
    "sync:x:5:0:sync:/sbin:/bin/sync",
    "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown",
    "halt:x:7:0:halt:/sbin:/sbin/halt",
    "mail:x:8:12:mail:/var/spool/mail:/sbin/nologin",
    "operator:x:11:0:operator:/root:/sbin/nologin",
    "sshd:x:74:74:SSHD:/var/empty/sshd:/sbin/nologin",
    "chrony:x:997:995::/var/lib/chrony:/sbin/nologin",
    "nginx:x:996:994::/var/lib/nginx:/sbin/nologin",
    "mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false",
    "postgres:x:26:26:PostgreSQL:/var/lib/pgsql:/bin/false",
    "redis:x:995:993::/var/lib/redis:/sbin/nologin",
    "tomcat:x:53:53::/opt/tomcat:/sbin/nologin",
    "deploy:x:1001:1001::/home/deploy:/bin/bash",
    "zhangsan:x:1002:1002::/home/zhangsan:/bin/bash",
    "lisi:x:1003:1003::/home/lisi:/bin/bash",
    "wangwu:x:1004:1004::/home/wangwu:/bin/bash",
    "zhao_liu:x:1005:1005::/home/zhao_liu:/bin/bash",
    "sun_qi:x:1006:1006::/home/sun_qi:/bin/bash",
    "zhou_ba:x:1007:1007::/home/zhou_ba:/bin/bash",
    "intern01:x:2001:2001::/home/intern01:/bin/bash",
    "intern02:x:2002:2002::/home/intern02:/bin/bash",
    "backup_svc:x:0:0:backup operator:/home/backup:/bin/bash",
    "test_temp:x:2100:2100::/home/test_temp:/bin/bash",
    "oldadmin:x:1008:1008::/home/oldadmin:/bin/bash",
]
DEMO_SHADOW = [
    "root:$6$ROOTHASH:20001:0:99999:7:::",
    "bin:*:19572:0:99999:7:::",
    "daemon:*:19572:0:99999:7:::",
    "adm:*:19572:0:99999:7:::",
    "lp:*:19572:0:99999:7:::",
    "sync:*:19572:0:99999:7:::",
    "shutdown:*:19572:0:99999:7:::",
    "halt:*:19572:0:99999:7:::",
    "mail:*:19572:0:99999:7:::",
    "operator:*:19572:0:99999:7:::",
    "sshd:!!:19572:0:99999:7:::",
    "chrony:!:19572:0:99999:7:::",
    "nginx:*:19572:0:99999:7:::",
    "mysql:!:19572:0:99999:7:::",
    "postgres:!:19572:0:99999:7:::",
    "redis:*:19572:0:99999:7:::",
    "tomcat:!!:19572:0:99999:7:::",
    "deploy:$6$DEPLOY:20371:0:90:7:::",
    "zhangsan:$6$ZS:20372:0:90:7:::",
    "lisi:$6$LS:20404:0:90:7:::",
    "wangwu:$6$WW:20674:0:90:7:::",
    "zhao_liu:$6$ZL:19000:0:60:7:::",
    "sun_qi:$6$SQ:20723:0:60:7:::",
    "zhou_ba::20000:0:99999:7:::",
    "intern01:$6$I1:20736:0:99999:7:::",
    "intern02:$6$I2:20737:0:99999:7:::",
    "backup_svc:$6$BK:20500:0:99999:7:::",
    "test_temp:!:20740:0:99999:7:::",
    "oldadmin:$6$OA:19400:0:180:7:::",
]
DEMO_GROUP = [
    "root:x:0:",
    "wheel:x:10:deploy,zhangsan,backup_svc",
    "sudo:x:27:deploy,zhangsan,oldadmin,ex_admin",
    "docker:x:994:deploy,zhangsan,lisi",
    "users:x:100:",
]

def run_demo():
    """演示: 接手一台老服务器的账号名单。所有数据为演示数据(结构参照真实发行版)。"""
    import io
    pw_f = _wtmp(DEMO_PASSWD)
    sh_f = _wtmp(DEMO_SHADOW)
    gr_f = _wtmp(DEMO_GROUP)
    try:
        rows = parse_passwd(pw_f)
        shm = parse_shadow(sh_f)
        grm = parse_group(gr_f)
        td = today_or_inject("2026-11-14")
        findings, views = audit_accounts(rows, shm, grm, td, check_home=False,
                                         warn_expire=14)
        print(f"userlens v{VERSION} —— 演示环境: 接手一台跑了 4 年的老服务器")
        print("(数据为演示数据，判定逻辑与真实运行完全一致)")
        print("=" * 60)
        print(f"账号总数: {views['total_accounts']}    "
              f"可交互 shell: {len(views['interactive'])}")
        print("-" * 60)
        for f in findings:
            tag = {"CRITICAL": "[!!]", "WARN": "[! ]", "INFO": "[  ]"}[f["level"]]
            print(f"{tag} {f['level']:<8} {f['code']:<13} {f['account']:<12} {f['msg']}")
        n_c = sum(1 for f in findings if f["level"] == "CRITICAL")
        n_w = sum(1 for f in findings if f["level"] == "WARN")
        print("-" * 60)
        print(f"合计: CRITICAL={n_c}  WARN={n_w}")
        return 2 if findings else 0
    finally:
        for p in (pw_f, sh_f, gr_f):
            try:
                os.unlink(p)
            except OSError:
                pass

# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="userlens —— 账号户口审计镜: passwd/shadow/group 生命周期审计")
    ap.add_argument("--version", action="version",
                    version=f"{TOOL} v{VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--passwd", default="/etc/passwd")
        p.add_argument("--shadow", default="/etc/shadow")
        p.add_argument("--group", default="/etc/group")
        p.add_argument("--today", default=None, help="YYYY-MM-DD 测试注入")
        p.add_argument("--json", action="store_true")

    p_audit = sub.add_parser("audit", help="全量体检")
    common(p_audit)
    p_audit.add_argument("--check-home", action="store_true")
    p_audit.add_argument("--warn-expire", type=int, default=14,
                         help="临期告警窗口(天)")

    p_shells = sub.add_parser("shells", help="可交互 shell 账号清单")
    common(p_shells)

    p_base = sub.add_parser("baseline", help="保存基线")
    common(p_base)
    p_base.add_argument("--save", required=True, help="基线 JSON 输出路径")

    p_cmp = sub.add_parser("compare", help="与基线比对")
    common(p_cmp)
    p_cmp.add_argument("baseline", help="基线 JSON 路径")

    p_demo = sub.add_parser("demo", help="内置演示环境(数据为演示数据)")
    p_demo.add_argument("--json", action="store_true")

    sub.add_parser("selftest", help="内置自测")
    p_ex = sub.add_parser("explain", help="解释不变量")
    p_ex.add_argument("code", nargs="?", default=None)

    args = ap.parse_args(argv)

    if args.cmd == "selftest":
        total, failed = selftest()
        print(f"userlens selftest: {total} checks")
        if failed:
            for c, n in failed:
                print(f"  FAIL {c}: {n}")
            print(f"RESULT: {total - len(failed)}/{total} GREEN — FAIL")
            return 1
        print("RESULT: ALL GREEN")
        return 0

    if args.cmd == "explain":
        if args.code and args.code in INVARIANTS:
            print(f"{args.code}: {INVARIANTS[args.code]}")
            return 0
        print("userlens 不变量表:")
        for k in sorted(INVARIANTS):
            print(f"  {k}: {INVARIANTS[k]}")
        return 0

    if args.cmd == "demo":
        return run_demo()

    if args.cmd == "shells":
        rows = parse_passwd(args.passwd)
        inter = [r["name"] for r in rows
                 if r["shell"] and r["shell"] not in NONLOGIN_SHELLS]
        if args.json:
            print(json.dumps({"tool": TOOL, "interactive": sorted(inter)},
                             ensure_ascii=False, indent=2))
        else:
            print(f"可交互 shell 账号 ({len(inter)}):")
            for n in sorted(inter):
                print(f"  {n}")
        return 0

    rows = parse_passwd(args.passwd)
    shm = parse_shadow(args.shadow)
    grm = parse_group(args.group)
    td = today_or_inject(args.today)

    if args.cmd == "baseline":
        st = snapshot_state(rows, shm, grm)
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump({"tool": TOOL, "version": VERSION, "state": st}, f,
                      ensure_ascii=False, indent=2)
        print(f"基线已保存: {args.save}  (账号 {len(st['accounts'])} 个)")
        return 0

    if args.cmd == "compare":
        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                base = json.load(f)
            if base.get("tool") != TOOL or "state" not in base:
                raise ValueError("不是 userlens 基线文件")
        except (OSError, ValueError) as e:
            print(f"userlens: 基线文件不可用: {e}", file=sys.stderr)
            return 3
        cur = snapshot_state(rows, shm, grm)
        events = diff_states(base["state"], cur)
        print_events(events, json_out=args.json, baseline_path=args.baseline)
        return 4 if events else 0

    # audit
    findings, views = audit_accounts(rows, shm, grm, td,
                                     check_home=args.check_home,
                                     warn_expire=args.warn_expire)
    print_audit(findings, views, rows, json_out=args.json)
    has_bad = any(f["level"] in ("CRITICAL", "WARN") for f in findings)
    return 2 if has_bad else 0

if __name__ == "__main__":
    sys.exit(main())
