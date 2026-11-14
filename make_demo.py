#!/usr/bin/env python3
"""userlens 真机端到端演示: 接手日 audit → 存基线 → 30天后突变 → compare 抓漂移。
全部跑真实子进程(userlens.py fixture 注入), 输出原样落盘 demo_log.json 供证据图消费。
故事: 接手一台 4 年老服务器, 30 天后第一次月度对账。"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "userlens.py")
T1 = "2026-11-14"   # 接手日
T2 = "2026-12-14"   # 30 天后月度对账

def run(args):
    r = subprocess.run([sys.executable, TOOL] + args, capture_output=True, text=True)
    return r.stdout.rstrip("\n"), r.returncode

def wtmp(lines):
    fd, p = tempfile.mkstemp(prefix="uldemo_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return p

# ---------------- 接手日 (day 1) ----------------
pw1 = wtmp([
    "root:x:0:0:root:/root:/bin/bash",
    "deploy:x:1001:1001::/home/deploy:/bin/bash",
    "zhangsan:x:1002:1002::/home/zhangsan:/bin/bash",
    "lisi:x:1003:1003::/home/lisi:/bin/bash",
    "wangwu:x:1004:1004::/home/wangwu:/bin/bash",
    "zhao_liu:x:1005:1005::/home/zhao_liu:/bin/bash",
    "sun_qi:x:1006:1006::/home/sun_qi:/bin/bash",
    "zhou_ba:x:1007:1007::/home/zhou_ba:/bin/bash",
    "oldadmin:x:1008:1008::/home/oldadmin:/bin/bash",
    "intern01:x:2001:2001::/home/intern01:/bin/bash",
    "nginx:x:996:994::/var/lib/nginx:/sbin/nologin",
    "mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false",
])
sh1 = wtmp([
    "root:$6$RH:20001:0:99999:7:::",
    "deploy:$6$DP:20001:0:90:7:::",
    "zhangsan:$6$ZS:20001:0:90:7:::",
    "lisi:$6$LS:20001:0:90:7:::",
    "wangwu:$6$WW:20001:0:90:7:::",
    "zhao_liu:$6$ZL:19000:0:60:7:::",
    "sun_qi:$6$SQ:20723:0:60:7:::",
    "zhou_ba::20000:0:99999:7:::",
    "oldadmin:$6$OA:19400:0:180:7:::",
    "intern01:$6$I1:20736:0:99999:7:::",
    "nginx:*:19572:0:99999:7:::",
    "mysql:!:19572:0:99999:7:::",
])
gr1 = wtmp([
    "wheel:x:10:deploy,zhangsan",
    "sudo:x:27:deploy,oldadmin",
    "docker:x:994:deploy,zhangsan,lisi",
    "users:x:100:",
])
BASE = os.path.join(HERE, "demo_baseline.json")

out1, rc1 = run(["audit", "--passwd", pw1, "--shadow", sh1, "--group", gr1,
                 "--today", T1])
out2, rc2 = run(["baseline", "--passwd", pw1, "--shadow", sh1, "--group", gr1,
                 "--today", T1, "--save", BASE])

# ---------------- 30 天后 (day 30) ----------------
# 突变: ① 影子管理员 backup_svc(UID 0) 混进来 ② zhangsan shell 被换 nologin(离职处理了一半)
#        ③ lisi 加进 sudo(第二个提权组, 集合差分会漏的那种) ④ intern01 被删 ⑤ wangwu/sun_qi 密码过期
pw2 = wtmp([
    "root:x:0:0:root:/root:/bin/bash",
    "deploy:x:1001:1001::/home/deploy:/bin/bash",
    "zhangsan:x:1002:1002::/home/zhangsan:/sbin/nologin",
    "lisi:x:1003:1003::/home/lisi:/bin/bash",
    "wangwu:x:1004:1004::/home/wangwu:/bin/bash",
    "zhao_liu:x:1005:1005::/home/zhao_liu:/bin/bash",
    "sun_qi:x:1006:1006::/home/sun_qi:/bin/bash",
    "zhou_ba:x:1007:1007::/home/zhou_ba:/bin/bash",
    "oldadmin:x:1008:1008::/home/oldadmin:/bin/bash",
    "backup_svc:x:0:0:backup operator:/home/backup:/bin/bash",
    "nginx:x:996:994::/var/lib/nginx:/sbin/nologin",
    "mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false",
])
sh2 = wtmp([
    "root:$6$RH:20001:0:99999:7:::",
    "deploy:$6$DP:20001:0:90:7:::",
    "zhangsan:$6$ZS:20750:0:90:7:::",   # 12-01 换过
    "lisi:$6$LS:20001:0:90:7:::",
    "wangwu:$6$WW:20001:0:90:7:::",     # lastchg 20001+90=20091 过期
    "zhao_liu:$6$ZL:19000:0:60:7:::",
    "sun_qi:$6$SQ:20723:0:60:7:::",
    "zhou_ba::20000:0:99999:7:::",
    "oldadmin:$6$OA:19400:0:180:7:::",
    "backup_svc:$6$BK:20780:0:99999:7:::",
    "nginx:*:19572:0:99999:7:::",
    "mysql:!:19572:0:99999:7:::",
])
gr2 = wtmp([
    "wheel:x:10:deploy,zhangsan",
    "sudo:x:27:deploy,oldadmin,lisi",
    "docker:x:994:deploy,zhangsan,lisi",
    "users:x:100:",
])

out3, rc3 = run(["audit", "--passwd", pw2, "--shadow", sh2, "--group", gr2,
                 "--today", T2])
out4, rc4 = run(["compare", BASE, "--passwd", pw2, "--shadow", sh2,
                 "--group", gr2, "--today", T2])

log = {
    "day1_audit": {"out": out1, "rc": rc1, "label": "day-1 audit"},
    "day1_baseline": {"out": out2, "rc": rc2, "label": "day-1 baseline"},
    "day30_audit": {"out": out3, "rc": rc3, "label": "day-30 audit"},
    "day30_compare": {"out": out4, "rc": rc4, "label": "day-30 compare"},
}
with open(os.path.join(HERE, "demo_log.json"), "w") as f:
    json.dump(log, f, ensure_ascii=False, indent=2)

for k, v in log.items():
    print(f"===== {k} (exit={v['rc']}) =====")
    print(v["out"][-800:] if len(v["out"]) > 900 else v["out"])
    print()

# 清理 fixture, 保留基线文件供展示
for p in (pw1, sh1, gr1, pw2, sh2, gr2):
    os.unlink(p)
print("demo_log.json written")
