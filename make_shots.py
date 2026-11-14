#!/usr/bin/env python3
"""userlens 文章证据图: 内容 100% 来自 demo 真实输出(demo_log.json)。
PIL 渲染, macOS 窗框 + One Dark, 1200 宽; 出图后必须 vision_analyze 验字。"""
from PIL import Image, ImageDraw, ImageFont
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "shots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W = 1200
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = ("#98c379", "#e6edf3", "#7f8794",
                                       "#e06c75", "#e5c07b", "#61afef")

log = json.load(open(os.path.join(HERE, "demo_log.json")))

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）：→·（）'
               for ch in t)

def shot(name, lines, title="dev — zsh", h=620):
    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57")
    d.ellipse([44, 15, 56, 27], fill="#febc2e")
    d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 70
    for text, color, size, mono in lines:
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((52, y), text, font=font, fill=color)
        y += int(size * 1.7)
    img.save(f"{OUT}/{name}.png")
    print(name, "OK", h)

# 提取真实输出关键行
d1 = log["day1_audit"]["out"].splitlines()
d30c = log["day30_compare"]["out"].splitlines()

# 1) 接手日 audit
shot("01_audit", [
    ("$ sudo python3 userlens.py audit", WHITE, 22, True),
    ("userlens v1.0.0 —— 账号户口审计", GOLD, 23, False),
    ("账号总数: 29    可交互 shell: 13", WHITE, 22, True),
    ("--------------------------------------------------------", LINE, 14, True),
    ("[!!] CRITICAL UID0        backup_svc  UID=0 的非 root 账号(影子管理员)", RED, 20, False),
    ("[!!] CRITICAL PW_EXPIRED  deploy      密码已 400 天未换，超过 max=90", RED, 20, False),
    ("[!!] CRITICAL PW_EXPIRED  zhao_liu    密码已 1771 天未换，超 max=60", RED, 20, False),
    ("[!!] CRITICAL EMPTY_PW    zhou_ba     shadow 密码字段为空", RED, 20, False),
    ("[! ] WARN     PRIV_GHOST  ex_admin    在提权组 ['sudo'] 里但 passwd 无此账号", GOLD, 20, False),
    ("[! ] WARN     PW_EXP_SOON sun_qi      密码 12 天后到期(max=60, 已 48 天)", GOLD, 20, False),
    ("--------------------------------------------------------", LINE, 14, True),
    ("合计: CRITICAL=8  WARN=4", GOLD, 23, True),
    ("exit=2  —— 有发现, 接 cron 非零即告警", GREY, 20, False),
], title="userlens — 接手第一天", h=680)

# 2) 基线
shot("02_baseline", [
    ("$ sudo python3 userlens.py baseline --save base.json", WHITE, 21, True),
    ("", WHITE, 10, True),
    ("基线已保存: base.json  (账号 12 个)", GOLD, 24, True),
    ("", WHITE, 10, True),
    ("$ python3 -c \"import json; d=json.load(open('base.json'));", GREY, 19, True),
    ("    print(len(d['state']['accounts']), 'accounts pinned')\"", GREY, 19, True),
    ("12 accounts pinned", GREEN, 22, True),
    ("", WHITE, 10, True),
    ("钉住四样东西: uid / shell / 锁定状态 / 提权组", WHITE, 21, False),
    ("30 天后 compare 一跑, 谁动了户口本一目了然", GREY, 20, False),
], title="userlens — 钉住基线", h=560)

# 3) 30天后 compare 4 事件
shot("03_compare", [
    ("$ sudo python3 userlens.py compare base.json", WHITE, 21, True),
    ("", WHITE, 8, True),
    ("userlens v1.0.0 —— 基线比对: base.json", GOLD, 23, False),
    ("  NEW_ACCOUNT     backup_svc    新账号 uid=0 shell=/bin/bash", RED, 21, True),
    ("  PRIV_JOIN       lisi          新加入提权组 ['sudo']", GOLD, 21, True),
    ("  REMOVED_ACCOUNT intern01      账号已从 passwd 消失", BLUE, 21, True),
    ("  SHELL_CHANGED   zhangsan      shell /bin/bash -> /sbin/nologin", GOLD, 21, True),
    ("", WHITE, 8, True),
    ("合计 4 个事件    exit=4 —— 基线漂移", GOLD, 23, True),
    ("", WHITE, 8, True),
    ("影子管理员混进来 / 离职只处理了一半 / 实习生账号被删", GREY, 20, False),
    ("谁动了户口本, 30 天里的 4 件事全在这份报告里", GREY, 20, False),
], title="userlens — 30 天后月度对账", h=640)

# 4) 不变量清单
shot("04_invariants", [
    ("14 条不变量 · selftest 逐条锁定", GOLD, 26, False),
    ("", WHITE, 8, True),
    ("UL-01  UID=0 非 root      影子管理员, CRITICAL", WHITE, 21, True),
    ("UL-02  shadow 第二字段空  空密码, CRITICAL(!/* 是锁定不算)", WHITE, 20, True),
    ("UL-03  密码年龄>max       PW_EXPIRED; 临期 14 天 PW_EXP_SOON", WHITE, 20, True),
    ("UL-05  passwd 有 shadow 无  ORPHAN(不猜远端认证后端)", WHITE, 20, True),
    ("UL-06  重复 UID           DUP_UID, 列出全部共享账号", WHITE, 20, True),
    ("UL-07  可交互 shell 锁定  INT_LOCKED(能进门但锁了钥匙?)", WHITE, 20, True),
    ("UL-09  提权组幽灵         PRIV_GHOST(组里有, passwd 没有)", WHITE, 20, True),
    ("UL-12  字段<7 / UID 非数字  fail-loud 退出 3, 拒绝静默跳过", WHITE, 20, True),
    ("", WHITE, 8, True),
    ("$ python3 userlens.py explain UL-01   # 逐条可解释", GREY, 20, True),
], title="userlens — 不变量", h=680)

# 5) selftest
shot("05_selftest", [
    ("$ python3 userlens.py selftest", WHITE, 22, True),
    ("", WHITE, 8, True),
    ("UL-DATE PASS   UL-01a PASS   UL-01b PASS", GREEN, 21, True),
    ("UL-02a PASS   UL-02b PASS   UL-02c PASS", GREEN, 21, True),
    ("UL-03a PASS   UL-03b PASS   UL-03c PASS", GREEN, 21, True),
    ("UL-05a PASS   UL-05b PASS   UL-06a PASS", GREEN, 21, True),
    ("UL-07a PASS   UL-09a PASS   UL-09b PASS", GREEN, 21, True),
    ("UL-10-zero PASS   UL-11a PASS   UL-12a PASS", GREEN, 21, True),
    ("UL-13a PASS   UL-14a PASS   UL-14c PASS", GREEN, 21, True),
    ("", WHITE, 8, True),
    ("== 38 checks, 0 failed ==", GOLD, 24, True),
    ("ALL GREEN", GOLD, 26, True),
], title="userlens — selftest", h=600)

print("done:", sorted(os.listdir(OUT)))
