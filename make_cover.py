#!/usr/bin/env python3
"""userlens 封面 900x383: 对话钩子形态 + 硬指标。出图后必须 vision_analyze 验字。"""
from PIL import Image, ImageDraw, ImageFont

W, H = 900, 383
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"

img = Image.new("RGB", (W, H), "#0b0e1a")
d = ImageDraw.Draw(img)

# 背景渐变 135deg: #0b0e1a -> #1a0f2e
for x in range(W):
    t = x / W
    r = int(0x0b + (0x1a - 0x0b) * t)
    g = int(0x0e + (0x0f - 0x0e) * t)
    b = int(0x1a + (0x2e - 0x1a) * t)
    d.line([(x, 0), (x, H)], fill=(r, g, b))

_fc = {}
def F(size, mono=False):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

GOLD = "#f0b429"
WHITE = "#e6edf3"
GREY = "#8b949e"
GREEN = "#3fb950"

# 左金竖条
d.rectangle([28, 60, 34, 200], fill=GOLD)

# 栏目标签
d.text((52, 58), "审计套件 · 账号户口本透镜", font=F(20), fill=GOLD)

# 双行大字钩子（对话形态）
d.text((52, 108), "接手一台 4 年的老服务器，", font=F(38), fill=WHITE)
d.text((52, 160), "名单里 29 个账号，几个是雷？", font=F(38), fill=WHITE)
d.text((52, 236), "影子管理员 / 空密码 / 密码超期，一条命令抓完", font=F(22), fill=GREY)

# 右侧数据区
d.text((648, 96), "38", font=F(64, mono=True), fill=GOLD)
d.text((652, 170), "项自测全绿", font=F(20), fill=GREY)
d.text((648, 214), "14", font=F(44, mono=True), fill=GREEN)
d.text((700, 228), "条不变量", font=F(20), fill=GREY)

# 底部信息行（重点行加黑衬底）
d.rectangle([52, 320, 848, 358], fill="#05070d")
d.text((64, 328), "userlens", font=F(24, mono=True), fill=GOLD)
d.text((216, 332), "零依赖单文件 · passwd/shadow 一次体检 · 阅读原文直达", font=F(18), fill=WHITE)

img.save("/Users/len/Desktop/userlens-cover.png")
print("cover saved")
