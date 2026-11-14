#!/usr/bin/env python3
"""userlens 文章自检扫描: 标签配对/双分号/87%卡/显式对齐/敏感信息/事实锚点"""
import re
import sys

PATH = "/Users/len/CodeBuddy/dx/userlens/userlens-article.html"
html = open(PATH, encoding="utf-8").read()
errors = []
warns = []

# 1. 标签配对
for tag in ("section", "p", "pre", "body", "html"):
    op = len(re.findall(r"<%s[\s>]" % tag, html))
    cl = len(re.findall(r"</%s>" % tag, html))
    if op != cl:
        errors.append("TAG MISMATCH <%s>: open=%d close=%d" % (tag, op, cl))
img_op = len(re.findall(r"<img[\s]", html))
img_cl = len(re.findall(r"/?>", html)) - len(re.findall(r"<img[^>]*[^/]>", html))
# 更稳: 检查每个 img 标签是否自闭合
raw_imgs = re.findall(r"<img[^>]*>", html)
bad_img = [i for i in raw_imgs if not i.rstrip(">").rstrip().endswith("/")]
if bad_img:
    errors.append("IMG not selfclosed: %d (e.g. %s)" % (len(bad_img), bad_img[0][:60]))

# 2. 双分号
if ";;" in html:
    errors.append("DOUBLE SEMICOLON found")

# 3. 色块卡片 87% + margin auto (section with background)
secs = re.findall(r"<section[^>]*>", html)
bad_sec = 0
for s in secs:
    if "background" in s or "background:" in html[s.index("style="):]:
        if "width:87%" not in s or "margin-left:auto" not in s:
            bad_sec += 1
sections_with_bg = [s for s in secs if "background:" in s]
for s in sections_with_bg:
    if "width:87%" not in s or "margin-left:auto" not in s:
        errors.append("SECTION not 87%%+auto: %s" % s[:80])

# 4. 显式对齐 (所有 <p> 必须带 text-align)
ps = re.findall(r"<p[^>]*>", html)
no_align = [p for p in ps if "text-align" not in p]
if no_align:
    errors.append("P without text-align: %d (e.g. %s)" % (len(no_align), no_align[0][:60]))

# 5. 敏感信息 (公司资产虚构化检查)
sensitive = [
    r"172\.16\.", r"172\.18\.", r"10\.92\.", r"192\.168\.[0-9]+\.[0-9]+",
    r"352c9c67", r"ghp_[A-Za-z0-9]{20,}", r"br-[0-9a-f]{10,}",
    r"Appmobsf#", r"Aixdr#2026", r"br-624580c9bf89",
    r"10\.21[0-9]\.", r"10\.9[0-9]\.",
]
for pat in sensitive:
    m = re.search(pat, html)
    if m:
        errors.append("SENSITIVE hit: %s -> %s" % (pat, m.group(0)))
# 空格变体: 10.92 / 172.16 拆写
for pat in (r"10\.92\s", r"172\.16\s", r"172\.18\s"):
    if re.search(pat, html):
        errors.append("SENSITIVE space-variant: %s" % pat)

# 6. 事实锚点 (关键事实必须在文中)
anchors = [
    ("38", "自测数"), ("14", "不变量数"), ("UID", "影子管理员"),
    ("userlens.py", "工具名"), ("github.com/tomlen045/userlens", "阅读原文"),
    ("gitee.com/tomlen/userlens", "gitee 镜像"), ("backup_svc", "演示账号"),
    ("NEW_ACCOUNT", "漂移事件"), ("PRIV_JOIN", "提权事件"),
    ("shadow", "shadow 关键词"),
]
for needle, name in anchors:
    if needle not in html:
        errors.append("ANCHOR missing: %s (%s)" % (needle, name))

# 7. 图片 URL 必须是 gcore CDN SHA 锚定
img_urls = re.findall(r'<img src="([^"]+)"', html)
for u in img_urls:
    if not u.startswith("https://gcore.jsdelivr.net/gh/tomlen045/userlens@"):
        errors.append("IMG URL not SHA-pinned gcore: %s" % u[:70])
print("images: %d (all gcore SHA-pinned: %s)" % (len(img_urls),
      all(u.startswith("https://gcore.jsdelivr.net/gh/") for u in img_urls)))

if errors:
    print("SCAN FAIL (%d):" % len(errors))
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("SCAN PASS: tags paired, no ;;, sections 87%%+auto, all <p> aligned, sensitive=0, anchors %d/%d" % (len(anchors), len(anchors)))
