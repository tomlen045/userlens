#!/usr/bin/env python3
"""userlens 文章渲染 QA: chrome headless=old 截全页 -> 内容底边检测 -> 裁三段给 vision"""
import os
import subprocess
import sys

HERE = "/Users/len/CodeBuddy/dx/userlens"
HTML = os.path.join(HERE, "userlens-article.html")
OUT = os.path.join(HERE, "qa")
os.makedirs(OUT, exist_ok=True)

FULL = "/tmp/userlens_qa_full.png"

# 1) 渲染 (headless=old, alarm 兜底 60s); 已有产物则复用(Chrome 渲染完可能不退出)
if os.path.exists(FULL) and os.path.getsize(FULL) > 50000:
    print("reuse existing render:", os.path.getsize(FULL), "bytes")
else:
    cmd = ["perl", "-e", "alarm 80; exec @ARGV", "--",
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
           "--headless=old",
           "--disable-gpu",
           "--proxy-server=direct://",
           "--virtual-time-budget=30000",
           "--user-data-dir=/tmp/chrome-qa-userlens",
           "--window-size=1280,9000",
           "--screenshot=" + FULL,
           "file://" + HTML]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=70)
    except subprocess.TimeoutExpired:
        subprocess.run(["pkill", "-f", "chrome-qa-userlens"], capture_output=True)
    if not os.path.exists(FULL):
        print("RENDER FAIL (no screenshot produced)")
        sys.exit(1)
    print("rendered:", os.path.getsize(FULL), "bytes")

# 2) 内容底边检测 + 裁段
from PIL import Image
import numpy as np

img = Image.open(FULL).convert("RGB")
arr = np.array(img)
nonwhite = np.where((arr < 245).any(axis=2).any(axis=-1))[0]
if len(nonwhite) == 0:
    print("EMPTY PAGE")
    sys.exit(1)
bottom = int(nonwhite[-1]) + 20
print("content bottom:", bottom, "of", arr.shape[0])

img.crop((0, 0, 1280, min(1000, bottom))).save(OUT + "/qa_head.png")
mid_start = max(0, min(1800, bottom - 3600))
img.crop((0, mid_start, 1280, mid_start + 1800)).save(OUT + "/qa_mid.png")
tail_start = max(0, bottom - 1400)
img.crop((0, tail_start, 1280, bottom)).save(OUT + "/qa_tail.png")
print("QA segments saved:", sorted(os.listdir(OUT)))
