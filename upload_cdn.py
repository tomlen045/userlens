#!/usr/bin/env python3
"""上传 shots 到 GitHub (curl 版) + gcore jsDelivr SHA 锚定链接 + 逐张 md5 验证。"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

TOKEN = subprocess.run(["security", "find-generic-password", "-s", "GH_TOKEN", "-w"],
                       capture_output=True, text=True).stdout.strip()
REPO = "tomlen045/userlens"
CWD = os.path.dirname(os.path.abspath(__file__))

def gh_curl(method, path, body=None):
    cmd = ["curl", "-s", "-m", "40", "-w", "\n%{http_code}", "-X", method,
           "-H", "Authorization: Bearer " + TOKEN,
           "-H", "Accept: application/vnd.github+json",
           "-H", "User-Agent: userlens-cdn"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data", json.dumps(body)]
    cmd += ["https://api.github.com" + path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    payload, _, code = r.stdout.rpartition("\n")
    try:
        data = json.loads(payload) if payload.strip() else {}
    except Exception:
        data = {}
    return code, data

def push_file(local, remote_path, msg):
    content = base64.b64encode(open(local, "rb").read()).decode()
    code, old = gh_curl("GET", "/repos/%s/contents/%s" % (REPO, remote_path))
    body = {"message": msg, "content": content, "branch": "main"}
    if code == "200" and isinstance(old, dict) and old.get("sha"):
        body["sha"] = old["sha"]
    code, resp = gh_curl("PUT", "/repos/%s/contents/%s" % (REPO, remote_path), body)
    return code, (resp.get("commit") or {}).get("sha", "")

commit_shas = []
shots = ["01_audit", "02_baseline", "03_compare", "04_invariants", "05_selftest"]
for s in shots:
    st, csha = push_file("shots/%s.png" % s, "shots/%s.png" % s,
                         "docs: add %s terminal shot" % s)
    print("upload %s: %s commit=%s" % (s, st, csha[:10]))
    if st not in ("200", "201"):
        print("UPLOAD FAILED")
        sys.exit(1)
    commit_shas.append(csha)

HEAD = commit_shas[-1]
print("HEAD:", HEAD[:12])

report = {}
for s, csha in zip(shots, commit_shas):
    url = "https://gcore.jsdelivr.net/gh/%s@%s/shots/%s.png" % (REPO, csha, s)
    local_md5 = hashlib.md5(open("shots/%s.png" % s, "rb").read()).hexdigest()
    good = False
    for i in range(5):
        r = subprocess.run(["curl", "-s", "-m", "40", "-w", "\n%{http_code}\n%{content_type}",
                            url], capture_output=True)
        parts = r.stdout.rsplit(b"\n", 2)
        data = parts[0]
        meta = [p.decode() for p in parts[1:]]
        code, ct = (meta + ["0", ""])[:2]
        cd_md5 = hashlib.md5(data).hexdigest()
        if code == "200" and "image/png" in ct and cd_md5 == local_md5:
            good = True
            break
        print("  retry %s: status=%s ct=%s md5 %s vs %s" % (i + 1, code, ct,
                                                            cd_md5[:8], local_md5[:8]))
        time.sleep(5 * (i + 1))
    report[s] = {"url": url, "ok": good, "md5": local_md5}
    print("%s: %s" % (s, "OK" if good else "FAIL"))

json.dump(report, open(os.path.join(CWD, "cdn_check.json"), "w"), indent=2,
          ensure_ascii=False)
all_ok = all(v["ok"] for v in report.values())
print("CDN-ALL-OK" if all_ok else "CDN-SOME-FAILED")
sys.exit(0 if all_ok else 2)
