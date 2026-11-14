#!/usr/bin/env python3
"""GitHub 建仓 + push + 读回验证 (userlens)。全部 HTTP 走 curl 子进程
(本机 python urllib 对 api.github.com SSL 握手超时, curl 正常——2026-11-14 实测)。"""
import json
import os
import subprocess
import sys
import time

TOKEN = subprocess.run(["security", "find-generic-password", "-s", "GH_TOKEN", "-w"],
                       capture_output=True, text=True).stdout.strip()
REPO = "tomlen045/userlens"
CWD = "/Users/len/CodeBuddy/dx/userlens"

def curl_json(method, path, body=None, auth=True, tries=4):
    """curl 调 GitHub API, 返回 (http_code, dict_or_empty)"""
    cmd = ["curl", "-s", "-m", "30", "-w", "\n%{http_code}",
           "-X", method,
           "-H", "Accept: application/vnd.github+json",
           "-H", "User-Agent: userlens-publish"]
    if auth:
        cmd += ["-H", "Authorization: Bearer " + TOKEN]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json",
                "--data", json.dumps(body)]
    cmd += ["https://api.github.com" + path]
    for i in range(tries):
        r = subprocess.run(cmd, capture_output=True, text=True)
        out = r.stdout
        if "\n" in out:
            payload, _, code = out.rpartition("\n")
        else:
            payload, code = out, "0"
        try:
            data = json.loads(payload) if payload.strip() else {}
        except Exception:
            data = {}
        if code not in ("0", "") or payload.strip():
            return code, data
        print("retry %d: empty response" % (i + 1))
        time.sleep(3 * (i + 1))
    return "0", {}

def curl_status(url, tries=4):
    for i in range(tries):
        r = subprocess.run(["curl", "-s", "-m", "30", "-o", "/dev/null",
                            "-w", "%{http_code}", "-L",
                            "-H", "User-Agent: userlens-publish", url],
                           capture_output=True, text=True)
        code = r.stdout.strip()
        if code not in ("0", "", "000"):
            return code
        time.sleep(3 * (i + 1))
    return "0"

# 1. 建仓 (存在则跳过)
code, resp = curl_json("GET", "/repos/%s" % REPO)
if code == "200":
    print("repo exists, skip create")
else:
    code, resp = curl_json("POST", "/user/repos", {
        "name": "userlens",
        "description": "userlens - Unix account lifecycle auditor in one file: shadow admins (UID0), empty passwords, expired passwords (lastchg vs max), orphans, duplicate UIDs, privilege-group ghosts, baseline drift events, 38-check selftest. Zero dependencies, fail-loud, cron exit codes.",
        "private": False,
        "has_wiki": False,
        "has_projects": False,
    })
    print("create:", code, resp.get("full_name", ""), str(resp.get("errors") or "")[:120])
    if code not in ("201", "202"):
        sys.exit("create failed: %s %s" % (code, str(resp)[:200]))

# 2. git push (libcurl, token 内嵌 URL)
env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
url = "https://tomlen045:%s@github.com/%s.git" % (TOKEN, REPO)
def run(cmd):
    r = subprocess.run(cmd, cwd=CWD, capture_output=True, text=True, env=env)
    return r.returncode, (r.stdout + r.stderr).strip()

run(["git", "remote", "remove", "github"])
run(["git", "remote", "add", "github", url])
rc, out = run(["git", "push", "-u", "github", "main"])
print("push:", rc, out.splitlines()[-1] if out else "")
if rc != 0:
    sys.exit("push failed: %s" % out[:300])

# 3. 远端哈希对齐验证
rc, out = run(["git", "rev-parse", "HEAD"])
local_sha = out.strip()
remote_sha = ""
for i in range(6):
    code, resp = curl_json("GET", "/repos/%s/branches/main" % REPO)
    remote_sha = (resp.get("commit") or {}).get("sha", "")
    if remote_sha == local_sha:
        print("SHA ALIGN:", remote_sha[:12])
        break
    time.sleep(5)
else:
    sys.exit("sha mismatch: local=%s remote=%s" % (local_sha, remote_sha))

# 4. 匿名读回 (curl)
code, resp = curl_json("GET", "/repos/%s" % REPO, auth=False)
if code == "200":
    print("ANON-API: stars=%s private=%s" % (resp.get("stargazers_count"),
                                             resp.get("private")))
else:
    sys.exit("anon api failed: %s" % code)
raw_code = curl_status("https://raw.githubusercontent.com/%s/main/README.md" % REPO)
print("RAW-README:", raw_code)
page_code = curl_status("https://github.com/%s" % REPO)
print("PAGE:", page_code)
if raw_code == "200" and page_code == "200":
    print("GITHUB ALL OK")
else:
    sys.exit("readback incomplete: raw=%s page=%s" % (raw_code, page_code))
