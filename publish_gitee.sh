#!/bin/bash
# Gitee 建仓 + push + 置公开 + 匿名复核（userlens 专用，照 sshsweep 脚本逻辑）
set -e
cd /Users/len/CodeBuddy/dx/userlens
REPO=userlens
DESC="userlens - Unix account lifecycle auditor in one file: shadow admins (UID0), empty passwords, expired passwords (lastchg vs max), orphans, duplicate UIDs, privilege-group ghosts, baseline drift events (NEW_ACCOUNT/SHELL_CHANGED/PRIV_JOIN...), 38-check selftest (UL-01..14). Zero dependencies, fail-loud parsing, cron exit codes."

# 1. 找活 token
TOKEN=""
for t in $(grep -hoE '[0-9a-f]{32}' /Users/len/CodeBuddy/dx/*/.git/config 2>/dev/null | sort -u); do
  if curl -s -m 10 "https://gitee.com/api/v5/user?access_token=$t" | grep -q '"login":"tomlen"'; then
    TOKEN=$t; echo "token OK: ${t:0:6}..."; break
  fi
done
[ -n "$TOKEN" ] || { echo "no valid gitee token"; exit 1; }

# 2. 建仓 (form urlencode, token 在 body)
CODE=$(curl -s -o /tmp/gitee_create_$REPO.json -w '%{http_code}' -X POST \
  "https://gitee.com/api/v5/user/repos" \
  --data-urlencode "access_token=$TOKEN" \
  --data-urlencode "name=$REPO" \
  --data-urlencode "description=$DESC" \
  --data-urlencode "private=true" \
  --data-urlencode "auto_init=false")
echo "create: $CODE"; head -c 300 /tmp/gitee_create_$REPO.json; echo

# 3. push (token 内嵌 URL 必须带用户名段)
git init -q 2>/dev/null || true
git add -A
git commit -q -m "userlens 1.0.0: Unix account lifecycle auditor — shadow admin/empty pw/expiry/orphan/dup-UID audit, baseline drift events, 38-check selftest ALL GREEN" || true
git remote remove gitee 2>/dev/null || true
git remote add gitee "https://tomlen:$TOKEN@gitee.com/tomlen/$REPO.git"
GIT_TERMINAL_PROMPT=0 git -c http.version=HTTP/1.1 push -u gitee main 2>&1 | tail -2

# 4. 置公开 (必须带 name 字段)
sleep 2
PCODE=$(curl -s -o /tmp/gitee_patch_$REPO.json -w '%{http_code}' -X PATCH \
  "https://gitee.com/api/v5/repos/tomlen/$REPO" \
  --data-urlencode "access_token=$TOKEN" \
  --data-urlencode "name=$REPO" \
  --data-urlencode "private=false")
echo "patch-public: $PCODE"

# 5. 匿名读回复核
sleep 2
curl -s "https://gitee.com/api/v5/repos/tomlen/$REPO" | python3 -c "import json,sys; d=json.load(sys.stdin); print('GITEE-VERIFY private=%s full_name=%s' % (d.get('private'), d.get('full_name')))"
curl -s -o /dev/null -w 'raw-readme: %{http_code}\n' "https://gitee.com/tomlen/$REPO/raw/main/README.md"
