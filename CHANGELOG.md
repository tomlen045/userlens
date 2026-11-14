# userlens CHANGELOG

## 1.0.0 (2026-11-14)

首发版本。

- audit：UID0 影子管理员 / EMPTY_PW 空密码 / PW_EXPIRED 密码超期 / PW_EXP_SOON 临期 /
  NEVER_SET / ORPHAN 孤儿 / DUP_UID 重复 UID / INT_LOCKED 交互但锁定 /
  HOME_MISSING / PRIV_GHOST 提权组幽灵
- shells：可交互 shell 账号清单
- baseline + compare：9 类漂移事件（NEW_ACCOUNT / REMOVED_ACCOUNT / SHELL_CHANGED /
  UID_CHANGED / LOCK_CHANGED / SHADOW_APPEARED / SHADOW_LOST / PRIV_JOIN / PRIV_LEAVE）
- --json 机器可读 + 退出码契约（audit 0/2/3，compare 0/4）
- demo 内置演示环境；selftest 38 checks；explain UL-xx 不变量解释
- 开发期自测逮住的 2 个真 bug：
  - PRIV_JOIN 集合级差分漏报「已在提权组的人又加入第二个提权组」→ 改按人比对组集合
  - /bin/sync、/sbin/shutdown、/sbin/halt 被误判为可交互 shell → 加入 NONLOGIN_SHELLS
