# 首次初始化：固定本地数据库路线

目标是在本机建立本人账号的数据库读取，不要求代理看见微信窗口。截图全白只说明界面通道无结果，不能证明密钥错误、数据库不可读或版本不兼容。以下步骤不调用UI、截图或OCR工具。

## 1. 检查准备阶段

在完整技能目录运行：

```sh
python3 scripts/bootstrap.py
python3 scripts/bootstrap.py --profile "/private/runtime/profile.json"
```

路径只是占位符。无配置时按[setup](setup.md)准备外置profile；不要为运行此检查先申请管理员权限。bootstrap仅检查元数据，不读取凭据正文／数据库、不执行工具、不捕获、不改应用，也不会弹权限或登录请求。

固定 `route=local_database_memory_helper`。`preparation_required`表示尚缺配置或凭据；`check_unavailable`表示路径、权限或工具检查尚不能完成；`verification_required`仅表示凭据元数据合格，需要继续验证。任何一种都不是ready。具体stage、reason和nextStep以JSON固定分类为准，不从异常中打印私有路径或内容。

bootstrap退出码3表示仍需准备或验证，不是程序崩溃；2表示检查不可用。它不会用退出码0或ready认证数据库接入。`--help`只展示用法。凭据父目录缺失须先修运行目录，不能当作已经准备好捕获输出的位置。

## 2. 有凭据：先验证，能读就不重取

```sh
python3 scripts/reader.py --profile "/private/runtime/profile.json" doctor
python3 scripts/reader.py --profile "/private/runtime/profile.json" find "<conversation-name>" --limit 20
python3 scripts/reader.py --profile "/private/runtime/profile.json" doctor --conversation "<resolved-id>"
```

第一个doctor尚无会话时，`bounded_conversation_read_required`不是密钥失效。准确会话由CLI查找结果和本人选择确定，不借UI标题猜测。权限／工具失败也不是“密钥无效”，先按[权限指南](permissions.md)诊断。

## 3. 无有效凭据：准备并检查本地捕获

读[私有副本准备](private-copy.md)和[捕获参数](acquisition.md)。本项目只复用现有过滤捕获器，在明确允许的私有目标中有界观察登录时的密钥派生；不新增内存转储、私有地址扫描或UI取钥。

先向 `capture_filtered.py` 提供捕获所需的同一组外置路径与核验指纹，并增加 `--preflight-only`。这一模式只验证配置、工具、签名和系统保护条件，不读取数据库salt、不附加进程、不写凭据或启动捕获。`preflight_passed`不等于能附加、不证明登录状态或兼容性。

如果缺合格副本、调试条件或动作被审核拒绝，停在准确阶段并说明缺什么。不要切换OCR、Frida、直接运行上游默认捕获器或让本人手动重跑同一被拒动作。本人密码、手机确认和合法系统同意只是认证交接，不替代动作许可。

## 4. 经允许的一次捕获与本人登录

只有前置条件齐备且相关动作允许时，才进入原有捕获流程。本人确认原账号和历史正常、正式微信已完全退出、指定私有副本停在原账号登录画面，暂不登录。进程路径和PID本身不能证明账号或登录状态，代理不盲点UI。

捕获器明确报告Armed后，由本人在指定副本完成登录和手机确认。代理通过程序阶段和固定状态读取进度，不用截图检查密钥。单轮最多300秒；同一错误先诊断，不反复要求退出登录。执行本阶段仍需以[acquisition](acquisition.md)的目标、验证、脱离和清理合同为准。

## 5. 验收与重复读取

- 捕获阶段：区分captured、partial_candidate_saved、失败或清理未确认；必须核对detachConfirmed，不把候选数量或Armed当成功。
- 收尾：确认调试器退出、私有副本停止、正式应用原签名匹配并恢复正常运行。
- 数据库阶段：验证当前发现的全部数据库；读取本人选定会话的一条真实消息，核对ID、发送者、时间、来源、覆盖及实际可读的安全Text／Quote。仅未知媒体或搜索snippet不足以证明正文已读。
- 日常阶段：只使用reader的有界查询与分页；无须重新登录或启动调试器。只读本机已同步内容，不承诺服务器完整历史或零封号风险。

用户明确另选的界面读取属于独立任务。它可以按其授权范围处理，但不能替代上述数据库验收。
