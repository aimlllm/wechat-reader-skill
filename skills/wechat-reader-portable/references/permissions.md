# Mac权限：按失败阶段处理

首次数据库接入不依赖代理读屏。只在实际操作被拒后判断需要哪层权限，不一次性要求开启全部隐私权限。权限检查结果、路径及系统日志留在外部私有记录，不上传仓库。

## 文件读取被拒

先核对本人选定的路径、owner、文件0600／私有父目录0700及工具校验。确认目标文件实际被系统拒绝访问后，再判断是否涉及“系统设置 → 隐私与安全 → 文件和文件夹／完全磁盘访问权限”。不要只凭EACCES或EPERM猜原因；普通文件权限与macOS隐私控制不同，管理员身份也不自动绕过后者。

只向系统实际归属的执行宿主申请必要授权，例如实际执行命令的终端或代理App，不能预先给所有Python、Codex、Claude和Terminal授权。路径不存在、错误账号、符号链接或工具hash不符，不能靠扩大权限修复。

## 私有副本准备受阻

“App 管理”允许一个App更新或删除其他App。只有准备独立私有副本确实受到这层保护拒绝，并核对责任宿主与目标路径后，才请求本人检查此设置；单一Operation not permitted不足以定论。它不是日常数据库查询或调试附加的通用前置，不改变正式微信的签名。

## 本地调试捕获受阻

先核对现有捕获器要求的开发者工具、私有目标签名与调试资格、完整进程路径和SIP状态。“开发者工具”设置只在具体拒绝或系统提示表明需要时检查；不能用它代替目标所需的get-task-allow资格。Hardened Runtime属于应用签名约束，不能当作一个终端权限开关。

SIP保持开启，正式微信保持原签名；仅处理已核验、明确允许的私有副本。缺少Xcode Command Line Tools、目标指纹不符、缺副本或版本条件未知时，先报告和修正具体前置，不重试附加或反复退出账号。

## UI权限不属于本路线

“录屏与系统录音”（旧系统可能叫屏幕录制）用于屏幕／声音获取，“无障碍”用于界面控制。只有本人另选的UI／OCR任务才按需处理。它们不是读取本地数据库或获取密钥的前提，UI blank时不要把重新授权录屏当成初始化的必经步骤。

## 代理审核与本人操作

代理的自动安全审核、执行策略与macOS权限是不同层。记录被拒的动作与脱敏原因；明确拒绝同一捕获动作时停止，不改用sudo、换脚本／工具、弱化策略或让本人手动执行来绕过。

本人可以完成相关动作已获允许的密码输入、手机登录确认和系统同意；密码只在本机可信提示中输入，不交给代理。处理系统要求重启执行宿主等步骤后，只重新检查已确认的问题，不重跑整套初始化。没有权限证明时保持check_unavailable，不声称版本不兼容或没有消息。

## 官方依据

- [Apple隐私与安全设置](https://support.apple.com/zh-cn/guide/mac-help/mchl211c911f/mac)：各项设置用途与名称；以使用者本机界面为准。
- [Apple文件权限分层](https://developer.apple.com/forums/thread/678819)：BSD／ACL与MAC访问控制、责任进程及错误区分。
- [Apple调试资格](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)、[Hardened Runtime](https://developer.apple.com/documentation/xcode/configuring-the-hardened-runtime)：调试工具资格不自动授予目标签名例外。
- [Codex自动审核](https://learn.chatgpt.com/docs/sandboxing/auto-review)：不同于Mac系统权限；审核拒绝不能靠换执行方式规避。

本页是排查指引，不是Apple、微信或代理厂商对本方案的兼容认证。
