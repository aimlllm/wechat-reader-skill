# 条件密钥恢复

仅在既有凭据逐库验证失败或尚无凭据时读本页。先排查错误账号、数据库路径、凭据权限、缺失分片和 CLI 接口；普通查询不附加调试器。

## 先核实可用条件

捕获只对使用者明确授权的私有微信副本进行。先完成[副本准备与清理合同](private-copy.md)。正式微信原签名和 SIP 必须保留；复制应用不证明副本可被调试。辅助程序不准备、签名、启动、登录或关闭应用，这些前置和恢复步骤由部署代理核验执行。签名、entitlements、进程权限或系统设置不满足时停止，不扩展为系统保护修改。

在外部私有部署记录固定：正式应用与私有副本的独立绝对路径和预期签名指纹、捕获及验证 CLI 的来源与校验值、所选数据库根、输出路径。不可用窗口标题或进程名称代替身份核验。正式应用与副本不得并行运行。

不要直接运行上游默认的 `greenbubbles-acquire capture`：其公开取钥说明围绕正式应用重签设计，不能据此假设它会使用这里指定的私有副本。本技能的过滤捕获辅助程序接受显式目标，只读检查应用状态，不修改签名、不关闭系统保护。

## Cold → Armed → Login

1. 退出正式微信；让已核实的私有副本处于未登录的登录界面。此时不要抢先登录。若需要退出当前账号或调整副本，仅执行本轮明确授权的操作。
2. 运行 `capture_filtered.py --help`，确认当前参数与本页一致。核验器、应用路径、预期指纹、数据根和输出均为必填；使用外部记录中的值。验证器同时要求预期 CDHash 和 `--verifier-sha256`，调用前核验签名与文件内容；缺少校验值或不匹配时不能执行。
3. 辅助程序确认 SIP、签名及目标进程身份后，等待明确的 `Armed` 状态；使用者随后自己登录。脚本不代替使用者登录，也不批量尝试账号。
4. 捕获值只交给验证器 stdin。至少一个数据库 salt 的 HMAC 验证通过后，才可将候选保存到指定外部凭据文件。全库验证通过才报告 `captured`；部分通过仅报告 `partial_candidate_saved` 并返回非零状态，须诊断未通过的库，不能宣布读取就绪。不得回显密钥、写日志、放入命令参数或粘贴到聊天中。
5. 结束后核对调试器已脱离并退出、私有副本停止、正式应用原始签名仍匹配，然后恢复正式应用。再运行 `reader.py doctor` 验证实际查询。

接口示例中的全部值均为占位符：

```sh
python3 scripts/capture_filtered.py \
  --verify-bin "/private/runtime/bin/<verified-acquire-cli>" \
  --verify-cdhash "<expected-verifier-cdhash>" \
  --verifier-sha256 "<expected-verifier-sha256>" \
  --app-path "/private/runtime/apps/<private-copy>.app" \
  --app-cdhash "<expected-private-copy-cdhash>" \
  --original-app-path "/Applications/<official-app>.app" \
  --original-cdhash "<expected-official-cdhash>" \
  --db-root "/private/runtime/data/<account>/db_storage" \
  --output "/private/runtime/credentials/<passphrase-file>" \
  --timeout-seconds 300
```

单次等待最多 300 秒。身份、签名、系统保护不匹配或候选没有任何 HMAC 验证通过时，不能保存为有效凭据；attach 被拒或预算耗尽后先诊断，不自动关 SIP、重签正式应用、强制结束其他进程或切换注入器重试。失败也须完成上述恢复检查。凭据采用完整写入后的独占发布，不覆盖已有文件；无论是否捕获成功，都以 `reader.py doctor` 的全库和消息读取结果判断可用状态。

硬终止可能留下私有 `.capture-pending-*` 文件。若正式凭据因多重链接被拒，先核实残留与凭据为同一 inode、完整内容和正确 owner，再清理该残留并重跑 doctor；不放宽权限检查，也不直接判定密钥错误。

## 为什么过滤系统 PBKDF

GreenBubbles 的捕获代码在系统 `CCKeyDerivationPBKDF` 上设置长度为 32 的条件断点，读取账户 passphrase 后脱离；按每库 salt 派生 key，再检查第一页 HMAC。它比固定微信私有地址或枚举每库内存 key 少依赖内部布局，且账户 passphrase 可用于验证后来创建的库。已有凭据在重启后先验证，不假定必须重取。

这不是跨版本保证：微信可能更换加密实现、调用入口或数据格式。Frida 仅是经过独立源码、权限和目标核验的备用；同样受系统权限限制，不能把 LLDB attach 失败解释为 Frida 必然可用。详见 [fallbacks.md](fallbacks.md)。

来源：[上游获取条件](https://github.com/bojieli/greenbubbles/blob/main/docs/PASSPHRASE_ACQUISITION.md)、[系统断点](https://github.com/bojieli/greenbubbles/blob/main/Sources/GreenBubblesAcquire/LLDBCaptureScript.swift)、[逐库 HMAC](https://github.com/bojieli/greenbubbles/blob/main/Sources/GreenBubblesAcquire/SQLCipherKeyVerifier.swift)。本页规定的是保护正式应用的包装流程，不宣称上游原装捕获器遵守这一流程。
