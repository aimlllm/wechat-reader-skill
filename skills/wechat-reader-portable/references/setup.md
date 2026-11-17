# 安装与私有配置

首次部署读本页；日常查询转到 [querying.md](querying.md)。仓库仅提供技能与包装脚本，不含 GreenBubbles、微信应用、数据库或密钥。

首次先运行[bootstrap检查](bootstrap.md)，保持本地数据库路线，不使用代理UI／截图／OCR判断能否取钥。权限按[permissions](permissions.md)分阶段处理；屏幕录制与无障碍不是数据库前置。

## 安装边界

运行环境需要 Python3.10+。本包装器针对 GreenBubbles v0.10.0 的 JSON 接口；上游目前面向 Apple silicon、macOS14+ 和微信4.1+。这不是其他版本兼容性或新机器真实部署的保证。

1. 将完整技能目录复制到使用者选择的代理技能目录，保留 `SKILL.md`、`scripts/`、`references/` 和模板的相对关系。不要只复制入口文件。
2. 从 [v0.10.0 Release](https://github.com/bojieli/greenbubbles/releases/tag/v0.10.0) 单独取得 macOS arm64 CLI ZIP 与该版本校验清单，或审查兼容的固定源码。按[上游说明](https://github.com/bojieli/greenbubbles)核对发布来源、许可证、签名和校验值；不要直接执行其重签正式微信的取钥流程。下载及解压到仓库外，核对 greenbubbles 和 greenbubbles-acquire 的版本、帮助及 JSON 接口。
3. 在私有部署记录中固定 CLI 版本、来源提交及二进制 SHA-256。Profile 中填写预期校验值；包装脚本执行前检查二进制内容。升级时重新核验来源和实际查询行为，不自动接受新 hash；路径相同不证明内容相同。
4. 在仓库外创建运行 profile；从 [profile 模板](../assets/profile.example.json)填入自己的值。示例位置 `/private/runtime/profile.json` 只是合成路径，不是运行默认值。

## Profile 合同

`schema` 为 `wechat.reader-profile.v1`。`db_root`、`credential_file`、`reader_bin`、`acquire_bin` 均由使用者显式填写外部绝对路径：

| 字段 | 用途 |
| --- | --- |
| `db_root` | 准确账号的数据库根；不能仅凭最近修改时间猜账号 |
| `credential_file` | 已取得的账户 passphrase 文件；不把内容写入 profile |
| `reader_bin` | 已核验并固定版本的 GreenBubbles 查询 CLI |
| `acquire_bin` | 同一部署记录内的密钥验证 CLI；查询失败不会自动调用捕获 |
| `reader_sha256` | 查询 CLI 的预期 SHA-256；来自已核验的部署记录 |
| `acquire_sha256` | 验证 CLI 的预期 SHA-256；校验失败停止调用 |

Profile 与凭据必须归当前使用者所有、非符号链接、权限 `0600`，父目录为 `0700`。应用路径、签名指纹、二进制校验值、账号选择证据及验证报告也只保存在外部私有部署记录，不提交模板的真实填充值。

在已安装技能目录内查看实际接口，再验证目标会话：

```sh
python3 scripts/reader.py --help
python3 scripts/reader.py --profile "/private/runtime/profile.json" doctor --conversation "<conversation-id>"
```

`ready` 要求密钥逐库验证和目标会话读取均通过，并且覆盖标记完整；`incomplete` 与 `check_unavailable` 都不能报告为部署成功。若当前 CLI 缺少包装器依赖的接口，应固定兼容版本或适配接口后再验证，不用空结果掩盖失败。

没有密钥时读 [acquisition.md](acquisition.md)。不要照搬上游对正式微信重签的步骤；本技能保留正式应用签名和 SIP。

## 可操作的准备顺序

1. 在仓库外建立私有目录，例如 `$HOME/.local/share/wechat-reader`。配置、凭据各自父目录为0700，文件0600。解析为真实绝对路径，避免 macOS 临时目录或工具软链接造成安全检查拒绝；不要为了通过检查而放宽权限。
2. 确认微信原账号及聊天正常，选择对应 db_storage 根，不能仅凭文件修改时间选账号。保持原数据库不变；不要打印账号目录内容、密钥或原始媒体字段。
3. 若已有自己的凭据，用模板填写外置 profile；若没有，先完成[私有副本准备](private-copy.md)和[条件捕获](acquisition.md)，不把示例凭据或别人的配置带过来。
4. `find` 得到明确会话 ID 后，运行 `doctor --conversation ID`。首次尚未给定会话时，doctor 的 `bounded_conversation_read_required` 代表仍缺真实消息证明，不是密钥失效。
5. 成功后再使用 `messages` 或 `search`。实际返回内容按[安全输出合同](querying.md)读取；保存结果时只写外部私有目录。通过云端模型分析时，只提供本人授权的必要内容。

## 常见阻塞

- Python版本不足：使用已安装的 Python3.10+；不要声称 macOS 自带版本必然足够。
- 路径／权限或工具指纹错误：先核对当前文件和来源，不自动接受新 hash，不修改整个微信容器的权限。
- 尚无合格私有副本或系统禁止附加：停在[本地初始化](bootstrap.md)的准确阶段，说明缺少的准备或权限，不自动切换UI／OCR；保持SIP，正式签名不改。代理审核拒绝的同一动作不能改成人工重跑或换工具。
- 全库只部分验证、真实消息为空或覆盖不完整：报告具体状态，不能当成接入成功；同样不能当成暂无消息。
