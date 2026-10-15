# Mac 微信只读 Skill · Codex / Claude Code

让 Mac 上的 Codex 或 Claude Code 在本人授权范围内查找、读取和总结**已同步到本机的微信聊天**。包含可复用 skill、读取包装器、条件密钥恢复辅助程序及合成测试；不包含任何使用者的配置、密钥或聊天记录。

这不是官方微信 API，也不是一键安装器。首次使用需要在自己的 Mac 上准备工具和验证兼容性；准备完成后，普通查询通常不需要重新登录或管理员权限。

## 开始前准备什么

- 一台运行微信并拥有目标聊天历史的 Mac，以及能访问本地文件和终端的 Codex 或 Claude Code。远程云端会话不能直接读取这台 Mac。
- Python **3.10+**。主工具 [GreenBubbles](https://github.com/bojieli/greenbubbles) 当前面向 **Apple silicon、macOS 14+、微信 4.1+**；这不是所有版本均兼容的承诺。
- 已有有效数据库密钥时先验证并复用。尚无密钥时，首次取钥可能需要 Xcode Command Line Tools、管理员授权、手机登录确认和系统同意；密码与手机确认由本人完成。

## 最快开始：交给你的代理

1. 在 GitHub 点击 **Code → Download ZIP** 并解压，或用 Git 克隆本仓库。
2. 用本机 Codex / Claude Code 打开这个目录；Claude Code 也可在解压目录内运行 `claude`。
3. 复制 [SETUP-PROMPT.md](SETUP-PROMPT.md) 给代理，也可以先说：

```text
阅读 README.md、SETUP-PROMPT.md 和 skills/wechat-reader-portable/SKILL.md。
按其中流程，在这台 Mac 上准备本人微信的只读访问。
先检查已有接入；真实配置、密钥和结果都放在仓库外。
验证全部数据库，再读取我指定会话的一条真实消息；未完成不要报告成功。
```

代理应检查当前机器、选择准确账号、核验外部工具、填写私有配置，再验证真实读取。需要取钥时，先准备和核验**独立私有微信副本**，保持正式微信原签名和 SIP 开启；不要直接照搬上游重签正式应用的命令。

## 可选：安装为长期可调用的 skill

无需安装也可以让代理直接阅读 skill。需要自动发现时，从仓库根目录运行对应的一段；已有同名目录或链接时会停止，请先比较版本。

**Codex：**

```sh
(
  set -e
  target="$HOME/.agents/skills/wechat-reader-portable"
  test ! -e "$target"
  test ! -L "$target"
  mkdir -p "$HOME/.agents/skills"
  cp -R skills/wechat-reader-portable "$target"
)
```

新会话输入 `$wechat-reader-portable`；桌面客户端也可用技能选择器。旧客户端目录规则可能不同，按[官方说明](https://learn.chatgpt.com/docs/build-skills)核对，避免同名技能重复安装。

**Claude Code：**

```sh
(
  set -e
  target="$HOME/.claude/skills/wechat-reader-portable"
  test ! -e "$target"
  test ! -L "$target"
  mkdir -p "$HOME/.claude/skills"
  cp -R skills/wechat-reader-portable "$target"
)
```

重新打开会话，输入 `/wechat-reader-portable`。见 [Claude Code 官方说明](https://code.claude.com/docs/en/skills)。请完整复制 skill 目录，保留脚本与参考文件。

## 准备好之后怎么用

```text
使用 wechat-reader-portable，检查当前账号的读取状态。
找到我指定的群，阅读最近七天消息，附上来源和时间。
找出提及或引用我的待回复候选，核对后续回复；说明真实 @ 是否已验证，只草拟，不发送。
```

具体命令与私有 profile 见[准备指南](skills/wechat-reader-portable/references/setup.md)；分页、引用与 @ 的判断见[查询指南](skills/wechat-reader-portable/references/querying.md)。

**完成标准：**选定账号正确、全部发现的数据库验证成功、指定会话中真实消息可读；执行过捕获时，还要确认调试器与私有副本已退出、正式微信恢复正常。`Armed`、候选密钥或合成测试通过都不足以证明完成。

## 隐私与限制

- 真实 profile、凭据、数据库、截图、导出和检查报告必须放在仓库之外；私有目录 `0700`、配置和凭据 `0600`。密钥只由程序经 stdin 使用，不发给代理、不写入参数或日志。
- 查询采用安全字段投影，不向代理输出原始 payload、XML 或媒体认证字段。未知格式保留为不可读；图片、语音、朋友圈和真实 @ 的完整解码不在本包装器保证范围。
- **本地读取不等于模型离线运行。** 使用云端 Codex / Claude 模型分析消息时，提供给模型的内容会交给相应服务商；只读取本人授权的必要范围。
- 本机可能没有完整手机历史；版本变化、索引和媒体解码可能造成缺失。读取失败必须说明原因，不能报告成“没有消息”。
- 此项目不发送消息、不自动回复，也不自动重签正式微信或关闭 SIP。首次取钥不能承诺账号零风险。

## 验证与维护

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 skills/wechat-reader-portable/scripts/capture_filtered.py --self-test
python3 scripts/privacy_audit.py
```

测试只用合成数据，不接触真实微信。隐私检查覆盖本地可达 Git 历史、暂存区、跟踪文件和提交身份，仍需人工审阅；它不证明其他机器的实际兼容性。

详细边界、复用选择与验证记录见[维护文档](docs/README.md)。代码与文档采用 [MIT](LICENSE)，第三方工具单独安装并遵守各自许可。本仓库不分发微信、GreenBubbles 二进制或实际部署文件。GitHub 页面仍会显示公开的仓库所属账号。
