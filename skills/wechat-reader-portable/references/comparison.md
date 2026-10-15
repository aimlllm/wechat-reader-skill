# 路线比较与来源

稳定性分开看：取钥对版本的依赖、日常数据一致性、失败是否可见、源码是否还能复现。以下是代码路线判断，不能替代使用者在当前平台与账户上的验证。

| 路线 | 相对优势 | 主要限制 | 使用选择 |
| --- | --- | --- | --- |
| 已有账户 passphrase + GreenBubbles 只读查询 | 逐库派生与验证，动态发现分片，分页和覆盖状态 | 微信私有格式、索引范围、跨库一致性仍有限 | 已验证后优先日常查询 |
| 过滤系统 PBKDF 捕获 | 少依赖微信私有地址；账户 passphrase 可用于后来新增库 | 登录时机、进程权限、系统调用或加密方案变化 | 仅有条件恢复；保留正式签名和 SIP |
| 每库 key 内存扫描 | 可直接适配已扫描数据库 | 布局变化、未访问新库、key 地图缺项；旧源可用性不稳定 | 有固定、可审查源码时再评估 |
| 截图／OCR | 不需要数据库密钥，对加密改动更耐受 | UI 变化、加载时机、文字与身份识别、完整性 | 有界应急，并保留原图复核 |
| 已解析原文归档 | 固定分析输入，重复总结可比对 | 不实时，不能重新取得未导出字段 | 已读内容的可重复分析 |
| 一致 SQLite 快照 | 固定数据库状态，可离线再查询 | 获取需正确处理 WAL 与凭据；仍不覆盖手机未同步内容 | 需要稳定分页或重新解码时 |

不以星数、作者自评分或“零检测风险”作为稳定证明。CLI 成功退出、数据库 HMAC 验证和消息覆盖完整也是不同证据；分别记录，不能互相替代。

## 可复查公开来源

- [GreenBubbles](https://github.com/bojieli/greenbubbles)：主查询 CLI、许可与 Release；[只读查询实码](https://github.com/bojieli/greenbubbles/blob/main/Native/GreenBubbles/src/live_query.rs)、[取钥机制](https://github.com/bojieli/greenbubbles/blob/main/docs/PASSPHRASE_ACQUISITION.md)。上游原装取钥说明要求修改应用签名，不作为本技能私有副本流程的保证。
- [wechat-mac-reader 安装脚本](https://github.com/xingfanxia/wechat-mac-reader/blob/main/scripts/setup.sh)：组合每库扫描器和 chatlog-bot；两个依赖均需重新核实来源。曾依赖的 [Thearas 解密项目](https://github.com/Thearas/wechat-db-decrypt-macos) 当前公开入口只保留说明；[chatlog-bot 下架公示](https://github.com/github/dmca/blob/master/2026/07/2026-07-27-wechat-6.md) 记录访问封锁背景，不是对使用者作法律结论。
- [Chatlog Alpha 当前说明](https://github.com/teest114514/chatlog_alpha)：GitHub 源码和 Release 撤下；[迁移项目](https://gitflic.ru/project/goring/chatlog_alpha)。代码可用性、许可、功能和平台支持需重新查证，不能按旧分享断言已停止或仍兼容。
- [wechat-summary](https://github.com/jackwener/wechat-summary)：[分页捕获实码](https://github.com/jackwener/wechat-summary/blob/main/workflows.py)、[OCR 去重实码](https://github.com/jackwener/wechat-summary/blob/main/ocr.py)。
- [ai-wechat-newsletter](https://github.com/LouYu2015/ai-wechat-newsletter)：[外部 key 连接](https://github.com/LouYu2015/ai-wechat-newsletter/blob/main/wechat_daily/wechat_db.py)、[分片发现和提取](https://github.com/LouYu2015/ai-wechat-newsletter/blob/main/wechat_daily/chat_extractor.py)。日报组织可参考，live immutable 连接不采用。
- [grapeot/wechat_db_parser](https://github.com/grapeot/wechat_db_parser)：已解密离线格式的参考，不直接证明当前 macOS live 可用；[yage.ai 可行性报告](https://yage.ai/share/wechat-uia-platform-feasibility-survey-20260327.html) 提供路线背景，实际能力仍以代码和授权验证为准。
- [SQLite URI 语义](https://www.sqlite.org/uri.html)、[WAL 与只读条件](https://www.sqlite.org/wal.html)：用于区分正常只读连接、不可变输入和一致快照。

来源可能撤下或改变。固定使用的源码／Release 在外部部署记录标注来源提交、许可证、校验值和检查时间；不把本文的路线评估当成永久安装保证。
