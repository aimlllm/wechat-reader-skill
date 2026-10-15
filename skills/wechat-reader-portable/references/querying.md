# 只读查询与证据

使用已验证的外部 profile。在已安装技能目录执行示例；时间为 Unix 秒，所有会话和文本均为合成占位符。

## 安全输出合同

find、messages、search 均返回 `schema=wechat.reader-output.v1` 的 envelope，结果在 `items`。相比旧版 find 的裸数组，这是有意的接口变化。保留 operation、status、projectionComplete、source、consistency、page 和固定字段 warnings；未知上游字段不透传。

消息正文只接受上游已解析的 Text 和安全 Quote。文本在 `text`，安全引用在 `quote`（replyText、referText、referSender、referDisplayName、referType、referServerId）。未支持或疑似原始 XML／认证字段的内容标为 Unknown／incomplete；这不是空消息。长内容和被裁剪内容需要说明限制，不能悄悄当完整正文。

search 只提供 `snippet`，标记 SearchSnippet／snippet，不能拿它作为完整原话证据。关键结论回到同一会话的有界 messages 读取。没有 raw 开关；不通过执行底层 CLI、打印原始 payload 或临时 schema 探针绕过投影。find 没有上游游标与覆盖合同，因此只返回 limit／returned，不声称找到全部联系人。

`status=incomplete` 或 `projectionComplete=false` 都须报告缺失。即使安全投影完成，也要独立检查来源、coverageComplete 和分页；这些标记不证明本机拥有完整手机历史或真实 @ 已解码。

## 定位准确会话

先按名称查候选，再使用返回的准确会话 ID。不要用模糊名称匹配后的首条结果代替确认，也不要把候选列表写入仓库。

```sh
python3 scripts/reader.py --profile "/private/runtime/profile.json" find "<synthetic-conversation-name>" --limit 20
python3 scripts/reader.py --profile "/private/runtime/profile.json" doctor --conversation "<conversation-id>"
```

## 有界读取与分页

```sh
python3 scripts/reader.py --profile "/private/runtime/profile.json" messages \
  --conversation "<conversation-id>" --since "<start-unix-seconds>" --until "<end-unix-seconds>" --limit 100
python3 scripts/reader.py --profile "/private/runtime/profile.json" search \
  --conversation "<conversation-id>" --query "<synthetic-keyword>" \
  --since "<start-unix-seconds>" --until "<end-unix-seconds>" --limit 100
```

`--limit` 为1至200，不是全历史承诺；上游 v0.10.0 的 since 与 until 均含边界。检查 `page.hasMore`，有更多时用 `page.nextCursor` 再执行同一查询并增加 `--cursor`，保留原会话、关键词和时间窗。空页仍有游标时继续，不能解释为“没人提过”。

检查每页的覆盖、来源、警告与实际返回数量。Native FTS 依赖微信自己的索引；fallback 扫描有界窗口，可能只有部分覆盖。未读完分页、分片不可读、未匹配消息表或解码失败，应报告“在当前可读范围内找到／未找到”，不外推全部群历史。

跨库及跨页 live 读取不保证同一时刻。新消息或补同步可能改变后续页；重复分析需要 [固定输入](fallbacks.md)，不能给可变 live DB 设置 `immutable=1` 来制造快照。

## 引用、链接与署名

- 保存来源会话 ID、消息 ID、原始时间、发送人原始标识及解码状态到外部私有证据记录；展示时按用户需要选择昵称，未解析姓名保留原标识并说明。
- 只检查安全投影提供的类型、正文和安全引用，区分外层发送者与被引用者。未展开的卡片报告不可读，不打印压缩内容、原始 payload 或 XML；不得用模型补造正文。
- 可见的 @名字不证明协议级真实提及，也不能直接当发言人。本包装器不保证真实 @ 的结构字段已解码；需要时单独审查有界安全字段解码器，不把未读到说成没有被 @。
- 可见正文中的分享链接可在授权范围内另行打开。卡片字段未解码时说明链接未知，不转储媒体认证 URL。获取网页内容和读取微信记录是独立动作。
- 总结明确区分原话、群友转述、上游 README 宣称与自己推断。只对实际读到的原句加引号；“成功运行”必须有群友明确自述或实际验证支持。

参考：[上游分页与输出](https://github.com/bojieli/greenbubbles/blob/main/docs/CLI_REFERENCE.md)、[消息格式与覆盖](https://github.com/bojieli/greenbubbles/blob/main/docs/WECHAT_DATABASE_FORMAT.md)、[已知限制](https://github.com/bojieli/greenbubbles/blob/main/docs/KNOWN_LIMITATIONS.md)。
