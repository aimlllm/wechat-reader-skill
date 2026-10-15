# 复用选择

核对日期：2026-10-15。沿用已有可移植技能和 MIT 辅助程序，以全新 Git 历史建立分享包；不复制运行配置或旧交付历史。

集成 [GreenBubbles](https://github.com/bojieli/greenbubbles)，独立核验 [v0.10.0 Release](https://github.com/bojieli/greenbubbles/releases/tag/v0.10.0)。读取包装器针对该接口，升级重新核对 JSON 合同、全库验证与实际读取，不盲目追最新版。本仓库不分发其源码或二进制。

已复核鸭哥的 [wechat_db_parser](https://github.com/grapeot/wechat_db_parser) 与 [yage.ai 方法入口](https://yage.ai/context-infrastructure.html)：已解密离线格式不替代当前 macOS 本地读取及取钥，不引入其实现。其他路线沿用[既有比较](../../skills/wechat-reader-portable/references/comparison.md)，不为本次分享新造解密系统。

代价是首次部署仍需来源核验、私有副本准备和本机验证。保留上游升级路线，包装器只处理私有输入、范围、错误和输出。公开前发现完整 JSON 直出有原始字段风险，因此增加安全字段投影。
