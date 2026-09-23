# MoonRADIUS 查重记录

- 检查日期：2026-09-23
- 候选范围：RADIUS/AAA 报文、属性字典、认证器校验和 Accounting 工作流。
- 检索词：`radius`、`rfc2865`、`rfc2866`、`aaa`、`access-request`、`accounting-request`。
- MoonCakes：实时模块索引未发现直接实现 RADIUS 报文与 AAA 状态机的 MoonBit 包。
- 相关项目：`EJJ-ai-nb/canaryring` 的关键词包含 blast radius，但其功能是灰度发布与影响范围模拟，不是 RADIUS 协议。
- 相邻项目：StatsD/OpenMetrics 属于指标协议；LDAP、OAuth/JWT 属于目录或 Web 凭证；MQTT/AMQP/NATS 属于消息协议。它们与 RADIUS 的核心报文、属性和认证器不同。
- 上游参考：`layeh/radius`，MPL-2.0；RFC 2865、RFC 2866。
- 重合判断：未发现直接重合的成熟 MoonBit 项目。
- 决策：通过查重门，进入实现。
- 限制：公开索引不能证明不存在尚未发布或尚未被索引的实现；实现中继续保持 RADIUS/AAA 边界。
