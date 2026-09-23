# MoonRADIUS 架构

## 数据流

`Bytes -> decode -> Packet -> validate/diagnose -> policy -> response_authenticator -> encode -> Bytes`

`Packet` 保留属性数组的顺序和重复项，未知属性不被丢弃。这样协议代理和
测试工具可以在不理解全部字典的情况下完成转发与审计。

## 模块职责

- `radius.mbt`：Code、Header、Attribute、Packet、标准属性编号；
- `codec.mbt`：20 字节头和 TLV 的边界检查；
- `auth.mbt` / `authenticator.mbt`：PAP、CHAP 和 RFC 认证器；
- `attributes.mbt`：字典和 Vendor-Specific；
- `policy.mbt` / `accounting.mbt`：无数据库的决策和 Accounting 数据抽取；
- `transport.mbt` / `server.mbt`：传输接口、内存传输和请求分发；
- `diagnostics.mbt` / `wire_rules.mbt`：稳定诊断与请求形状规则；
- `replay.mbt`：有限容量的重传/冲突识别；
- `examples.mbt`：三个离线可执行工作流。

## 有意不实现

本项目不实现 socket、完整 FreeRADIUS 配置语言、EAP 方法、RadSec/TLS、
LDAP/Kerberos/OAuth 后端、用户数据库或日志/指标协议。它们属于应用或其他
专业库的边界。
