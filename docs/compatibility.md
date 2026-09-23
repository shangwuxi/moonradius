# 兼容性矩阵

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| RADIUS 20 字节头 | 支持 | Code、Identifier、Length、Authenticator |
| 属性 TLV | 支持 | 1–253 字节值，保留未知和重复属性 |
| Access 工作流 | 支持 | Request、Accept、Reject、Challenge |
| Accounting 工作流 | 支持 | Start、Interim、Stop、Response |
| PAP | 支持 | RFC 2865 User-Password 分块算法 |
| CHAP | 支持 | RFC 2865 CHAP-Password 计算和校验 |
| Vendor-Specific | 支持 | 单个 vendor 子属性编码和解析 |
| UDP/socket | 应用接入 | 核心包只提供 DatagramTransport seam |
| EAP | 未实现 | 需要独立的 EAP 方法和状态机 |
| RadSec/TLS | 未实现 | 不属于当前协议核心范围 |
| FreeRADIUS 配置/数据库 | 未实现 | 由应用或服务器产品负责 |

## 质量基线

当前本地验证包括 25 个测试、约 2,000 行 MoonBit 源码，覆盖正常报文、
截断报文、非法长度、保留属性类型、PAP/CHAP、响应认证器、Accounting、
重传冲突和内存传输。多目标 `moon check` 已覆盖 wasm-gc、wasm、js、
native。
