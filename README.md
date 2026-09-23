# MoonRADIUS

MoonRADIUS 是一个面向 MoonBit 的 RADIUS/AAA 协议基础库。它把报文边界、
属性 TLV、PAP/CHAP、响应认证器、Accounting 生命周期和可替换传输边界放在
一个可测试的纯 MoonBit 包中，适合 NAS、企业 Wi-Fi、VPN 网关、协议测试器
和离线报文工具使用。

它不是 FreeRADIUS 的替代品：库不管理用户数据库，不实现 EAP 方法、RadSec/TLS
或 LDAP/Kerberos/OAuth 身份后端。应用负责 UDP/socket，MoonRADIUS 负责协议
数据和确定性的校验结果。

## 已实现能力

- RFC 2865/2866 报文头和属性 TLV 的有界编码、解码；
- Access-Request/Accept/Reject/Challenge 与 Accounting-Request/Response；
- User-Password 分块加密/解密、CHAP 响应计算、响应认证器；
- 标准属性常量、整数/文本/IPv4 构造器、Vendor-Specific 属性；
- 字典查询、重复属性保留、未知属性保留、稳定结构诊断；
- PAP/CHAP 访问策略、Accounting 记录抽取、内存 DatagramTransport；
- 重传/冲突分类和 identifier/request-authenticator 关联；
- 23 个白盒/黑盒测试，包含正例、截断、非法长度、认证和完整工作流。

## 三个可运行示例

### 1. 企业 Wi-Fi PAP

`example_wifi_request()` 构造带 User-Name、加密 User-Password、NAS-Identifier
和 NAS-Port 的 Access-Request；`example_wifi_accept()` 使用内存策略校验后生成
带响应认证器的 Access-Accept。

### 2. VPN CHAP Challenge

`example_vpn_challenge()` 生成带 CHAP-Password 和 State 的请求。应用可以把
`AccessDecision::Challenge` 作为下一阶段挑战响应，而无需把 VPN 业务逻辑塞入
协议编码器。

### 3. NAS Accounting Start/Stop

`example_accounting_start()` 生成 Accounting-Start；`make_accounting_stop()`
附加输入/输出字节并生成 Stop。`accounting_response()` 校验必需属性后签名
Accounting-Response。

## 最小用法

```moonbit
let request = Packet::request(AccessRequest, 1)
  .with_attribute(Attribute::username("alice"))
  .with_attribute(Attribute::reply("hello"))
let wire = encode(request)
let parsed = decode(wire)
let diagnostics = diagnose(wire)
```

## 验证

```bash
moon fmt --check
moon check --deny-warn
moon test
```

## 协议边界与参考

项目以 RFC 2865、RFC 2866 为协议依据，参考 Go 项目
[`layeh/radius`](https://github.com/layeh/radius) 的公开行为和 API 组织方式，
但 MoonBit 实现为独立重写，不复制上游源码。上游为 MPL-2.0；本仓库代码为
Apache-2.0。MD5 依赖来自 `gmlewis/md5`，仅用于 RADIUS 历史协议规定的
认证器/PAP/CHAP 互操作，不应被当作新系统密码哈希算法。

## 安全说明

共享密钥、明文密码和解密后的 User-Password 由调用方管理；库不会持久化它们。
RADIUS PAP/MD5 是协议兼容机制，不是现代密码存储方案。生产部署必须使用
网络隔离、密钥轮换、重放保护和上层传输安全策略。
