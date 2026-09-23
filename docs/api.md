# API 速览

## 报文

- `Packet::request(code, identifier)`：创建零认证器请求；
- `with_attribute` / `with_attributes`：追加属性，不覆盖重复项；
- `attribute` / `attributes_of`：查询第一项或全部同类型项；
- `encode` / `decode`：执行有界 wire 编解码；
- `diagnose`：在不抛异常的情况下获得偏移诊断。

## 认证

- `encrypt_user_password` / `decrypt_user_password`；
- `make_chap_password` / `verify_chap`；
- `response_authenticator` / `verify_response_authenticator`。

## 业务边界

- `AccessPolicy` 只提供可审计的内存策略示例，生产应用应注入自己的凭据
  存储；
- `RadiusServer` 只分发已解码报文并签名响应，不绑定 socket；
- `MemoryTransport` 用于离线测试，UDP 适配器可以实现 `DatagramTransport`。
