///|
test "server accepts a valid PAP request and signs response" {
  let request = example_wifi_request()
  let policy = AccessPolicy::new().allow(
    Credential::new("alice@example.com", b"correct horse battery staple"),
  )
  let server = RadiusServer::new(
    ServerConfig::new(b"wifi-shared-secret", policy),
  )
  let result = server.handle(request)
  match result {
    Response(response) => {
      assert_eq(response.header.code, AccessAccept)
      assert_true(
        verify_response_authenticator(
          response,
          request.header.authenticator,
          b"wifi-shared-secret",
        ),
      )
    }
    Drop(_) => abort("expected Access-Accept")
  }
}

///|
test "server returns accounting response and updates counters" {
  let server = RadiusServer::new(
    ServerConfig::new(b"accounting-secret", AccessPolicy::new()),
  )
  let result = server.handle(example_accounting_start())
  match result {
    Response(response) => assert_eq(response.header.code, AccountingResponse)
    Drop(_) => abort("expected Accounting-Response")
  }
  assert_eq(server.handled_count(), 1)
  assert_eq(server.accounting_count(), 1)
}

///|
test "typed IPv4 and attribute builders preserve values" {
  let address = IPv4::new(192, 0, 2, 15)
  match address {
    Some(value) => {
      let attribute = Attribute::ipv4(NAS_IP_Address, value)
      assert_eq(attribute.value, b"\xC0\x00\x02\x0F")
      assert_true(IPv4::from_attribute(attribute) is Some(_))
    }
    None => abort("valid IPv4 rejected")
  }
}

///|
test "server drops malformed decoded packets before policy evaluation" {
  let packet = Packet::new(AccessRequest, 8, b"\x00")
  let server = RadiusServer::new(
    ServerConfig::new(b"secret", AccessPolicy::new()),
  )
  match server.handle(packet) {
    Response(_) => abort("malformed packet must not reach policy")
    Drop(messages) => {
      assert_true(messages.length() == 1)
      assert_eq(server.rejected_count(), 1)
    }
  }
}
