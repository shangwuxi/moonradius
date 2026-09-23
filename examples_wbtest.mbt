///|
test "wifi example is a valid access request" {
  let packet = example_wifi_request()
  assert_true(packet.is_access_request())
  assert_true(packet.attribute(User_Name) is Some(_))
  let wire = encode(packet)
  assert_eq(wire.length(), 97)
}

///|
test "vpn example verifies with a challenge policy" {
  let packet = example_vpn_challenge()
  let policy = AccessPolicy::new()
    .allow(Credential::new("vpn-user", b"vpn-password"))
    .with_chap(b"vpn-challenge-2026")
  let decision = decide_access(packet, policy, b"unused")
  assert_eq(decision, Accept)
}

///|
test "accounting start has a stable record" {
  let record = AccountingRecord::from_packet(example_accounting_start())
  assert_eq(record.session_id, Some("sess-20260923-0001"))
  assert_eq(record.status_type, Some(Acct_Start))
}

///|
test "memory transport carries packets without socket dependencies" {
  let transport = MemoryTransport::new()
  let packet = example_accounting_start()
  transport.send(packet)
  let wire = transport.take_sent()
  transport.inject(wire)
  let received = transport.receive()
  assert_eq(received.header.code, AccountingRequest)
  assert_eq(transport.pending(), 0)
}

///|
test "diagnostics are stable for malformed datagrams" {
  let diagnostics = diagnose(b"\x01\x01\x00\x10")
  assert_true(diagnostics.length() == 1)
  assert_true(diagnostics[0].message == "RADIUS header requires 20 bytes")
}
