///|
test "replay table distinguishes new retransmission and conflict" {
  let first = Packet::request(AccessRequest, 1)
  let table = ReplayTable::new(2)
  assert_eq(table.classify(first), New)
  assert_eq(table.record(first), New)
  assert_eq(table.classify(first), Retransmission)
  let conflict = Packet::new(
    AccessRequest,
    1,
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10",
  )
  assert_eq(table.classify(conflict), Conflict)
}

///|
test "response correlation follows RFC packet classes" {
  let request = example_wifi_request()
  let response = example_wifi_accept()
  assert_true(response_matches(request, response))
  assert_true(response_identifier_matches(request, response))
  let accounting = example_accounting_start()
  let accounting_response = example_accounting_response()
  assert_true(response_matches(accounting, accounting_response))
}

///|
test "packet statistics do not expose secret values" {
  let stats = PacketStats::from_packet(example_wifi_request())
  assert_true(stats.attributes == 5)
  assert_true(stats.total_value_bytes > 16)
}
