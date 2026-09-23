///|
test "wire rules identify missing request attributes" {
  let request = Packet::request(AccessRequest, 1)
  let missing = missing_attributes(request)
  assert_eq(missing.length(), 1)
  assert_eq(missing[0], User_Name)
  assert_true(!packet_is_well_formed(request))
}

///|
test "wire rules accept complete accounting start" {
  let packet = example_accounting_start()
  assert_eq(missing_attributes(packet).length(), 0)
  assert_true(packet_is_well_formed(packet))
  assert_eq(packet_code_name(packet.header.code), "Accounting-Request")
}
