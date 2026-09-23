///|
test "strict diagnostics identifies trailing bytes at declared offset" {
  let bytes = b"\x01\x01\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\xAA"
  let diagnostics = diagnose_strict(bytes)
  assert_true(diagnostics.length() >= 2)
  assert_eq(diagnostics[diagnostics.length() - 1].offset, 22)
}

///|
test "diagnostics keeps valid attribute stream clean" {
  let packet = Packet::request(AccessRequest, 3).with_attribute(
    Attribute::text(User_Name, "alice"),
  )
  let diagnostics = diagnose(encode(packet))
  assert_true(diagnostics_are_clean(diagnostics))
}
