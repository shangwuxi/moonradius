///|
test "codec rejects reserved attribute type zero" {
  let packet = Packet::request(AccessRequest, 1).with_attribute(
    Attribute::new(b'\x00', b"x"),
  )
  try {
    let _ = encode(packet)
    abort("expected reserved type error")
  } catch {
    InvalidAttribute(_) => ()
    _ => abort("unexpected error")
  }
}

///|
test "diagnostics reports invalid attribute lengths with offsets" {
  let bytes = b"\x01\x01\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
  let diagnostics = diagnose(bytes)
  assert_true(diagnostics.length() == 1)
  assert_true(diagnostics[0].offset == 20)
}
