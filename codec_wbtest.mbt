///|
test "round trip access request" {
  let packet = Packet::new(
    AccessRequest,
    7,
    Bytes::makei(16, fn(index) { (index + 1).to_byte() }),
  ).with_attribute(Attribute::new(1, b"alice"))
  let decoded = decode(encode(packet))
  assert_eq(decoded.header.code, AccessRequest)
  assert_eq(decoded.header.identifier.to_int(), 7)
  assert_eq(decoded.attributes.length(), 1)
  assert_eq(decoded.attributes[0].value, b"alice")
}

///|
fn expect_truncated_attribute() -> Unit {
  try {
    let _ = decode(
      b"\x01\x01\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    )
    abort("expected truncated attribute")
  } catch {
    AttributeTruncated(offset) => if offset != 20 { abort("unexpected offset") }
    _ => abort("unexpected error")
  }
}

///|
test "reject truncated attribute" {
  expect_truncated_attribute()
}
