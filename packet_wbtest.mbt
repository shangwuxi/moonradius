///|
test "packet attribute transformations preserve ordering" {
  let packet = Packet::request(AccessRequest, 4)
    .with_attribute(Attribute::text(User_Name, "alice"))
    .with_attribute(Attribute::text(Reply_Message, "old"))
    .with_attribute(Attribute::text(Reply_Message, "duplicate"))
  let filtered = packet.without_attribute(Reply_Message)
  assert_eq(filtered.attributes.length(), 1)
  let replaced = packet.replace_attribute(
    Reply_Message,
    Attribute::reply("new"),
  )
  assert_eq(replaced.attributes.length(), 2)
  assert_eq(replaced.attribute(Reply_Message).unwrap().value, b"new")
}

///|
test "packet copy can be edited independently" {
  let packet = example_accounting_start()
  let copied = packet.copy().with_attribute(Attribute::reply("audit"))
  assert_eq(packet.attributes.length() + 1, copied.attributes.length())
}
