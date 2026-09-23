///|
test "packet accessors expose correlation fields and preserve ownership" {
  let packet = Packet::request(AccessRequest, 9).with_attribute(
    Attribute::text(User_Name, "alice"),
  )
  assert_eq(packet.code(), AccessRequest)
  assert_eq(packet.identifier(), 9)
  assert_eq(packet.authenticator().length(), 16)
  let attributes = packet.all_attributes()
  assert_eq(attributes.length(), 1)
  attributes.push(Attribute::text(Reply_Message, "local copy"))
  assert_eq(packet.attributes_of(Reply_Message).length(), 0)
}
