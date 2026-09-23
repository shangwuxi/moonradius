///|
fn read_u16(bytes : Bytes, offset : Int) -> Int raise RadiusError {
  if offset < 0 || offset + 1 >= bytes.length() {
    raise TooShort
  }
  (bytes[offset].to_int() << 8) | bytes[offset + 1].to_int()
}

///|
fn byte_at(value : Int) -> Byte {
  (value & 255).to_byte()
}

///|
fn join_bytes(left : Bytes, right : Bytes) -> Bytes {
  Bytes::makei(left.length() + right.length(), fn(index) {
    if index < left.length() {
      left[index]
    } else {
      right[index - left.length()]
    }
  })
}

///|
fn bytes_from_array(values : Array[Byte]) -> Bytes {
  Bytes::makei(values.length(), fn(index) { values[index] })
}

///|
pub fn encode(packet : Packet) -> Bytes raise RadiusError {
  if packet.header.authenticator.length() != 16 {
    raise InvalidAuthenticator
  }
  let mut body = b""
  for attribute in packet.attributes {
    if attribute.value.length() > 253 {
      raise InvalidAttribute("attribute value exceeds 253 bytes")
    }
    let length = attribute.value.length() + 2
    let prefix = bytes_from_array([attribute.kind, byte_at(length)])
    body = join_bytes(body, join_bytes(prefix, attribute.value))
  }
  let total = 20 + body.length()
  if total > 65535 {
    raise InvalidLength(total)
  }
  let mut header = bytes_from_array([
    byte_at(packet.header.code.to_int()),
    packet.header.identifier,
    byte_at(total >> 8),
    byte_at(total),
  ])
  header = join_bytes(header, packet.header.authenticator)
  join_bytes(header, body)
}

///|
pub fn decode(bytes : Bytes) -> Packet raise RadiusError {
  if bytes.length() < 20 {
    raise TooShort
  }
  let code_value = bytes[0].to_int()
  let code = Code::from_int(code_value)
  if code is Unknown(_) {
    raise InvalidCode(code_value)
  }
  let declared = read_u16(bytes, 2)
  if declared < 20 || declared != bytes.length() {
    raise InvalidLength(declared)
  }
  let header = Header::{
    code,
    identifier: bytes[1],
    authenticator: Bytes::makei(16, fn(index) { bytes[4 + index] }),
  }
  let attributes : Array[Attribute] = []
  let mut offset = 20
  while offset < bytes.length() {
    if offset + 1 >= bytes.length() {
      raise AttributeTruncated(offset)
    }
    let kind = bytes[offset]
    let length = bytes[offset + 1].to_int()
    if length < 2 {
      raise AttributeTooShort(offset)
    }
    if offset + length > bytes.length() {
      raise AttributeTruncated(offset)
    }
    let value = Bytes::makei(length - 2, fn(index) { bytes[offset + 2 + index] })
    attributes.push(Attribute::{ kind, value, })
    offset = offset + length
  }
  Packet::{ header, attributes, }
}
