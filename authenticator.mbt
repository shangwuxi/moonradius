/// RFC 2865/2866 request and response authenticator calculations.

///|
fn packet_without_authenticator(
  packet : Packet,
  authenticator : Bytes,
) -> Bytes raise RadiusError {
  let body = encode_attributes(packet.attributes)
  let total = 20 + body.length()
  if total > 65535 {
    raise InvalidLength(total)
  }
  join_bytes(
    bytes_from_array([
      byte_at(packet.header.code.to_int()),
      packet.header.identifier,
      byte_at(total >> 8),
      byte_at(total),
    ]),
    join_bytes(authenticator, body),
  )
}

///|
/// Compute the response authenticator for Access-Accept/Reject/Challenge or
/// Accounting-Response packets.
pub fn response_authenticator(
  packet : Packet,
  request_authenticator : Bytes,
  secret : Bytes,
) -> Bytes raise RadiusError {
  if request_authenticator.length() != 16 {
    raise InvalidAuthenticator
  }
  md5_bytes(
    join_bytes(
      packet_without_authenticator(packet, request_authenticator),
      secret,
    ),
  )
}

///|
/// Attach a calculated response authenticator to a packet.
pub fn Packet::with_response_authenticator(
  self : Packet,
  request_authenticator : Bytes,
  secret : Bytes,
) -> Packet raise RadiusError {
  let authenticator = response_authenticator(
    self, request_authenticator, secret,
  )
  Packet::new(self.header.code, self.header.identifier, authenticator).with_attributes(
    self.attributes,
  )
}

///|
/// Add several attributes in one operation.
pub fn Packet::with_attributes(
  self : Packet,
  attributes : Array[Attribute],
) -> Packet {
  for attribute in attributes {
    self.attributes.push(attribute)
  }
  self
}

///|
/// Verify that a received response carries the expected authenticator.
pub fn verify_response_authenticator(
  packet : Packet,
  request_authenticator : Bytes,
  secret : Bytes,
) -> Bool raise RadiusError {
  if packet.header.code != AccessAccept &&
    packet.header.code != AccessReject &&
    packet.header.code != AccessChallenge &&
    packet.header.code != AccountingResponse {
    false
  } else {
    byte_eq(
      packet.header.authenticator,
      response_authenticator(packet, request_authenticator, secret),
    )
  }
}

///|
/// Validate the packet type expected by an Access response workflow.
pub fn validate_access_response(packet : Packet) -> Bool {
  packet.header.code == AccessAccept ||
  packet.header.code == AccessReject ||
  packet.header.code == AccessChallenge
}

///|
/// Validate the packet type expected by an Accounting response workflow.
pub fn validate_accounting_response(packet : Packet) -> Bool {
  packet.header.code == AccountingResponse
}
