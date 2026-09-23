/// RFC packet-shape rules kept separate from the binary codec.

///|
pub fn request_authenticator_is_present(packet : Packet) -> Bool {
  packet.header.authenticator.length() == 16
}

///|
pub fn request_has_identifier(packet : Packet) -> Bool {
  packet.header.identifier.to_int() >= 0
}

///|
pub fn packet_code_name(code : Code) -> String {
  match code {
    AccessRequest => "Access-Request"
    AccessAccept => "Access-Accept"
    AccessReject => "Access-Reject"
    AccountingRequest => "Accounting-Request"
    AccountingResponse => "Accounting-Response"
    AccessChallenge => "Access-Challenge"
    StatusServer => "Status-Server"
    StatusClient => "Status-Client"
    Unknown(value) => "Unknown(" + value.to_string() + ")"
  }
}

///|
pub fn required_attributes_for(code : Code) -> Array[Byte] {
  match code {
    AccessRequest => [User_Name]
    AccountingRequest => [Acct_Status_Type, Acct_Session_Id]
    _ => []
  }
}

///|
pub fn missing_attributes(packet : Packet) -> Array[Byte] {
  let missing = []
  for kind in required_attributes_for(packet.header.code) {
    if packet.attribute(kind) is None {
      missing.push(kind)
    }
  }
  missing
}

///|
pub fn packet_is_request(packet : Packet) -> Bool {
  packet.header.code == AccessRequest ||
  packet.header.code == AccountingRequest ||
  packet.header.code == StatusServer
}

///|
pub fn packet_is_response(packet : Packet) -> Bool {
  packet.header.code == AccessAccept ||
  packet.header.code == AccessReject ||
  packet.header.code == AccessChallenge ||
  packet.header.code == AccountingResponse ||
  packet.header.code == StatusClient
}

///|
pub fn validate_wire_rules(packet : Packet) -> Array[String] {
  let errors = []
  if !request_authenticator_is_present(packet) {
    errors.push("authenticator must contain 16 bytes")
  }
  if packet_is_request(packet) && missing_attributes(packet).length() > 0 {
    errors.push("required request attributes are missing")
  }
  for attribute in packet.attributes {
    match validate_attribute(attribute) {
      Some(message) => errors.push(message)
      None => ()
    }
  }
  errors
}

///|
pub fn packet_is_well_formed(packet : Packet) -> Bool {
  validate_wire_rules(packet).length() == 0
}
