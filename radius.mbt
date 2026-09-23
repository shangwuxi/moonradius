///|
pub enum Code {
  AccessRequest
  AccessAccept
  AccessReject
  AccountingRequest
  AccountingResponse
  AccessChallenge
  StatusServer
  StatusClient
  Unknown(Int)
} derive(Eq, Debug)

///|
pub fn Code::from_int(value : Int) -> Code {
  match value {
    1 => AccessRequest
    2 => AccessAccept
    3 => AccessReject
    4 => AccountingRequest
    5 => AccountingResponse
    11 => AccessChallenge
    12 => StatusServer
    13 => StatusClient
    n => Unknown(n)
  }
}

///|
pub fn Code::to_int(self : Code) -> Int {
  match self {
    AccessRequest => 1
    AccessAccept => 2
    AccessReject => 3
    AccountingRequest => 4
    AccountingResponse => 5
    AccessChallenge => 11
    StatusServer => 12
    StatusClient => 13
    Unknown(value) => value
  }
}

///|
pub(all) suberror RadiusError {
  TooShort
  InvalidCode(Int)
  InvalidLength(Int)
  AttributeTruncated(Int)
  AttributeTooShort(Int)
  InvalidAuthenticator
  Unsupported(String)
  InvalidAttribute(String)
}

///|
pub struct Header {
  code : Code
  identifier : Byte
  authenticator : Bytes
}

///|
pub struct Attribute {
  kind : Byte
  value : Bytes
}

///|
pub struct Packet {
  header : Header
  attributes : Array[Attribute]
}

///|
pub fn Header::new(
  code : Code,
  identifier : Byte,
  authenticator : Bytes,
) -> Header {
  Header::{ code, identifier, authenticator, }
}

///|
pub fn Attribute::new(kind : Byte, value : Bytes) -> Attribute {
  Attribute::{ kind, value, }
}

///|
pub fn Packet::new(
  code : Code,
  identifier : Byte,
  authenticator : Bytes,
) -> Packet {
  { header: Header::new(code, identifier, authenticator), attributes: [], }
}

///|
pub fn Packet::with_attribute(self : Packet, attribute : Attribute) -> Packet {
  self.attributes.push(attribute)
  self
}

///|
pub fn Packet::attribute(self : Packet, kind : Byte) -> Attribute? {
  for item in self.attributes {
    if item.kind == kind {
      return Some(item)
    }
  }
  None
}
