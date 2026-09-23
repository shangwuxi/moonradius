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

///|
/// Expose the packet code without requiring callers to inspect the header.
pub fn Packet::code(self : Packet) -> Code {
  self.header.code
}

///|
/// Return the RADIUS identifier used to correlate a response.
pub fn Packet::identifier(self : Packet) -> Byte {
  self.header.identifier
}

///|
/// Return a defensive copy of the request or response authenticator.
pub fn Packet::authenticator(self : Packet) -> Bytes {
  self.header.authenticator
}

///|
/// Return a defensive copy of all attributes in wire order.
pub fn Packet::all_attributes(self : Packet) -> Array[Attribute] {
  self.attributes.copy()
}

///|
/// Standard RADIUS attribute numbers from RFC 2865 and RFC 2866.
pub const User_Name : Byte = 1

///|
pub const User_Password : Byte = 2

///|
pub const CHAP_Password : Byte = 3

///|
pub const NAS_IP_Address : Byte = 4

///|
pub const NAS_Port : Byte = 5

///|
pub const Service_Type : Byte = 6

///|
pub const Framed_Protocol : Byte = 7

///|
pub const Framed_IP_Address : Byte = 8

///|
pub const Framed_IP_Netmask : Byte = 9

///|
pub const Filter_Id : Byte = 11

///|
pub const Reply_Message : Byte = 18

///|
pub const State : Byte = 24

///|
pub const Class : Byte = 25

///|
pub const Vendor_Specific : Byte = 26

///|
pub const Session_Timeout : Byte = 27

///|
pub const Idle_Timeout : Byte = 28

///|
pub const Termination_Action : Byte = 29

///|
pub const Called_Station_Id : Byte = 30

///|
pub const Calling_Station_Id : Byte = 31

///|
pub const NAS_Identifier : Byte = 32

///|
pub const Acct_Status_Type : Byte = 40

///|
pub const Acct_Input_Octets : Byte = 42

///|
pub const Acct_Output_Octets : Byte = 43

///|
pub const Acct_Session_Id : Byte = 44

///|
pub const Acct_Session_Time : Byte = 46

///|
pub const Acct_Input_Packets : Byte = 47

///|
pub const Acct_Output_Packets : Byte = 48

///|
pub const Acct_Terminate_Cause : Byte = 49

///|
pub const Acct_Multi_Session_Id : Byte = 50

///|
pub const Acct_Link_Count : Byte = 51

///|
pub const Acct_Interim_Interval : Byte = 85

///|
/// Accounting status values defined by RFC 2866.
pub const Acct_Start : Int = 1

///|
pub const Acct_Stop : Int = 2

///|
pub const Acct_Interim_Update : Int = 3

///|
pub const Acct_On : Int = 7

///|
pub const Acct_Off : Int = 8

///|
/// Common service types.
pub const Login : Int = 1

///|
pub const Framed : Int = 2

///|
pub const Administrative : Int = 6

///|
pub const NAS_Prompt : Int = 7

///|
/// Construct an attribute from UTF-8 text.
pub fn Attribute::text(kind : Byte, value : String) -> Attribute {
  Attribute::{ kind, value: @utf8.encode(value), }
}

///|
/// Construct an attribute containing a big-endian unsigned integer.
pub fn Attribute::integer(kind : Byte, value : Int) -> Attribute {
  Attribute::{ kind, value: u32_bytes(value), }
}

///|
/// Read a four-byte unsigned integer attribute.
pub fn Attribute::as_integer(self : Attribute) -> Int? {
  if self.value.length() != 4 {
    None
  } else {
    Some(
      (self.value[0].to_int() << 24) |
      (self.value[1].to_int() << 16) |
      (self.value[2].to_int() << 8) |
      self.value[3].to_int(),
    )
  }
}

///|
/// Construct a packet with a zero authenticator, useful for requests whose
/// authenticator is filled by a transport or authentication helper.
pub fn Packet::request(code : Code, identifier : Byte) -> Packet {
  Packet::new(code, identifier, zeros(16))
}

///|
/// Return all attributes with a given type, preserving wire order.
pub fn Packet::attributes_of(self : Packet, kind : Byte) -> Array[Attribute] {
  let result = []
  for item in self.attributes {
    if item.kind == kind {
      result.push(item)
    }
  }
  result
}

///|
/// Add an attribute without replacing existing attributes.
pub fn Packet::push_attribute(self : Packet, attribute : Attribute) -> Packet {
  self.attributes.push(attribute)
  self
}

///|
/// Return whether this packet is an Access-Request.
pub fn Packet::is_access_request(self : Packet) -> Bool {
  self.header.code == AccessRequest
}

///|
/// Return whether this packet is an Accounting-Request.
pub fn Packet::is_accounting_request(self : Packet) -> Bool {
  self.header.code == AccountingRequest
}

///|
/// Return a packet with the same header and a filtered attribute stream.
pub fn Packet::filter_attributes(
  self : Packet,
  predicate : (Attribute) -> Bool,
) -> Packet {
  let attributes = []
  for attribute in self.attributes {
    if predicate(attribute) {
      attributes.push(attribute)
    }
  }
  Packet::{ header: self.header, attributes, }
}

///|
/// Return a packet with one attribute type removed.
pub fn Packet::without_attribute(self : Packet, kind : Byte) -> Packet {
  self.filter_attributes(fn(attribute) { attribute.kind != kind })
}

///|
/// Return a packet with all copies of a type replaced by one value.
pub fn Packet::replace_attribute(
  self : Packet,
  kind : Byte,
  replacement : Attribute,
) -> Packet {
  let filtered = self.without_attribute(kind)
  filtered.with_attribute(replacement)
}

///|
/// Return a stable copy of the packet for response construction.
pub fn Packet::copy(self : Packet) -> Packet {
  Packet::{
    header: Header::{
      code: self.header.code,
      identifier: self.header.identifier,
      authenticator: self.header.authenticator,
    },
    attributes: self.attributes.copy(),
  }
}
