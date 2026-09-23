///|
/// Common value constructors for RADIUS attributes.
pub struct IPv4 {
  first : Byte
  second : Byte
  third : Byte
  fourth : Byte
}

///|
pub fn IPv4::new(first : Int, second : Int, third : Int, fourth : Int) -> IPv4? {
  if first < 0 ||
    first > 255 ||
    second < 0 ||
    second > 255 ||
    third < 0 ||
    third > 255 ||
    fourth < 0 ||
    fourth > 255 {
    None
  } else {
    Some(IPv4::{
      first: first.to_byte(),
      second: second.to_byte(),
      third: third.to_byte(),
      fourth: fourth.to_byte(),
    })
  }
}

///|
pub fn IPv4::to_bytes(self : IPv4) -> Bytes {
  Bytes::makei(4, fn(index) {
    match index {
      0 => self.first
      1 => self.second
      2 => self.third
      _ => self.fourth
    }
  })
}

///|
pub fn IPv4::from_attribute(attribute : Attribute) -> IPv4? {
  if attribute.value.length() != 4 {
    None
  } else {
    Some(IPv4::{
      first: attribute.value[0],
      second: attribute.value[1],
      third: attribute.value[2],
      fourth: attribute.value[3],
    })
  }
}

///|
pub fn Attribute::ipv4(kind : Byte, address : IPv4) -> Attribute {
  Attribute::new(kind, address.to_bytes())
}

///|
pub enum FramedProtocolValue {
  PPP
  SLIP
  ARAP
  GPRS
  None
} derive(Eq, Debug)

///|
pub extend FramedProtocolValue with Eq::{not_equal, equal}

///|
pub extend FramedProtocolValue with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub fn FramedProtocolValue::to_int(self : FramedProtocolValue) -> Int {
  match self {
    PPP => 1
    SLIP => 2
    ARAP => 3
    GPRS => 7
    None => 5
  }
}

///|
pub fn Attribute::framed_protocol(value : FramedProtocolValue) -> Attribute {
  Attribute::integer(Framed_Protocol, value.to_int())
}

///|
pub fn framed_protocol_values() -> Array[FramedProtocolValue] {
  [PPP, SLIP, ARAP, GPRS, None]
}

///|
pub enum TerminationCause {
  UserRequest
  LostCarrier
  LostService
  IdleTimeout
  SessionTimeout
  AdminReset
  AdminReboot
  PortError
  NASRequest
  NASReboot
} derive(Eq, Debug)

///|
pub extend TerminationCause with Eq::{not_equal, equal}

///|
pub extend TerminationCause with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub fn TerminationCause::to_int(self : TerminationCause) -> Int {
  match self {
    UserRequest => 1
    LostCarrier => 2
    LostService => 3
    IdleTimeout => 4
    SessionTimeout => 5
    AdminReset => 6
    AdminReboot => 7
    PortError => 8
    NASRequest => 9
    NASReboot => 10
  }
}

///|
pub fn Attribute::termination_cause(cause : TerminationCause) -> Attribute {
  Attribute::integer(Acct_Terminate_Cause, cause.to_int())
}

///|
pub fn termination_causes() -> Array[TerminationCause] {
  [
    UserRequest,
    LostCarrier,
    LostService,
    IdleTimeout,
    SessionTimeout,
    AdminReset,
    AdminReboot,
    PortError,
    NASRequest,
    NASReboot,
  ]
}

///|
pub fn Attribute::session_status(value : Int) -> Attribute {
  Attribute::integer(Acct_Status_Type, value)
}

///|
pub fn Attribute::session_id(value : String) -> Attribute {
  Attribute::text(Acct_Session_Id, value)
}

///|
pub fn Attribute::reply(value : String) -> Attribute {
  Attribute::text(Reply_Message, value)
}

///|
pub fn Attribute::username(value : String) -> Attribute {
  Attribute::text(User_Name, value)
}

///|
pub fn Attribute::nas_identifier(value : String) -> Attribute {
  Attribute::text(NAS_Identifier, value)
}

///|
pub fn Attribute::nas_port(value : Int) -> Attribute {
  Attribute::integer(NAS_Port, value)
}
