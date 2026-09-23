///|
/// Small policy layer for examples and integration tests.
///
/// MoonRADIUS deliberately does not contain a user database.  This module
/// supplies deterministic in-memory decisions so an application can wire its
/// own store into the packet and authenticator APIs.
pub enum AccessDecision {
  Accept
  Reject(String)
  Challenge(String)
} derive(Eq, Debug)

///|
pub struct Credential {
  username : String
  password : Bytes
}

///|
pub fn Credential::new(username : String, password : Bytes) -> Credential {
  Credential::{ username, password, }
}

///|
pub struct AccessPolicy {
  credentials : Array[Credential]
  require_chap : Bool
  challenge : Bytes
  reply_message : String?
}

///|
pub fn AccessPolicy::new() -> AccessPolicy {
  AccessPolicy::{
    credentials: [],
    require_chap: false,
    challenge: b"",
    reply_message: None,
  }
}

///|
pub fn AccessPolicy::allow(
  self : AccessPolicy,
  credential : Credential,
) -> AccessPolicy {
  self.credentials.push(credential)
  self
}

///|
pub fn AccessPolicy::with_chap(
  self : AccessPolicy,
  challenge : Bytes,
) -> AccessPolicy {
  AccessPolicy::{
    credentials: self.credentials,
    require_chap: true,
    challenge,
    reply_message: self.reply_message,
  }
}

///|
pub fn AccessPolicy::with_reply(
  self : AccessPolicy,
  message : String,
) -> AccessPolicy {
  AccessPolicy::{
    credentials: self.credentials,
    require_chap: self.require_chap,
    challenge: self.challenge,
    reply_message: Some(message),
  }
}

///|
fn text_attribute(packet : Packet, kind : Byte) -> String? {
  match packet.attribute(kind) {
    Some(attribute) => Some(@utf8.decode_lossy(attribute.value))
    None => None
  }
}

///|
fn credential_for(policy : AccessPolicy, username : String) -> Credential? {
  for credential in policy.credentials {
    if credential.username == username {
      return Some(credential)
    }
  }
  None
}

///|
/// Decide an Access-Request using PAP or CHAP, without performing I/O.
pub fn decide_access(
  packet : Packet,
  policy : AccessPolicy,
  secret : Bytes,
) -> AccessDecision raise RadiusError {
  if !packet.is_access_request() {
    return Reject("packet is not an Access-Request")
  }
  let username = match text_attribute(packet, User_Name) {
    Some(value) => value
    None => return Reject("missing User-Name")
  }
  let credential = match credential_for(policy, username) {
    Some(value) => value
    None => return Reject("unknown user")
  }
  if policy.require_chap {
    match packet.attribute(CHAP_Password) {
      Some(attribute) =>
        if verify_chap(attribute, credential.password, policy.challenge) {
          Accept
        } else {
          Reject("CHAP response did not verify")
        }
      None => Challenge("CHAP-Password is required")
    }
  } else {
    match packet.user_password(secret) {
      Some(password) =>
        if constant_time_equal(password, credential.password) ||
          trim_zero_padding(password) == credential.password {
          Accept
        } else {
          Reject("PAP password did not verify")
        }
      None => Reject("missing User-Password")
    }
  }
}

///|
/// Remove RFC 2865 block padding from a decrypted password.
pub fn trim_zero_padding(value : Bytes) -> Bytes {
  let mut end = value.length()
  while end > 0 && value[end - 1] == b'\x00' {
    end = end - 1
  }
  Bytes::makei(end, fn(index) { value[index] })
}

///|
/// Build the response corresponding to an Access decision.
pub fn access_response(
  request : Packet,
  decision : AccessDecision,
  secret : Bytes,
) -> Packet raise RadiusError {
  let base = match decision {
    Accept => Packet::new(AccessAccept, request.header.identifier, zeros(16))
    Reject(reason) =>
      Packet::new(AccessReject, request.header.identifier, zeros(16)).with_attribute(
        Attribute::text(Reply_Message, reason),
      )
    Challenge(message) =>
      Packet::new(AccessChallenge, request.header.identifier, zeros(16)).with_attribute(
        Attribute::text(Reply_Message, message),
      )
  }
  base.with_response_authenticator(request.header.authenticator, secret)
}

///|
/// Accounting data extracted from an Accounting-Request.
pub struct AccountingRecord {
  session_id : String?
  status_type : Int?
  input_octets : Int?
  output_octets : Int?
  input_packets : Int?
  output_packets : Int?
}

///|
pub fn AccountingRecord::from_packet(packet : Packet) -> AccountingRecord {
  AccountingRecord::{
    session_id: text_attribute(packet, Acct_Session_Id),
    status_type: integer_attribute(packet, Acct_Status_Type),
    input_octets: integer_attribute(packet, Acct_Input_Octets),
    output_octets: integer_attribute(packet, Acct_Output_Octets),
    input_packets: integer_attribute(packet, Acct_Input_Packets),
    output_packets: integer_attribute(packet, Acct_Output_Packets),
  }
}

///|
fn integer_attribute(packet : Packet, kind : Byte) -> Int? {
  match packet.attribute(kind) {
    Some(attribute) => attribute.as_integer()
    None => None
  }
}

///|
/// Validate the minimum shape of an Accounting-Request.
pub fn validate_accounting_request(packet : Packet) -> Array[String] {
  let errors = []
  if !packet.is_accounting_request() {
    errors.push("packet is not an Accounting-Request")
  }
  if packet.attribute(Acct_Status_Type) is None {
    errors.push("missing Acct-Status-Type")
  }
  if packet.attribute(Acct_Session_Id) is None {
    errors.push("missing Acct-Session-Id")
  }
  errors
}

///|
/// Create an Accounting-Response with the correct authenticator.
pub fn accounting_response(
  request : Packet,
  secret : Bytes,
) -> Packet raise RadiusError {
  if validate_accounting_request(request).length() > 0 {
    raise InvalidAttribute("accounting request is missing required attributes")
  }
  Packet::new(AccountingResponse, request.header.identifier, zeros(16)).with_response_authenticator(
    request.header.authenticator,
    secret,
  )
}
