/// Accounting helpers for RFC 2866 start, interim, and stop records.

///|
/// The lifecycle class of an Accounting-Request.
pub enum AccountingEvent {
  Start
  Interim
  Stop
  AdministrativeOn
  AdministrativeOff
  UnknownStatus(Int)
  MissingStatus
} derive(Eq, Debug)

///|
pub extend AccountingEvent with Eq::{not_equal, equal}

///|
pub extend AccountingEvent with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub fn accounting_status(packet : Packet) -> Int? {
  match packet.attribute(Acct_Status_Type) {
    Some(attribute) => attribute.as_integer()
    None => None
  }
}

///|
/// Classify the status attribute without making callers depend on numeric
/// RFC constants.
pub fn accounting_event(packet : Packet) -> AccountingEvent {
  match accounting_status(packet) {
    None => MissingStatus
    Some(Acct_Start) => Start
    Some(Acct_Interim_Update) => Interim
    Some(Acct_Stop) => Stop
    Some(Acct_On) => AdministrativeOn
    Some(Acct_Off) => AdministrativeOff
    Some(value) => UnknownStatus(value)
  }
}

///|
/// Return a stable session label for logs and accounting adapters.
pub fn accounting_session_label(packet : Packet) -> String {
  match accounting_session_id(packet) {
    Some(value) if value.length() > 0 => value
    _ => "<missing-session-id>"
  }
}

///|
pub fn is_accounting_start(packet : Packet) -> Bool {
  accounting_status(packet) == Some(Acct_Start)
}

///|
pub fn is_accounting_stop(packet : Packet) -> Bool {
  accounting_status(packet) == Some(Acct_Stop)
}

///|
pub fn is_accounting_interim(packet : Packet) -> Bool {
  accounting_status(packet) == Some(Acct_Interim_Update)
}

///|
pub fn accounting_session_id(packet : Packet) -> String? {
  match packet.attribute(Acct_Session_Id) {
    Some(attribute) => Some(@utf8.decode_lossy(attribute.value))
    None => None
  }
}

///|
pub fn accounting_counter(packet : Packet, kind : Byte) -> Int {
  match packet.attribute(kind) {
    Some(attribute) =>
      match attribute.as_integer() {
        Some(value) => value
        None => 0
      }
    None => 0
  }
}

///|
pub fn accounting_octets(packet : Packet) -> Int {
  accounting_counter(packet, Acct_Input_Octets) +
  accounting_counter(packet, Acct_Output_Octets)
}

///|
pub fn accounting_packets(packet : Packet) -> Int {
  accounting_counter(packet, Acct_Input_Packets) +
  accounting_counter(packet, Acct_Output_Packets)
}

///|
pub fn make_accounting_start(
  identifier : Byte,
  authenticator : Bytes,
  session_id : String,
) -> Packet {
  Packet::new(AccountingRequest, identifier, authenticator)
  .with_attribute(Attribute::session_status(Acct_Start))
  .with_attribute(Attribute::session_id(session_id))
}

///|
pub fn make_accounting_stop(
  identifier : Byte,
  authenticator : Bytes,
  session_id : String,
  input_octets : Int,
  output_octets : Int,
) -> Packet {
  make_accounting_start(identifier, authenticator, session_id)
  .replace_attribute(Acct_Status_Type, Attribute::session_status(Acct_Stop))
  .with_attribute(Attribute::integer(Acct_Input_Octets, input_octets))
  .with_attribute(Attribute::integer(Acct_Output_Octets, output_octets))
}
