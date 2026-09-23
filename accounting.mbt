/// Accounting helpers for RFC 2866 start, interim, and stop records.

///|
pub fn accounting_status(packet : Packet) -> Int? {
  match packet.attribute(Acct_Status_Type) {
    Some(attribute) => attribute.as_integer()
    None => None
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
