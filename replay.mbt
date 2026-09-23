///|
/// Request bookkeeping helpers for datagram servers.
///
/// RADIUS uses an identifier plus request authenticator to correlate
/// retransmissions.  This module does not decide policy; it gives an
/// application a bounded, deterministic way to classify repeated requests.
pub enum RequestDisposition {
  New
  Retransmission
  Conflict
} derive(Eq, Debug)

///|
pub extend RequestDisposition with Eq::{not_equal, equal}

///|
pub extend RequestDisposition with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub struct RequestKey {
  identifier : Byte
  authenticator : Bytes
}

///|
pub fn RequestKey::from_packet(packet : Packet) -> RequestKey {
  RequestKey::{
    identifier: packet.header.identifier,
    authenticator: packet.header.authenticator,
  }
}

///|
pub fn RequestKey::same(self : RequestKey, other : RequestKey) -> Bool {
  self.identifier == other.identifier &&
  byte_eq(self.authenticator, other.authenticator)
}

///|
/// A bounded replay table suitable for one shared-secret endpoint.
pub struct ReplayTable {
  entries : Array[RequestKey]
  capacity : Int
}

///|
pub fn ReplayTable::new(capacity : Int) -> ReplayTable {
  ReplayTable::{
    entries: [],
    capacity: if capacity < 1 {
      1
    } else {
      capacity
    },
  }
}

///|
pub fn ReplayTable::size(self : ReplayTable) -> Int {
  self.entries.length()
}

///|
pub fn ReplayTable::classify(
  self : ReplayTable,
  packet : Packet,
) -> RequestDisposition {
  let key = RequestKey::from_packet(packet)
  for entry in self.entries {
    if entry.identifier == key.identifier {
      if entry.same(key) {
        return Retransmission
      } else {
        return Conflict
      }
    }
  }
  New
}

///|
/// Record a new request, evicting the oldest key at capacity.
pub fn ReplayTable::record(
  self : ReplayTable,
  packet : Packet,
) -> RequestDisposition {
  let disposition = self.classify(packet)
  match disposition {
    New => {
      if self.entries.length() >= self.capacity {
        let _ = self.entries.remove(0)
      }
      self.entries.push(RequestKey::from_packet(packet))
    }
    Retransmission => ()
    Conflict => ()
  }
  disposition
}

///|
/// Decide whether a packet is a legal response to a request code.
pub fn response_matches(request : Packet, response : Packet) -> Bool {
  match request.header.code {
    AccessRequest =>
      response.header.code == AccessAccept ||
      response.header.code == AccessReject ||
      response.header.code == AccessChallenge
    AccountingRequest => response.header.code == AccountingResponse
    _ => false
  }
}

///|
/// Ensure identifier correlation is preserved across a response.
pub fn response_identifier_matches(request : Packet, response : Packet) -> Bool {
  request.header.identifier == response.header.identifier
}

///|
/// Return a compact packet summary for diagnostics and logs.
pub fn packet_summary(packet : Packet) -> String {
  let code = match packet.header.code {
    AccessRequest => "Access-Request"
    AccessAccept => "Access-Accept"
    AccessReject => "Access-Reject"
    AccountingRequest => "Accounting-Request"
    AccountingResponse => "Accounting-Response"
    AccessChallenge => "Access-Challenge"
    StatusServer => "Status-Server"
    StatusClient => "Status-Client"
    Unknown(_) => "Unknown"
  }
  code +
  " id=" +
  packet.header.identifier.to_int().to_string() +
  " attrs=" +
  packet.attributes.length().to_string()
}

///|
/// Collect basic counters without inspecting sensitive attribute values.
pub struct PacketStats {
  attributes : Int
  vendor_attributes : Int
  total_value_bytes : Int
}

///|
pub fn PacketStats::from_packet(packet : Packet) -> PacketStats {
  let mut vendors = 0
  let mut values = 0
  for attribute in packet.attributes {
    if attribute.kind == Vendor_Specific {
      vendors = vendors + 1
    }
    values = values + attribute.value.length()
  }
  PacketStats::{
    attributes: packet.attributes.length(),
    vendor_attributes: vendors,
    total_value_bytes: values,
  }
}
