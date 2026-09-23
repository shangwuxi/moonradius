///|
/// Transport-neutral packet exchange primitives.
pub suberror TransportError {
  Closed
  Empty
  Packet(RadiusError)
}

///|
/// A deterministic in-memory transport used by examples and tests.
pub struct MemoryTransport {
  incoming : Array[Bytes]
  outgoing : Array[Bytes]
  mut closed : Bool
}

///|
pub fn MemoryTransport::new() -> MemoryTransport {
  MemoryTransport::{ incoming: [], outgoing: [], closed: false, }
}

///|
pub fn MemoryTransport::close(self : MemoryTransport) -> Unit {
  self.closed = true
}

///|
pub fn MemoryTransport::inject(self : MemoryTransport, packet : Bytes) -> Unit {
  self.incoming.push(packet)
}

///|
/// Encode and queue a packet for the peer.
pub fn MemoryTransport::send(
  self : MemoryTransport,
  packet : Packet,
) -> Unit raise TransportError {
  if self.closed {
    raise Closed
  }
  self.outgoing.push(encode(packet)) catch {
    error => raise Packet(error)
  }
}

///|
/// Receive and decode one injected packet.
pub fn MemoryTransport::receive(
  self : MemoryTransport,
) -> Packet raise TransportError {
  if self.closed {
    raise Closed
  }
  if self.incoming.length() == 0 {
    raise Empty
  }
  let bytes = self.incoming.remove(0)
  decode(bytes) catch {
    error => raise Packet(error)
  }
}

///|
/// Take the next encoded packet sent by this endpoint.
pub fn MemoryTransport::take_sent(
  self : MemoryTransport,
) -> Bytes raise TransportError {
  if self.outgoing.length() == 0 {
    raise Empty
  }
  self.outgoing.remove(0)
}

///|
/// Number of packets waiting on either side.
pub fn MemoryTransport::pending(self : MemoryTransport) -> Int {
  self.incoming.length() + self.outgoing.length()
}

///|
/// An integration boundary for UDP or another datagram implementation.
pub(open) trait DatagramTransport {
  fn send(Self, Packet) -> Unit raise TransportError
  fn receive(Self) -> Packet raise TransportError
}

///|
pub impl DatagramTransport for MemoryTransport with fn send(self, packet) {
  MemoryTransport::send(self, packet)
}

///|
pub impl DatagramTransport for MemoryTransport with fn receive(self) {
  MemoryTransport::receive(self)
}
