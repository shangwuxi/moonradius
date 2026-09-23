///|
/// A transport-independent RADIUS request dispatcher.
///
/// This is intentionally a small protocol server core: it owns packet
/// validation, policy dispatch, and response signing, while the application
/// owns sockets, users, persistence, and logging.
pub enum ServerResult {
  Response(Packet)
  Drop(Array[String])
}

///|
pub struct ServerConfig {
  secret : Bytes
  access_policy : AccessPolicy
  accounting_enabled : Bool
  reject_malformed : Bool
}

///|
pub fn ServerConfig::new(secret : Bytes, policy : AccessPolicy) -> ServerConfig {
  ServerConfig::{
    secret,
    access_policy: policy,
    accounting_enabled: true,
    reject_malformed: true,
  }
}

///|
pub fn ServerConfig::without_accounting(self : ServerConfig) -> ServerConfig {
  ServerConfig::{
    secret: self.secret,
    access_policy: self.access_policy,
    accounting_enabled: false,
    reject_malformed: self.reject_malformed,
  }
}

///|
pub fn ServerConfig::allow_malformed(self : ServerConfig) -> ServerConfig {
  ServerConfig::{
    secret: self.secret,
    access_policy: self.access_policy,
    accounting_enabled: self.accounting_enabled,
    reject_malformed: false,
  }
}

///|
pub struct RadiusServer {
  config : ServerConfig
  mut handled : Int
  mut rejected : Int
  mut accounting : Int
}

///|
pub fn RadiusServer::new(config : ServerConfig) -> RadiusServer {
  RadiusServer::{ config, handled: 0, rejected: 0, accounting: 0, }
}

///|
pub fn RadiusServer::handled_count(self : RadiusServer) -> Int {
  self.handled
}

///|
pub fn RadiusServer::rejected_count(self : RadiusServer) -> Int {
  self.rejected
}

///|
pub fn RadiusServer::accounting_count(self : RadiusServer) -> Int {
  self.accounting
}

///|
/// Process one already-decoded request.
pub fn RadiusServer::handle(
  self : RadiusServer,
  packet : Packet,
) -> ServerResult raise RadiusError {
  self.handled = self.handled + 1
  let diagnostics = packet.diagnostics()
  if diagnostics.length() > 0 && self.config.reject_malformed {
    self.rejected = self.rejected + 1
    return Drop(["malformed packet rejected before policy evaluation"])
  }
  match packet.header.code {
    AccessRequest => {
      let decision = decide_access(
        packet,
        self.config.access_policy,
        self.config.secret,
      )
      Response(access_response(packet, decision, self.config.secret))
    }
    AccountingRequest =>
      if !self.config.accounting_enabled {
        self.rejected = self.rejected + 1
        Drop(["accounting is disabled"])
      } else {
        let errors = validate_accounting_request(packet)
        if errors.length() > 0 {
          self.rejected = self.rejected + 1
          Drop(errors)
        } else {
          self.accounting = self.accounting + 1
          Response(accounting_response(packet, self.config.secret))
        }
      }
    _ => {
      self.rejected = self.rejected + 1
      Drop(["unsupported request code"])
    }
  }
}

///|
/// Decode and dispatch a datagram.
pub fn RadiusServer::handle_bytes(
  self : RadiusServer,
  wire : Bytes,
) -> ServerResult raise RadiusError {
  match decode(wire) {
    packet => self.handle(packet)
  }
}

///|
/// Encode the response from a server result, if one exists.
pub fn ServerResult::encode(self : ServerResult) -> Bytes? raise RadiusError {
  match self {
    Response(packet) => Some(encode(packet))
    Drop(_) => None
  }
}

///|
/// Run a complete request/response exchange through the memory transport.
pub fn serve_once(
  server : RadiusServer,
  transport : MemoryTransport,
) -> ServerResult raise RadiusError {
  let request = transport.receive() catch {
    _ => raise Unsupported("transport receive failed")
  }
  let result = server.handle(request)
  match result {
    Response(response) => {
      transport.send(response) catch {
        _ => raise Unsupported("transport send failed")
      }
      result
    }
    Drop(_) => result
  }
}
