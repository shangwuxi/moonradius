/// Complete, offline examples used by the README and the test suite.
///
/// These functions deliberately return packets rather than opening sockets.
/// Applications can connect the result to UDP, a simulator, or a gateway.

///|
/// Enterprise Wi-Fi Access-Request with PAP.
pub fn example_wifi_request() -> Packet {
  let request_authenticator = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
  let encrypted = encrypt_user_password(
    b"correct horse battery staple", b"wifi-shared-secret", request_authenticator,
  ) catch {
    _ => b""
  }
  Packet::new(AccessRequest, 42, request_authenticator)
  .with_attribute(Attribute::text(User_Name, "alice@example.com"))
  .with_attribute(Attribute::new(User_Password, encrypted))
  .with_attribute(Attribute::text(NAS_Identifier, "ap-east-01"))
  .with_attribute(Attribute::integer(NAS_Port, 17))
  .with_attribute(Attribute::integer(Service_Type, Framed))
}

///|
/// VPN Access-Challenge flow with a CHAP challenge.
pub fn example_vpn_challenge() -> Packet {
  let challenge = b"vpn-challenge-2026"
  Packet::new(
    AccessRequest,
    7,
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F",
  )
  .with_attribute(Attribute::text(User_Name, "vpn-user"))
  .with_attribute(
    Attribute::new(
      CHAP_Password,
      make_chap_password(7, b"vpn-password", challenge),
    ),
  )
  .with_attribute(Attribute::new(State, challenge))
  .with_attribute(Attribute::text(NAS_Identifier, "vpn-gateway"))
}

///|
/// NAS Accounting Start record.
pub fn example_accounting_start() -> Packet {
  Packet::new(
    AccountingRequest,
    12,
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F",
  )
  .with_attribute(Attribute::integer(Acct_Status_Type, Acct_Start))
  .with_attribute(Attribute::text(Acct_Session_Id, "sess-20260923-0001"))
  .with_attribute(Attribute::text(User_Name, "alice@example.com"))
  .with_attribute(Attribute::text(NAS_Identifier, "nas-01"))
  .with_attribute(Attribute::integer(NAS_Port, 17))
}

///|
/// Build an Access-Accept for the Wi-Fi example.
pub fn example_wifi_accept() -> Packet raise RadiusError {
  let request = example_wifi_request()
  let policy = AccessPolicy::new()
    .allow(
      Credential::new("alice@example.com", b"correct horse battery staple"),
    )
    .with_reply("authenticated by MoonRADIUS")
  let decision = decide_access(request, policy, b"wifi-shared-secret")
  access_response(request, decision, b"wifi-shared-secret")
}

///|
/// Build an Accounting-Response for the start example.
pub fn example_accounting_response() -> Packet raise RadiusError {
  accounting_response(example_accounting_start(), b"accounting-secret")
}

///|
/// Run all three examples through encode/decode and return wire lengths.
pub fn run_examples() -> Array[Int] raise RadiusError {
  let wifi = decode(encode(example_wifi_request()))
  let vpn = decode(encode(example_vpn_challenge()))
  let accounting = decode(encode(example_accounting_start()))
  [encode(wifi).length(), encode(vpn).length(), encode(accounting).length()]
}

///|
/// A short textual description suitable for CLI help output.
pub fn example_catalog() -> Array[String] {
  [
    "wifi-pap: enterprise Wi-Fi Access-Request with encrypted User-Password", "vpn-chap: VPN Access-Request with CHAP response and state",
    "nas-accounting: Accounting-Start record with session counters",
  ]
}
