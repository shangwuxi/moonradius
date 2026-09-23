///|
/// Stable structural diagnostics suitable for CLI and test output.
pub enum DiagnosticKind {
  Header
  Attribute
} derive(Eq, Debug)

///|
pub struct Diagnostic {
  kind : DiagnosticKind
  offset : Int
  message : String
}

///|
pub fn Diagnostic::new(
  kind : DiagnosticKind,
  offset : Int,
  message : String,
) -> Diagnostic {
  Diagnostic::{ kind, offset, message, }
}

///|
pub fn diagnose(bytes : Bytes) -> Array[Diagnostic] {
  let diagnostics = []
  if bytes.length() < 20 {
    diagnostics.push(
      Diagnostic::new(Header, 0, "RADIUS header requires 20 bytes"),
    )
    return diagnostics
  }
  if Code::from_int(bytes[0].to_int()) is Unknown(_) {
    diagnostics.push(Diagnostic::new(Header, 0, "unsupported RADIUS Code"))
  }
  let declared = (bytes[2].to_int() << 8) | bytes[3].to_int()
  if declared < 20 {
    diagnostics.push(
      Diagnostic::new(Header, 2, "declared length is below header size"),
    )
  } else if declared != bytes.length() {
    diagnostics.push(
      Diagnostic::new(Header, 2, "declared length does not match datagram"),
    )
  }
  if bytes.length() >= 20 {
    diagnose_attributes(bytes, diagnostics)
  }
  diagnostics
}

///|
fn diagnose_attributes(bytes : Bytes, diagnostics : Array[Diagnostic]) -> Unit {
  let mut offset = 20
  while offset < bytes.length() {
    if offset + 1 >= bytes.length() {
      diagnostics.push(
        Diagnostic::new(Attribute, offset, "attribute header is truncated"),
      )
      return
    }
    let length = bytes[offset + 1].to_int()
    if length < 2 {
      diagnostics.push(
        Diagnostic::new(Attribute, offset, "attribute length is below two"),
      )
      return
    }
    if offset + length > bytes.length() {
      diagnostics.push(
        Diagnostic::new(Attribute, offset, "attribute payload is truncated"),
      )
      return
    }
    offset = offset + length
  }
}

///|
/// Diagnose a packet while also checking the declared body boundary.
///
/// `diagnose` is intentionally non-throwing so command-line tools can show
/// every reliable problem in one pass. This helper adds a precise offset for
/// bytes that exist after the declared packet length.
pub fn diagnose_strict(bytes : Bytes) -> Array[Diagnostic] {
  let diagnostics = diagnose(bytes)
  if bytes.length() >= 4 {
    let declared = (bytes[2].to_int() << 8) | bytes[3].to_int()
    if declared >= 20 && declared < bytes.length() {
      diagnostics.push(
        Diagnostic::new(
          Header,
          declared,
          "datagram contains bytes after declared packet length",
        ),
      )
    }
  }
  diagnostics
}

///|
pub fn diagnostics_are_clean(diagnostics : Array[Diagnostic]) -> Bool {
  diagnostics.length() == 0
}

///|
pub fn Packet::diagnostics(self : Packet) -> Array[Diagnostic] {
  let errors = []
  for message in validate_packet(self) {
    errors.push(Diagnostic::new(Attribute, 20, message))
  }
  errors
}
