///|
fn main {
  let request = @radius.example_wifi_request()
  let wire = @radius.encode(request) catch { _ => abort("encode failed") }
  let parsed = @radius.decode(wire) catch { _ => abort("decode failed") }
  println("code=" + @radius.packet_code_name(parsed.code()))
  println("identifier=" + parsed.identifier().to_int().to_string())
  println("wire_bytes=" + wire.length().to_string())
  println("diagnostics=" + @radius.diagnose(wire).length().to_string())
}
