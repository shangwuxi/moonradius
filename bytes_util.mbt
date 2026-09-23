///|
fn zeros(count : Int) -> Bytes {
  if count <= 0 {
    b""
  } else {
    Bytes::makei(count, fn(_) { b'\x00' })
  }
}

///|
fn slice_bytes(
  input : Bytes,
  start : Int,
  length : Int,
) -> Bytes raise RadiusError {
  if start < 0 || length < 0 || start + length > input.length() {
    raise TooShort
  }
  Bytes::makei(length, fn(index) { input[start + index] })
}

///|
fn byte_eq(left : Bytes, right : Bytes) -> Bool {
  if left.length() != right.length() {
    false
  } else {
    let mut equal = true
    for index = 0; index < left.length(); index = index + 1 {
      if left[index] != right[index] {
        equal = false
      }
    }
    equal
  }
}

///|
fn xor_bytes(left : Bytes, right : Bytes) -> Bytes raise RadiusError {
  if left.length() != right.length() {
    raise InvalidAttribute("xor operands have different lengths")
  }
  Bytes::makei(left.length(), fn(index) {
    (left[index].to_int() ^ right[index].to_int()).to_byte()
  })
}

///|
fn u32_bytes(value : Int) -> Bytes {
  Bytes::makei(4, fn(index) { ((value >> (24 - index * 8)) & 255).to_byte() })
}
