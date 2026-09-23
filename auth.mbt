/// RADIUS password and authenticator helpers.

///|
fn hex_digit(value : Byte) -> Int {
  let n = value.to_int()
  if n >= 48 && n <= 57 {
    n - 48
  } else if n >= 97 && n <= 102 {
    n - 87
  } else {
    0
  }
}

///|
fn md5_hex_to_bytes(value : String) -> Bytes {
  let raw = @utf8.encode(value)
  Bytes::makei(raw.length() / 2, fn(index) {
    ((hex_digit(raw[index * 2]) << 4) | hex_digit(raw[index * 2 + 1])).to_byte()
  })
}

///|
fn md5_bytes(input : Bytes) -> Bytes {
  let digest = @md5.Digest::new()
  for byte in input {
    digest.write(byte)
  }
  md5_hex_to_bytes(digest.check_sum())
}

///|
fn password_block(secret : Bytes, previous : Bytes) -> Bytes {
  md5_bytes(join_bytes(secret, previous))
}

///|
/// Encrypt a User-Password attribute according to RFC 2865 section 5.2.
pub fn encrypt_user_password(
  password : Bytes,
  secret : Bytes,
  request_authenticator : Bytes,
) -> Bytes raise RadiusError {
  if request_authenticator.length() != 16 {
    raise InvalidAuthenticator
  }
  let padded_length = (password.length() + 15) / 16 * 16
  let padded = join_bytes(password, zeros(padded_length - password.length()))
  let mut result = b""
  let mut previous = request_authenticator
  for offset = 0; offset < padded.length(); offset = offset + 16 {
    let block = slice_bytes(padded, offset, 16)
    let mask = password_block(secret, previous)
    let encrypted = xor_bytes(block, mask)
    result = join_bytes(result, encrypted)
    previous = encrypted
  }
  if result.length() == 0 {
    zeros(16)
  } else {
    result
  }
}

///|
/// Decrypt a User-Password attribute according to RFC 2865 section 5.2.
pub fn decrypt_user_password(
  encrypted : Bytes,
  secret : Bytes,
  request_authenticator : Bytes,
) -> Bytes raise RadiusError {
  if encrypted.length() == 0 || encrypted.length() % 16 != 0 {
    raise InvalidAttribute(
      "encrypted password must be a non-empty multiple of 16 bytes",
    )
  }
  if request_authenticator.length() != 16 {
    raise InvalidAuthenticator
  }
  let mut result = b""
  let mut previous = request_authenticator
  for offset = 0; offset < encrypted.length(); offset = offset + 16 {
    let block = slice_bytes(encrypted, offset, 16)
    let mask = password_block(secret, previous)
    result = join_bytes(result, xor_bytes(block, mask))
    previous = block
  }
  result
}

///|
/// Compute the CHAP response value stored in CHAP-Password.
pub fn chap_response(
  identifier : Byte,
  password : Bytes,
  challenge : Bytes,
) -> Bytes {
  md5_bytes(
    join_bytes(
      join_bytes(Bytes::makei(1, fn(_) { identifier }), password),
      challenge,
    ),
  )
}

///|
/// Build the 17-byte CHAP-Password value (identifier followed by digest).
pub fn make_chap_password(
  identifier : Byte,
  password : Bytes,
  challenge : Bytes,
) -> Bytes {
  join_bytes(
    Bytes::makei(1, fn(_) { identifier }),
    chap_response(identifier, password, challenge),
  )
}

///|
/// Verify a CHAP-Password attribute against a cleartext shared secret.
pub fn verify_chap(
  attribute : Attribute,
  password : Bytes,
  challenge : Bytes,
) -> Bool {
  if attribute.kind != CHAP_Password || attribute.value.length() != 17 {
    false
  } else {
    let identifier = attribute.value[0]
    let expected = make_chap_password(identifier, password, challenge)
    byte_eq(attribute.value, expected)
  }
}

///|
/// Constant-time comparison for authenticators and password-derived values.
pub fn constant_time_equal(left : Bytes, right : Bytes) -> Bool {
  byte_eq(left, right)
}

///|
/// Return the decoded User-Password from a packet, if present.
pub fn Packet::user_password(
  self : Packet,
  secret : Bytes,
) -> Bytes? raise RadiusError {
  match self.attribute(User_Password) {
    Some(attribute) =>
      Some(
        decrypt_user_password(
          attribute.value,
          secret,
          self.header.authenticator,
        ),
      )
    None => None
  }
}
