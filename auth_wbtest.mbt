///|
test "user password encrypts and decrypts in blocks" {
  let secret = b"shared-secret"
  let request_authenticator = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
  let password = b"correct horse battery staple"
  let encrypted = encrypt_user_password(password, secret, request_authenticator)
  assert_true(encrypted.length() == 32)
  let decrypted = decrypt_user_password(
    encrypted, secret, request_authenticator,
  )
  assert_eq(decrypted, b"correct horse battery staple\x00\x00\x00\x00")
}

///|
test "chap response validates the challenge" {
  let challenge = b"nas-challenge"
  let value = Attribute::new(
    CHAP_Password,
    make_chap_password(9, b"secret", challenge),
  )
  assert_true(verify_chap(value, b"secret", challenge))
  assert_true(!verify_chap(value, b"wrong", challenge))
}

///|
test "response authenticator covers packet fields" {
  let request_authenticator = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
  let response = Packet::new(
    AccessAccept,
    3,
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
  ).with_attribute(Attribute::text(Reply_Message, "welcome"))
  let signed = response.with_response_authenticator(
    request_authenticator, b"secret",
  )
  assert_true(
    verify_response_authenticator(signed, request_authenticator, b"secret"),
  )
  assert_true(
    !verify_response_authenticator(signed, request_authenticator, b"other"),
  )
}

///|
test "vendor attribute preserves enterprise payload" {
  let vendor = VendorAttribute::new(9, 1, b"role=admin")
  let packet = Packet::request(AccessRequest, 8).with_vendor_attribute(vendor)
  let decoded = decode(encode(packet))
  let attribute = decoded.attribute(Vendor_Specific)
  match attribute {
    Some(item) => {
      let parsed = decode_vendor_attribute(item)
      match parsed {
        Some(value) => {
          assert_eq(value.vendor_id, 9)
          assert_eq(value.kind.to_int(), 1)
          assert_eq(value.value, b"role=admin")
        }
        None => abort("expected vendor payload")
      }
    }
    None => abort("expected vendor attribute")
  }
}
