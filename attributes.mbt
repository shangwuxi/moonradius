///|
/// Typed helpers for standard and vendor-specific attributes.
pub struct VendorAttribute {
  vendor_id : Int
  kind : Byte
  value : Bytes
}

///|
pub fn VendorAttribute::new(
  vendor_id : Int,
  kind : Byte,
  value : Bytes,
) -> VendorAttribute {
  VendorAttribute::{ vendor_id, kind, value, }
}

///|
/// Encode the value portion of a Vendor-Specific attribute.
pub fn VendorAttribute::encode(
  self : VendorAttribute,
) -> Bytes raise RadiusError {
  if self.vendor_id < 0 {
    raise InvalidAttribute("vendor id is outside uint32 range")
  }
  if self.value.length() > 249 {
    raise InvalidAttribute("vendor attribute value exceeds 249 bytes")
  }
  join_bytes(
    u32_bytes(self.vendor_id),
    join_bytes(
      Bytes::makei(2, fn(index) {
        if index == 0 {
          self.kind
        } else {
          (self.value.length() + 2).to_byte()
        }
      }),
      self.value,
    ),
  )
}

///|
/// Decode the value of a Vendor-Specific attribute.
pub fn decode_vendor_attribute(
  attribute : Attribute,
) -> VendorAttribute? raise RadiusError {
  if attribute.kind != Vendor_Specific || attribute.value.length() < 6 {
    None
  } else {
    Some(VendorAttribute::{
      vendor_id: (attribute.value[0].to_int() << 24) |
      (attribute.value[1].to_int() << 16) |
      (attribute.value[2].to_int() << 8) |
      attribute.value[3].to_int(),
      kind: attribute.value[4],
      value: slice_bytes(attribute.value, 6, attribute.value.length() - 6),
    })
  }
}

///|
/// Add a Vendor-Specific attribute to a packet.
pub fn Packet::with_vendor_attribute(
  self : Packet,
  vendor : VendorAttribute,
) -> Packet raise RadiusError {
  self.with_attribute(Attribute::new(Vendor_Specific, vendor.encode()))
}

///|
/// A small dictionary entry suitable for vendor extensions.
pub struct DictionaryEntry {
  name : String
  code : Byte
  kind : String
}

///|
pub fn DictionaryEntry::new(
  name : String,
  code : Byte,
  kind : String,
) -> DictionaryEntry {
  DictionaryEntry::{ name, code, kind, }
}

///|
/// An immutable dictionary assembled from standard and vendor entries.
pub struct Dictionary {
  entries : Array[DictionaryEntry]
}

///|
pub fn Dictionary::new() -> Dictionary {
  Dictionary::{ entries: [], }
}

///|
pub fn Dictionary::standard() -> Dictionary {
  let dictionary = Dictionary::new()
  let dictionary = dictionary.add(
    DictionaryEntry::new("User-Name", User_Name, "string"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("User-Password", User_Password, "password"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("CHAP-Password", CHAP_Password, "chap"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("NAS-IP-Address", NAS_IP_Address, "ipv4"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("NAS-Port", NAS_Port, "integer"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("Service-Type", Service_Type, "integer"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("Reply-Message", Reply_Message, "string"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("State", State, "octets"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("Class", Class, "octets"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("Acct-Status-Type", Acct_Status_Type, "integer"),
  )
  let dictionary = dictionary.add(
    DictionaryEntry::new("Acct-Session-Id", Acct_Session_Id, "string"),
  )
  dictionary
}

///|
pub fn Dictionary::add(
  self : Dictionary,
  entry : DictionaryEntry,
) -> Dictionary {
  self.entries.push(entry)
  self
}

///|
pub fn Dictionary::lookup_code(
  self : Dictionary,
  code : Byte,
) -> DictionaryEntry? {
  for entry in self.entries {
    if entry.code == code {
      return Some(entry)
    }
  }
  None
}

///|
pub fn Dictionary::lookup_name(
  self : Dictionary,
  name : String,
) -> DictionaryEntry? {
  for entry in self.entries {
    if entry.name == name {
      return Some(entry)
    }
  }
  None
}

///|
/// Validate attribute lengths and required payload shapes.
pub fn validate_attribute(attribute : Attribute) -> String? {
  if attribute.value.length() > 253 {
    Some("attribute payload exceeds 253 bytes")
  } else if attribute.kind == CHAP_Password && attribute.value.length() != 17 {
    Some("CHAP-Password must contain one identifier and sixteen digest bytes")
  } else if attribute.kind == Acct_Status_Type && attribute.value.length() != 4 {
    Some("Acct-Status-Type must be a four-byte integer")
  } else {
    None
  }
}

///|
/// Return all validation messages without dropping the original attributes.
pub fn validate_packet(packet : Packet) -> Array[String] {
  let errors = []
  if packet.header.authenticator.length() != 16 {
    errors.push("authenticator must be exactly 16 bytes")
  }
  for attribute in packet.attributes {
    match validate_attribute(attribute) {
      Some(message) => errors.push(message)
      None => ()
    }
  }
  errors
}
