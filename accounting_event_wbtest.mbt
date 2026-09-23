///|
test "accounting event classification covers lifecycle statuses" {
  assert_eq(accounting_event(example_accounting_start()), Start)
  let interim = Packet::request(AccountingRequest, 4)
    .with_attribute(Attribute::session_status(Acct_Interim_Update))
    .with_attribute(Attribute::session_id("s-4"))
  assert_eq(accounting_event(interim), Interim)
  let unknown = Packet::request(AccountingRequest, 5).with_attribute(
    Attribute::integer(Acct_Status_Type, 99),
  )
  assert_eq(accounting_event(unknown), UnknownStatus(99))
}

///|
test "accounting session label is safe for missing identifiers" {
  let packet = Packet::request(AccountingRequest, 7)
  assert_eq(accounting_session_label(packet), "<missing-session-id>")
}
