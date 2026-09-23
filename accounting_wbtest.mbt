///|
test "accounting status helpers identify lifecycle records" {
  let start = example_accounting_start()
  assert_true(is_accounting_start(start))
  assert_true(!is_accounting_stop(start))
  let stop = make_accounting_stop(1, zeros(16), "s-1", 100, 200)
  assert_true(is_accounting_stop(stop))
  assert_eq(accounting_octets(stop), 300)
}

///|
test "accounting counters tolerate malformed value shapes" {
  let packet = Packet::request(AccountingRequest, 1).with_attribute(
    Attribute::new(Acct_Input_Octets, b"\x01"),
  )
  assert_eq(accounting_counter(packet, Acct_Input_Octets), 0)
}
