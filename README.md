# MoonRADIUS

MoonRADIUS is a transport-independent RADIUS packet and attribute toolkit for MoonBit.

The project is an independent MoonBit rewrite based on the protocol behavior of
`layeh/radius` and the RADIUS specifications. It is not a FreeRADIUS server and
does not include a user database, EAP method implementation, or RadSec/TLS.

## Current scope

- RADIUS header and attribute encoding/decoding
- Access and Accounting packet types
- bounded parsing with stable structural errors
- standard and vendor-specific attribute containers
- transport-independent packet handling

## Example

```moonbit
let request = Packet::new(AccessRequest, 1, nonce)
  .with_attribute(Attribute::new(1, b"alice"))
let wire = encode(request)
let parsed = decode(wire)
```

## Verification

```bash
moon fmt
moon check --deny-warn
moon test
```

## Upstream and license

The protocol reference is RFC 2865/RFC 2866. The implementation is a rewrite
in MoonBit and does not vendor upstream source. The original behavioral
reference is [`layeh/radius`](https://github.com/layeh/radius), licensed under
MPL-2.0. This repository is Apache-2.0.
