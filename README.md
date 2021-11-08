# pdu

Small, fast, and correct L2/L3/L4 packet parser.

**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** Apache-2.0

[![build status](https://travis-ci.org/alexforster/pdu.svg?branch=master)](https://travis-ci.org/alexforster/pdu)
[![crates.io version](https://img.shields.io/crates/v/pdu.svg)](https://crates.io/crates/pdu)
[![docs.rs](https://docs.rs/pdu/badge.svg)](https://docs.rs/pdu)

#### Small

 * Fully-featured `no_std` support
 * No Crate dependencies and no macros
 * Internet protocols only: application-layer protocols are out of scope

#### Fast

 * Lazy parsing: only the fields that you access are parsed
 * Zero-copy construction: no heap allocations are performed

#### Correct

 * Tested against [Wireshark](https://www.wireshark.org/docs/man-pages/tshark.html) to ensure all packet fields are parsed correctly
 * Fuzzed using [Honggfuzz](https://github.com/google/honggfuzz) to ensure invalid input does not cause panics
 * Does not use any `unsafe` code

## Supported Protocols

The following protocol hierarchy can be parsed with this library:

 * Ethernet (including vlan)
   * ARP
   * IPv4 (including options)
     * TCP (including options)
     * UDP
     * ICMP
     * GREv0
       * ...Ethernet, IPv4, IPv6...
   * IPv6 (including extension headers)
     * TCP (including options)
     * UDP
     * ICMPv6
     * GREv0
       * ...Ethernet, IPv4, IPv6...

In addition, unrecognized upper protocols are accessible as bytes via `Raw`
enum variants.

## Getting Started

#### `Cargo.toml`

```toml
[dependencies]
pdu = "1.4"
```

#### Examples

- [Layer 2](./examples/l2.rs)
- [Layer 3](./examples/l3.rs)

You can run examples using `cargo`:

```
$ cargo run --example l2

[ethernet] destination_address: [68, 5b, 35, c0, 61, b6]
[ethernet] source_address: [0, 1d, 9, 94, 65, 38]
[ethernet] ethertype: 0x0800
[ipv4] source_address: [83, b3, c4, 2e]
[ipv4] destination_address: [83, b3, c4, dc]
[ipv4] protocol: 0x11
```