use pdu::*;

// parse a layer 3 (IP) packet using Ip::new()
fn main() {
    if let Err(e) = try_parse() {
        panic!("{}", e)
    }
}

fn try_parse() -> Result<()> {
    let packet: &[u8] = &[
        0x45, 0x00, 0x00, 0x3b, 0x2d, 0xfd, 0x00, 0x00, 0x40, 0x11, 0xbc, 0x43, 0x83, 0xb3, 0xc4, 0x2e, 0x83, 0xb3,
        0xc4, 0xdc, 0x18, 0xdb, 0x18, 0xdb, 0x00, 0x27, 0xe0, 0x3e, 0x05, 0x1d, 0x07, 0x15, 0x08, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x08, 0x07, 0x74, 0x65, 0x73, 0x74, 0x41, 0x70, 0x70, 0x08, 0x01, 0x31, 0x0a,
        0x04, 0x1e, 0xcc, 0xe2, 0x51,
    ];

    match Ip::new(packet) {
        Ok(Ip::Ipv4(ipv4_pdu)) => {
            println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address()?.as_ref());
            println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address()?.as_ref());
            println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol()?);
            // upper-layer protocols can be accessed via the inner() method (not shown)
            Ok(())
        }
        Ok(Ip::Ipv6(ipv6_pdu)) => {
            println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address()?.as_ref());
            println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address()?.as_ref());
            println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol()?);
            // upper-layer protocols can be accessed via the inner() method (not shown)
            Ok(())
        }
        Err(e) => {
            panic!("Ip::new() parser failure: {:?}", e);
        }
    }
}
