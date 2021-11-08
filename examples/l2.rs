use pdu::*;

// parse a layer 2 (Ethernet) packet using EthernetPdu::new()

fn main() {
    if let Err(e) = try_parse() {
        panic!("{}", e)
    }
}

fn try_parse() -> Result<()> {
    let packet: &[u8] = &[
        0x68, 0x5b, 0x35, 0xc0, 0x61, 0xb6, 0x00, 0x1d, 0x09, 0x94, 0x65, 0x38, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3b,
        0x2d, 0xfd, 0x00, 0x00, 0x40, 0x11, 0xbc, 0x43, 0x83, 0xb3, 0xc4, 0x2e, 0x83, 0xb3, 0xc4, 0xdc, 0x18, 0xdb,
        0x18, 0xdb, 0x00, 0x27, 0xe0, 0x3e, 0x05, 0x1d, 0x07, 0x15, 0x08, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x08, 0x07, 0x74, 0x65, 0x73, 0x74, 0x41, 0x70, 0x70, 0x08, 0x01, 0x31, 0x0a, 0x04, 0x1e, 0xcc, 0xe2,
        0x51,
    ];

    match EthernetPdu::new(packet) {
        Ok(ethernet_pdu) => {
            println!("[ethernet] destination_address: {:x?}", ethernet_pdu.destination_address()?.as_ref());
            println!("[ethernet] source_address: {:x?}", ethernet_pdu.source_address()?.as_ref());
            println!("[ethernet] ethertype: 0x{:04x}", ethernet_pdu.ethertype()?);
            if let Some(vlan) = ethernet_pdu.vlan() {
                println!("[ethernet] vlan: 0x{:04x}", vlan);
            }
            // upper-layer protocols can be accessed via the inner() method
            match ethernet_pdu.inner() {
                Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                    println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address()?.as_ref());
                    println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address()?.as_ref());
                    println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol()?);
                    // upper-layer protocols can be accessed via the inner() method (not shown)
                    Ok(())
                }
                Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                    println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address()?.as_ref());
                    println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address()?.as_ref());
                    println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol()?);
                    // upper-layer protocols can be accessed via the inner() method (not shown)
                    Ok(())
                }
                Ok(other) => {
                    panic!("Unexpected protocol {:?}", other);
                }
                Err(e) => {
                    panic!("EthernetPdu::inner() parser failure: {:?}", e);
                }
            }
        }
        Err(e) => {
            panic!("EthernetPdu::new() parser failure: {:?}", e);
        }
    }
}
