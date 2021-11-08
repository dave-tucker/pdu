/*
   Copyright (c) 2019 Alex Forster <alex@alexforster.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   SPDX-License-Identifier: Apache-2.0
*/

use pdu::*;

pub fn fuzz(data: &[u8]) {
    match Ipv6Pdu::new(&data) {
        Ok(ipv6_pdu) => {
            ipv6_pdu.version().unwrap();
            ipv6_pdu.dscp().unwrap();
            ipv6_pdu.ecn().unwrap();
            ipv6_pdu.flow_label().unwrap();
            ipv6_pdu.payload_length().unwrap();
            ipv6_pdu.next_header().unwrap();
            ipv6_pdu.computed_ihl().unwrap();
            ipv6_pdu.computed_protocol().unwrap();
            ipv6_pdu.computed_identification();
            ipv6_pdu.computed_more_fragments();
            ipv6_pdu.computed_fragment_offset();
            ipv6_pdu.hop_limit().unwrap();
            ipv6_pdu.source_address().unwrap();
            ipv6_pdu.destination_address().unwrap();
            for extension_header in ipv6_pdu.extension_headers() {
                match extension_header {
                    Ipv6ExtensionHeader::Raw { .. } => {
                        continue;
                    }
                    Ipv6ExtensionHeader::Fragment { .. } => {
                        continue;
                    }
                }
            }
        }
        Err(_) => {}
    }
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            fuzz(&data);
        });
    }
}
