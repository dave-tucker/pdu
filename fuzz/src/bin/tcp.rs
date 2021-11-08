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
    match TcpPdu::new(&data) {
        Ok(tcp_pdu) => {
            tcp_pdu.source_port().unwrap();
            tcp_pdu.destination_port().unwrap();
            tcp_pdu.sequence_number().unwrap();
            tcp_pdu.acknowledgement_number().unwrap();
            tcp_pdu.data_offset().unwrap();
            tcp_pdu.computed_data_offset().unwrap();
            tcp_pdu.flags().unwrap();
            tcp_pdu.fin();
            tcp_pdu.syn();
            tcp_pdu.rst();
            tcp_pdu.psh();
            tcp_pdu.ack();
            tcp_pdu.urg();
            tcp_pdu.ecn();
            tcp_pdu.cwr();
            tcp_pdu.window_size().unwrap();
            tcp_pdu.computed_window_size(14).unwrap();
            tcp_pdu.checksum().unwrap();
            let ip = Ip::Ipv4(
                Ipv4Pdu::new(&[
                    0x45u8, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ])
                .unwrap(),
            );
            tcp_pdu.computed_checksum(&ip).unwrap();
            let ip = Ip::Ipv6(
                Ipv6Pdu::new(&[
                    0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .unwrap(),
            );
            tcp_pdu.computed_checksum(&ip).unwrap();
            tcp_pdu.urgent_pointer().unwrap();
            for option in tcp_pdu.options() {
                match option {
                    TcpOption::Raw { .. } => {
                        continue;
                    }
                    TcpOption::NoOp => {
                        continue;
                    }
                    TcpOption::Mss { .. } => {
                        continue;
                    }
                    TcpOption::WindowScale { .. } => {
                        continue;
                    }
                    TcpOption::SackPermitted => {
                        continue;
                    }
                    TcpOption::Sack { .. } => {
                        continue;
                    }
                    TcpOption::Timestamp { .. } => {
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
