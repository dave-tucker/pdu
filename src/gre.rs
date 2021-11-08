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

use crate::{util, Error, Result};

/// Represents a GRE header and payload
#[derive(Debug, Copy, Clone)]
pub struct GrePdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of a [`GrePdu`]
#[derive(Debug, Copy, Clone)]
pub enum Gre<'a> {
    Raw(&'a [u8]),
    Ethernet(super::EthernetPdu<'a>),
    Ipv4(super::Ipv4Pdu<'a>),
    Ipv6(super::Ipv6Pdu<'a>),
}

impl<'a> GrePdu<'a> {
    /// Constructs a [`GrePdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 4 {
            return Err(Error::Truncated);
        }
        if buffer[1] & 0x07 != 0 {
            // we only support rfc2784 GRE frames
            return Err(Error::Malformed);
        }
        let pdu = GrePdu { buffer };
        if buffer.len() < pdu.computed_ihl() {
            return Err(Error::Truncated);
        }
        Ok(pdu)
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Consumes this object and returns a reference to the entire underlying buffer that was provided during
    /// construction
    pub fn into_buffer(self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.clone().into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Gre<'a>> {
        self.clone().into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Gre<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(match self.ethertype()? {
            super::EtherType::TEB => Gre::Ethernet(super::EthernetPdu::new(rest)?),
            super::EtherType::IPV4 => Gre::Ipv4(super::Ipv4Pdu::new(rest)?),
            super::EtherType::IPV6 => Gre::Ipv6(super::Ipv6Pdu::new(rest)?),
            _ => Gre::Raw(rest),
        })
    }

    pub fn computed_ihl(&'a self) -> usize {
        let mut ihl = 4;
        if self.has_checksum() {
            ihl += 4;
        }
        if self.has_key() {
            ihl += 4;
        }
        if self.has_sequence_number() {
            ihl += 4;
        }
        ihl
    }

    pub fn version(&'a self) -> Result<u8> {
        Ok(util::read_u8(self.buffer, 1)? & 0x07)
    }

    pub fn ethertype(&'a self) -> Result<u16> {
        util::read_u16(self.buffer, 2)
    }

    pub fn has_checksum(&'a self) -> bool {
        if let Ok(data) = util::read_u8(self.buffer, 0) {
            return (data & 0x80) != 0;
        } else {
            return false;
        }
    }

    pub fn has_key(&'a self) -> bool {
        if let Ok(data) = util::read_u8(self.buffer, 0) {
            return (data & 0x20) != 0;
        } else {
            return false;
        }
    }

    pub fn has_sequence_number(&'a self) -> bool {
        if let Ok(data) = util::read_u8(self.buffer, 0) {
            return (data & 0x10) != 0;
        } else {
            return false;
        }
    }

    pub fn checksum(&'a self) -> Option<u16> {
        if self.has_checksum() {
            if let Ok(data) = util::read_u16(self.buffer, 4) {
                Some(data)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn computed_checksum(&'a self) -> Option<u16> {
        if self.has_checksum() {
            let span1 = match util::read_slice_inclusive(self.buffer, 0, 3) {
                Ok(span) => span,
                Err(_) => return None,
            };
            let span2 = match util::read_slice_after(self.buffer, 6) {
                Ok(span) => span,
                Err(_) => return None,
            };
            Some(util::checksum(&[&span1, &span2]))
        } else {
            None
        }
    }

    pub fn key(&'a self) -> Option<u32> {
        if self.has_checksum() && self.has_key() {
            util::read_u32(self.buffer, 8).ok()
        } else if self.has_key() {
            util::read_u32(self.buffer, 4).ok()
        } else {
            None
        }
    }

    pub fn sequence_number(&'a self) -> Option<u32> {
        if self.has_sequence_number() && self.has_checksum() && self.has_key() {
            util::read_u32(self.buffer, 12).ok()
        } else if self.has_sequence_number() && (self.has_checksum() || self.has_key()) {
            util::read_u32(self.buffer, 8).ok()
        } else if self.has_sequence_number() {
            util::read_u32(self.buffer, 4).ok()
        } else {
            None
        }
    }
}
