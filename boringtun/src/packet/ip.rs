use std::net::IpAddr;

use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::packet::{Ipv4, Ipv6};

/// A packet bitfield-struct containing the `version`-field that is shared between IPv4 and IPv6.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct IpvxVersion {
    #[bits(4)]
    pub _unknown: u8,
    #[bits(4)]
    pub version: u8,
}

/// An IP packet, including headers, that may be either IPv4 or IPv6.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ip {
    pub header: IpvxVersion,
    pub payload: [u8],
}

impl Ip {
    pub fn destination(&self) -> Option<IpAddr> {
        match self.header.version() {
            4 => {
                let ipv4 = Ipv4::<[u8]>::ref_from_bytes(self.as_bytes()).ok()?;
                Some(ipv4.header.destination().into())
            }
            6 => {
                let ipv6 = Ipv6::<[u8]>::ref_from_bytes(self.as_bytes()).ok()?;
                Some(ipv6.header.destination().into())
            }
            _ => None,
        }
    }
}
