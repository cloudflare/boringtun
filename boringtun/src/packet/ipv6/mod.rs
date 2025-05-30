use std::{fmt::Debug, net::Ipv6Addr};
use zerocopy::{big_endian, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::IpNextProtocol;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv6<Payload: ?Sized = [u8]> {
    pub header: Ipv6Header,
    pub payload: Payload,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv6Header {
    // TODO: replace with bitfield type
    version_traffic_flow: big_endian::U32,

    pub payload_length: big_endian::U16,
    pub next_header: IpNextProtocol,
    pub hop_limit: u8,
    pub source_address: big_endian::U128,
    pub destination_address: big_endian::U128,
}

impl Ipv6Header {
    pub fn source(&self) -> Ipv6Addr {
        let bits = self.source_address.get();
        Ipv6Addr::from_bits(bits)
    }

    pub fn destination(&self) -> Ipv6Addr {
        let bits = self.destination_address.get();
        Ipv6Addr::from_bits(bits)
    }

    pub fn next_protocol(&self) -> IpNextProtocol {
        self.next_header
    }

    pub fn set_version(&mut self, version: u8) {
        let old = self.version_traffic_flow.get();
        let new = (old & 0x0FFFFFFF) | (((version as u32) & 0xF) << 28);
        self.version_traffic_flow.set(new);
    }

    pub fn set_traffic_class(&mut self, tc: u8) {
        let old = self.version_traffic_flow.get();
        let new = (old & !(0xFF << 20)) | (((tc as u32) & 0xFF) << 20);
        self.version_traffic_flow.set(new);
    }

    pub fn set_flow_label(&mut self, flow: u32) {
        let old = self.version_traffic_flow.get();
        let new = (old & !0xFFFFF) | (flow & 0xFFFFF);
        self.version_traffic_flow.set(new);
    }
}
