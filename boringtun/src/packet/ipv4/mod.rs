use bitfield_struct::bitfield;
use std::{fmt::Debug, net::Ipv4Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

mod protocol;
pub use protocol::*;

use super::util::size_must_be;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv4<Payload: ?Sized = [u8]> {
    pub header: Ipv4Header,
    pub payload: Payload,
}

/// A bitfield struct containing the IPv4 fields `version` and `ihl`.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4VersionIhl {
    #[bits(4)]
    pub ihl: u8,
    #[bits(4)]
    pub version: u8,
}

/// A bitfield struct containing the IPv4 fields `dscp` and `ecn`.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4DscpEcn {
    #[bits(2)]
    pub ecn: u8,
    #[bits(6)]
    pub dscp: u8,
}

/// A bitfield struct containing the IPv4 fields `flags` and `fragment_offset`.
#[bitfield(u16, repr = big_endian::U16, from = big_endian::U16::new, into = big_endian::U16::get)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4FlagsFragmentOffset {
    #[bits(13)]
    pub fragment_offset: u16,
    #[bits(3)]
    pub flags: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version_and_ihl: Ipv4VersionIhl,
    pub dscp_and_ecn: Ipv4DscpEcn,
    pub total_len: big_endian::U16,
    pub identification: big_endian::U16,
    pub flags_and_fragment_offset: Ipv4FlagsFragmentOffset,
    pub time_to_live: u8,
    pub protocol: IpNextProtocol,
    pub header_checksum: big_endian::U16,
    pub source_address: big_endian::U32,
    pub destination_address: big_endian::U32,
}

impl Ipv4Header {
    /// Construct an IPv4 header with the reasonable defaults.
    ///
    /// `payload` field is used to set the length and compute the checksum.
    #[allow(dead_code)]
    pub const fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: IpNextProtocol,
        payload: &[u8],
    ) -> Self {
        Self::new_for_length(source, destination, protocol, payload.len() as u16)
    }

    pub const fn new_for_length(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: IpNextProtocol,
        payload_len: u16,
    ) -> Self {
        let header_len = size_of::<Ipv4Header>() as u16;
        let total_len = header_len + payload_len;

        Self {
            protocol,

            version_and_ihl: Ipv4VersionIhl::new().with_version(4).with_ihl(5),
            dscp_and_ecn: Ipv4DscpEcn::new(),
            total_len: big_endian::U16::new(total_len),
            identification: big_endian::U16::ZERO,
            flags_and_fragment_offset: Ipv4FlagsFragmentOffset::new(),
            time_to_live: 64, // default TTL in linux
            source_address: big_endian::U32::from_bytes(source.octets()),
            destination_address: big_endian::U32::from_bytes(destination.octets()),

            // TODO:
            header_checksum: big_endian::U16::ZERO,
        }
    }
}

impl Ipv4Header {
    pub const LEN: usize = size_must_be::<Ipv4Header>(20);

    /// The IP version. Must be `4` for a valid IPv4 header.
    pub const fn version(&self) -> u8 {
        self.version_and_ihl.version()
    }

    /// Internet Header Length.
    ///
    /// This is the length of the IPv4 header, specified in 4-byte words.
    /// The minimum value is `5`. If the header contains any IPv4 options, this value will be
    /// larger.
    pub const fn ihl(&self) -> u8 {
        self.version_and_ihl.ihl()
    }

    pub const fn source(&self) -> Ipv4Addr {
        let bits = self.source_address.get();
        Ipv4Addr::from_bits(bits)
    }

    pub const fn destination(&self) -> Ipv4Addr {
        let bits = self.destination_address.get();
        Ipv4Addr::from_bits(bits)
    }

    pub const fn next_protocol(&self) -> IpNextProtocol {
        self.protocol
    }

    pub const fn dscp(&self) -> u8 {
        self.dscp_and_ecn.dscp()
    }

    pub const fn ecn(&self) -> u8 {
        self.dscp_and_ecn.ecn()
    }

    pub const fn flags(&self) -> u8 {
        self.flags_and_fragment_offset.flags()
    }

    pub const fn fragment_offset(&self) -> u16 {
        self.flags_and_fragment_offset.fragment_offset()
    }
}

impl Debug for Ipv4Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Header")
            .field("version", &self.version())
            .field("ihl", &self.ihl())
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("total_len", &self.total_len.get())
            .field("identification", &self.identification.get())
            .field("flags", &self.flags())
            .field("fragment_offset", &self.fragment_offset())
            .field("time_to_live", &self.time_to_live)
            .field("protocol", &self.protocol)
            .field("header_checksum", &self.header_checksum.get())
            .field("source_address", &self.source())
            .field("destination_address", &self.destination())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Ipv4, Ipv4Header};
    use crate::packet::IpNextProtocol;
    use std::net::Ipv4Addr;
    use zerocopy::TryFromBytes;

    const EXAMPLE_IPV4_ICMP: &[u8] = &[
        0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc6, 0x26, 0xa, 0x8c, 0xc2, 0xdd,
        0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
        0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn ipv4_header_layout() {
        let packet = Ipv4::<[u8]>::try_ref_from_bytes(EXAMPLE_IPV4_ICMP).unwrap();
        let header = &packet.header;

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.dscp(), 32);
        assert_eq!(header.ecn(), 0x3);
        assert_eq!(header.total_len, 84);
        assert_eq!(header.identification, 41747);
        assert_eq!(header.flags(), 0b010);
        assert_eq!(header.fragment_offset(), 0);
        assert_eq!(header.time_to_live, 64);
        assert_eq!(header.protocol, IpNextProtocol::Icmp);
        assert_eq!(header.header_checksum, 0xc626);
        assert_eq!(header.source(), Ipv4Addr::new(10, 140, 194, 221));
        assert_eq!(header.destination(), Ipv4Addr::new(1, 2, 3, 4));

        assert_eq!(
            packet.payload.len() + Ipv4Header::LEN,
            usize::from(header.total_len)
        );
    }
}
