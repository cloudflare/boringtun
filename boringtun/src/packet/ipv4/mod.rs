use std::{fmt::Debug, net::Ipv4Addr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

mod protocol;
pub use protocol::*;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv4<Payload: ?Sized = [u8]> {
    pub header: Ipv4Header,
    pub payload: Payload,
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Ipv4Header {
    // TODO: replace u8 with bitfield type
    version_and_ihl: u8,

    // TODO: replace u8 with bitfield type
    dscp_and_ecn: u8,

    pub total_len: big_endian::U16,
    pub identification: big_endian::U16,

    // TODO: replace u16 with bitfield type
    flags_and_fragment_offset: big_endian::U16,

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

            version_and_ihl: 0x45,
            dscp_and_ecn: 0,
            total_len: big_endian::U16::new(total_len),
            identification: big_endian::U16::ZERO,
            flags_and_fragment_offset: big_endian::U16::ZERO,
            time_to_live: 64, // default TTL in linux
            source_address: big_endian::U32::from_bytes(source.octets()),
            destination_address: big_endian::U32::from_bytes(destination.octets()),

            // TODO:
            header_checksum: big_endian::U16::ZERO,
        }
    }
}

impl Ipv4Header {
    /// The IP version. Must be `4` for a valid IPv4 header.
    pub fn version(&self) -> u8 {
        (self.version_and_ihl & 0xf0) >> 4
    }

    /// Internet Header Length.
    ///
    /// This is the length of the IPv4 header, specified in 4-byte words.
    /// The minimum value is `5`. If the header contains any IPv4 options, this value will be
    /// larger.
    pub fn ihl(&self) -> u8 {
        self.version_and_ihl & 0x0f
    }

    pub fn source(&self) -> Ipv4Addr {
        let bits = self.source_address.get();
        Ipv4Addr::from_bits(bits)
    }

    pub fn destination(&self) -> Ipv4Addr {
        let bits = self.destination_address.get();
        Ipv4Addr::from_bits(bits)
    }

    pub fn next_protocol(&self) -> IpNextProtocol {
        self.protocol
    }
}

impl Debug for Ipv4Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Header")
            .field("version_and_ihl", &self.version_and_ihl) // TODO: split these up
            .field("dscp_and_ecn", &self.dscp_and_ecn) // TODO: split these up
            .field("total_len", &self.total_len.get())
            .field("identification", &self.identification.get())
            .field(
                "flags_and_fragment_offset",
                &self.flags_and_fragment_offset.get(), // TODO: split these up
            )
            .field("time_to_live", &self.time_to_live)
            .field("protocol", &self.protocol)
            .field("header_checksum", &self.header_checksum.get())
            .field("source_address", &self.source())
            .field("destination_address", &self.destination())
            .finish()
    }
}
