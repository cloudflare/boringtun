use std::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::util::size_must_be;

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct Udp<Payload: ?Sized = [u8]> {
    pub header: UdpHeader,
    pub payload: Payload,
}

#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable)]
pub struct UdpHeader {
    pub source_port: big_endian::U16,
    pub destination_port: big_endian::U16,
    pub length: big_endian::U16,
    pub checksum: big_endian::U16,
}

impl UdpHeader {
    #[allow(dead_code)]
    pub const LEN: usize = size_must_be::<UdpHeader>(8);
}

impl fmt::Debug for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpHeader")
            .field("source_port", &self.source_port.get())
            .field("destination_port", &self.destination_port.get())
            .field("length", &self.length.get())
            .field("checksum", &self.checksum.get())
            .finish()
    }
}
