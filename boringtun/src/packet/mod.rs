use std::{marker::PhantomData, ops::Deref};

use bitfield_struct::bitfield;
use bytes::Bytes;
use either::Either;
use eyre::{Context, bail, eyre};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

mod ipv4;
mod ipv6;
mod pool;
mod udp;
mod util;

pub use ipv4::*;
pub use ipv6::*;
pub use pool::*;
pub use udp::*;

/// An owned packet of some type.
///
/// The generic type `Kind` represents the type of packet.
/// For example, a `Packet<[u8]>` is an untyped packet containing arbitrary bytes.
/// It can be safely decoded into a `Packet<Ipv4>` using [`Packet::try_into_ip`],
/// and further decoded into a `Packet<Ipv4<Udp>>` using [`Packet::try_into_udp`].
///
/// [Packet] uses [Bytes] as the backing buffer, and can thus be cheaply cloned.
///
/// ```
/// use boringtun::packet::*;
/// use std::net::Ipv4Addr;
/// use zerocopy::IntoBytes;
///
/// let ip_header = Ipv4Header::new(
///     Ipv4Addr::new(10, 0, 0, 1),
///     Ipv4Addr::new(1, 2, 3, 4),
///     IpNextProtocol::Icmp,
///     &[],
/// );
///
/// let ip_header_bytes = ip_header.as_bytes();
///
/// let raw_packet: Packet<[u8]> = Packet::copy_from_slice(ip_header_bytes);
/// let ipv4_packet: Packet<Ipv4> = raw_packet.try_into_ip().unwrap().unwrap_left();
/// assert_eq!(&ip_header, &ipv4_packet.header);
/// ```
#[derive(Debug)]
pub struct Packet<Kind: ?Sized = [u8]> {
    buf: Bytes,

    /// Marker type defining what type `Bytes` is.
    ///
    /// INVARIANT:
    /// `buf` must have been ensured to actually contain a packet of this type.
    _kind: PhantomData<Kind>,
}

/// A marker trait that indicates that a [Packet] contains a valid payload of a specific type.
///
/// For example, [CheckedPayload] is implemented for [`Ipv4<[u8]>`], and a [`Packet<Ipv4<[u8]>>>`]
/// can only be constructed through [`Packet::<[u8]>::try_into_ip`], which checks that the IPv4
/// header is valid.
pub trait CheckedPayload: FromBytes + KnownLayout + Immutable {}

impl CheckedPayload for [u8] {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv6<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv4<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Udp<P> {}

/// A packet bitfield-struct containing the `version`-field that is shared between IPv4 and IPv6.
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct IpvxVersion {
    #[bits(4)]
    pub _unknown: u8,
    #[bits(4)]
    pub version: u8,
}

impl Packet<[u8]> {
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            buf: bytes,
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self {
            buf: Bytes::copy_from_slice(bytes),
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn try_into_ip(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        let buf_len = self.buf.len();

        if buf_len == 0 {
            bail!("Empty packet");
        }

        // Decode the IP version field to figure out if this is IPv4 of IPv6.
        let ip_version = IpvxVersion::from_bits(self.buf[0]).version();

        match ip_version {
            4 => {
                let ipv4 = Ipv4::<[u8]>::try_ref_from_bytes(&self.buf[..])
                    .map_err(|e| eyre!("Bad IPv4 packet: {e:?}"))?;

                let ip_len = usize::from(ipv4.header.total_len.get());
                if ip_len != buf_len {
                    bail!("IP header length did not match packet length: {ip_len} != {buf_len}");
                }

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv4 packet.
                // update `_kind` to reflect this.
                let packet = Packet {
                    buf: self.buf,
                    _kind: PhantomData::<Ipv4>,
                };

                Ok(Either::Left(packet))
            }
            6 => bail!("TODO: IPv6"),
            v => bail!("Bad IP version: {v}"),
        }
    }
}

impl Packet<Ipv4> {
    /// Check if the IP payload is valid UDP.
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv4<Udp>>> {
        let ip = self.deref();

        match ip.header.ihl() {
            5 => {}
            6.. => {
                return Err(eyre!("IP header: {:?}", ip.header))
                    .wrap_err(eyre!("IPv4 packets with options are not supported"));
            }
            ihl @ ..5 => {
                return Err(eyre!("IP header: {:?}", ip.header))
                    .wrap_err(eyre!("Bad IHL value: {ihl}"));
            }
        }

        validate_udp(ip.header.next_protocol(), &ip.payload)
            .wrap_err_with(|| eyre!("IP header: {:?}", ip.header))?;

        // we have asserted that the packet is a valid IPv4 UDP packet.
        // update `_kind` to reflect this.
        let packet = Packet {
            buf: self.buf,
            _kind: PhantomData::<Ipv4<Udp>>,
        };

        Ok(packet)
    }
}

impl Packet<Ipv6> {
    /// Check if the IP payload is valid UDP.
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv6<Udp>>> {
        let ip = self.deref();

        validate_udp(ip.header.next_protocol(), &ip.payload)
            .wrap_err_with(|| eyre!("IP header: {:?}", ip.header))?;

        // we have asserted that the packet is a valid IPv6 UDP packet.
        // update `_kind` to reflect this.
        let packet = Packet {
            buf: self.buf,
            _kind: PhantomData::<Ipv6<Udp>>,
        };

        Ok(packet)
    }
}

fn validate_udp(next_protocol: IpNextProtocol, payload: &[u8]) -> eyre::Result<()> {
    let IpNextProtocol::Udp = next_protocol else {
        bail!("Expected UDP, but packet was {next_protocol:?}");
    };

    let ip_payload_len = payload.len();
    let udp =
        Udp::<[u8]>::try_ref_from_bytes(payload).map_err(|e| eyre!("Bad UDP packet: {e:?}"))?;

    let udp_len = usize::from(udp.header.length.get());
    if udp_len != ip_payload_len {
        return Err(eyre!("UDP header: {:?}", udp.header)).wrap_err_with(|| {
            eyre!(
                "UDP header length did not match IP payload length: {} != {}",
                udp_len,
                ip_payload_len,
            )
        });
    }

    // NOTE: Do not bother to validate checksums, because WireGuard will fail to decapsulate
    // invalid packets anyway

    Ok(())
}

impl<Kind> Deref for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    type Target = Kind;

    fn deref(&self) -> &Self::Target {
        Self::Target::try_ref_from_bytes(&self.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

// Don't use `derive`, because that would require `Kind` to be `Clone`.
impl<Kind> Clone for Packet<Kind> {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            _kind: PhantomData,
        }
    }
}
