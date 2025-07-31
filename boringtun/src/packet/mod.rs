use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use bytes::BytesMut;
use either::Either;
use eyre::{Context, bail, eyre};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

mod ip;
mod ipv4;
mod ipv6;
mod pool;
mod udp;
mod util;

pub use ip::*;
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
/// [Packet] uses [BytesMut] as the backing buffer.
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
pub struct Packet<Kind: ?Sized = [u8]> {
    inner: PacketInner,

    /// Marker type defining what type `Bytes` is.
    ///
    /// INVARIANT:
    /// `buf` must have been ensured to actually contain a packet of this type.
    _kind: PhantomData<Kind>,
}

pub struct PacketInner {
    buf: BytesMut,

    // If the [BytesMut] was allocated by a [PacketBufPool], this will return the buffer to be re-used later.
    _return_to_pool: Option<ReturnToPool>,
}

/// A marker trait that indicates that a [Packet] contains a valid payload of a specific type.
///
/// For example, [CheckedPayload] is implemented for [`Ipv4<[u8]>`], and a [`Packet<Ipv4<[u8]>>>`]
/// can only be constructed through [`Packet::<[u8]>::try_into_ip`], which checks that the IPv4
/// header is valid.
pub trait CheckedPayload: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

impl CheckedPayload for [u8] {}
impl CheckedPayload for Ip {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv6<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Ipv4<P> {}
impl<P: CheckedPayload + ?Sized> CheckedPayload for Udp<P> {}

impl<T: CheckedPayload + ?Sized> Packet<T> {
    fn cast<Y: CheckedPayload + ?Sized>(self) -> Packet<Y> {
        Packet {
            inner: self.inner,
            _kind: PhantomData::<Y>,
        }
    }

    pub fn into_bytes(self) -> Packet<[u8]> {
        self.cast()
    }

    fn buf(&self) -> &[u8] {
        &self.inner.buf
    }
}

impl Packet<[u8]> {
    pub fn new_from_pool(return_to_pool: ReturnToPool, bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: Some(return_to_pool),
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn from_bytes(bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: None,
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::from(bytes),
                _return_to_pool: None,
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    pub fn truncate(&mut self, new_len: usize) {
        self.inner.buf.truncate(new_len);
    }

    pub fn try_into_ip(self) -> eyre::Result<Packet<Ip>> {
        let buf_len = self.buf().len();

        // IPv6 packets are larger, but their length after we know the packet IP version.
        // This is the smallest any packet can be.
        if buf_len < Ipv4Header::LEN {
            bail!("Packet too small ({buf_len} < {})", Ipv4Header::LEN);
        }

        // we have asserted that the packet is long enough to _maybe_ be an IP packet.
        Ok(self.cast::<Ip>())
    }

    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        self.try_into_ip()?.try_into_ipvx()
    }
}

impl Packet<Ip> {
    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        match self.header.version() {
            4 => {
                let buf_len = self.buf().len();

                let ipv4 = Ipv4::<[u8]>::try_ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv4 packet: {e:?}"))?;

                let ip_len = usize::from(ipv4.header.total_len.get());
                if ip_len != buf_len {
                    bail!("IPv4 `total_len` did not match packet length: {ip_len} != {buf_len}");
                }

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv4 packet.
                // update `_kind` to reflect this.
                Ok(Either::Left(self.cast::<Ipv4>()))
            }
            6 => {
                let ipv6 = Ipv6::<[u8]>::try_ref_from_bytes(self.buf())
                    .map_err(|e| eyre!("Bad IPv6 packet: {e:?}"))?;

                let payload_len = usize::from(ipv6.header.payload_length.get());
                if payload_len != ipv6.payload.len() {
                    bail!(
                        "IPv6 `payload_len` did not match packet length: {payload_len} != {}",
                        ipv6.payload.len()
                    );
                }

                // TODO: validate checksum

                // we have asserted that the packet is a valid IPv6 packet.
                // update `_kind` to reflect this.
                Ok(Either::Right(self.cast::<Ipv6>()))
            }
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
        Ok(self.cast::<Ipv4<Udp>>())
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
        Ok(self.cast::<Ipv6<Udp>>())
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

    // TODO: validate checksum?

    Ok(())
}

impl<Kind> Deref for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    type Target = Kind;

    fn deref(&self) -> &Self::Target {
        Self::Target::try_ref_from_bytes(&self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

impl<Kind> DerefMut for Packet<Kind>
where
    Kind: CheckedPayload + ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        Self::Target::try_mut_from_bytes(&mut self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

/*
// Don't use `derive`, because that would require `Kind` to be `Clone`.
impl<Kind> Clone for Packet<Kind> {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            _kind: PhantomData,
        }
    }
}
 */
