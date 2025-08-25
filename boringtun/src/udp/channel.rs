use bytes::BytesMut;
use either::Either;
use pnet_packet::ip::IpNextHeaderProtocols;
use rand_core::RngCore;
use std::{
    io, iter,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic::AtomicU16},
};
use tokio::sync::{Mutex, mpsc};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    packet::{Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Packet, PacketBufPool, Udp},
    tun::{IpRecv, IpSend},
    udp::{UdpRecv, UdpSend, UdpTransport, UdpTransportFactory},
};

use super::UdpTransportFactoryParams;
pub use fragmentation::Ipv4Fragments;

/// An implementation of [`IpRecv`] using tokio channels. Create using
/// [`get_packet_channels`].
pub struct TunChannelRx {
    tun_rx: mpsc::Receiver<Packet<Ip>>,
}

/// An implementation of [`IpSend`] using tokio channels. Create using
/// [`get_packet_channels`].
pub struct TunChannelTx {
    tun_tx_v4: mpsc::Sender<Packet<Ipv4<Udp>>>,
    tun_tx_v6: mpsc::Sender<Packet<Ipv6<Udp>>>,

    /// A map of fragments, keyed by a tuple of (identification, source IP, destination IP).
    /// The value is a BTreeMap of fragment offsets to the corresponding fragments.
    /// The BTreeMap is used to ensure that fragments are kept in order, even if they arrive out of
    /// order. This is used to efficiently check if all fragments have been received.
    fragments_v4: Ipv4Fragments,
    // TODO: Ipv6 fragments?
}

/// An implementation of [`UdpSend`] using tokio channels. Create using
/// [`get_packet_channels`].
#[derive(Clone)]
pub struct UdpChannelTx {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
    source_port: u16,
    connection_id: u32,

    udp_tx: mpsc::Sender<Packet<Ip>>,
}

type Ipv4UdpReceiver = mpsc::Receiver<Packet<Ipv4<Udp>>>;
type Ipv6UdpReceiver = mpsc::Receiver<Packet<Ipv6<Udp>>>;

/// An implementation of [`UdpRecv`] for IPv4 UDP packets. Create using
/// [`get_packet_channels`].
pub struct UdpChannelV4Rx {
    /// The receiver for IPv4 UDP packets. Is always `Some` until drop.
    udp_rx_v4: Option<Ipv4UdpReceiver>,
    /// Shared memory with `PacketChannelUdp` to return the receiver after drop.
    return_udp_rx_v4: Arc<Mutex<Option<Ipv4UdpReceiver>>>,
}

impl Drop for UdpChannelV4Rx {
    fn drop(&mut self) {
        // Return the receiver to `PacketChannelUdp`
        *self
            .return_udp_rx_v4
            .try_lock()
            .expect("multiple concurrent calls to drop") = self.udp_rx_v4.take();
    }
}

/// An implementation of [`UdpRecv`] for IPv6 UDP packets. Create using
/// [`get_packet_channels`].
pub struct UdpChannelV6Rx {
    /// The receiver for IPv6 UDP packets. Is always `Some` until drop.
    udp_rx_v6: Option<Ipv6UdpReceiver>,
    /// Shared memory with `PacketChannelUdp` to return the receiver after drop.
    return_udp_rx_v6: Arc<Mutex<Option<Ipv6UdpReceiver>>>,
}

impl Drop for UdpChannelV6Rx {
    fn drop(&mut self) {
        // Return the receiver to `PacketChannelUdp`
        *self
            .return_udp_rx_v6
            .try_lock()
            .expect("multiple concurrent calls to drop") = self.udp_rx_v6.take();
    }
}

/// An implementation of [`UdpTransportFactory`], producing [`UdpSend`] and
/// [`UdpRecv`] implementations that use channels to send and receive packets.
pub struct PacketChannelUdp {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,

    udp_tx: mpsc::Sender<Packet<Ip>>,
    udp_rx_v4: Arc<Mutex<Option<Ipv4UdpReceiver>>>,
    udp_rx_v6: Arc<Mutex<Option<Ipv6UdpReceiver>>>,
}

/// Create a set of channel-based TUN and UDP endpoints for in-process device communication.
///
/// This function returns a tuple of (TunChannelTx, TunChannelRx, PacketChannelUdp), which can be used
/// to connect two [`Device`]s (e.g. for a multihop tunnel or for testing) entirely in memory.
///
/// # Arguments
/// * `capacity` - The channel buffer size for each direction.
/// * `source_ip_v4` - The IPv4 address to use as the source for outgoing packets.
/// * `source_ip_v6` - The IPv6 address to use as the source for outgoing packets.
///
/// # Returns
/// A tuple of (TunChannelTx, TunChannelRx, PacketChannelUdp).
///
/// # Example
/// ```no_run
/// use boringtun::udp::channel::{get_packet_channels, TunChannelTx, TunChannelRx, PacketChannelUdp};
/// use boringtun::device::{DeviceHandle, DeviceConfig};
/// use std::net::{Ipv4Addr, Ipv6Addr};
/// use std::sync::Arc;
/// use tokio::runtime::Runtime;
///
/// let capacity = 100;
/// let source_v4 = Ipv4Addr::new(10, 0, 0, 1);
/// let source_v6 = Ipv6Addr::UNSPECIFIED;
/// let (tun_tx, tun_rx, udp_channels) = get_packet_channels(capacity, source_v4, source_v6);
///
/// // Create entry and exit devices using the returned channels
/// let entry_device = DeviceHandle::new(UdpSocketFactory, tun_tx, tun_rx, /* device_config */);
/// let exit_device = DeviceHandle::new(udp_channels, Arc::new(/* async_tun */), Arc::new(/* async_tun */), /* device_config */);
/// // Now entry_device and exit_device can communicate in-process via the channels.
/// ```
///
pub fn get_packet_channels(
    capacity: usize,
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
) -> (TunChannelTx, TunChannelRx, PacketChannelUdp) {
    let (udp_tx, tun_rx) = mpsc::channel(capacity);
    let (tun_tx_v4, udp_rx_v4) = mpsc::channel(capacity);
    let (tun_tx_v6, udp_rx_v6) = mpsc::channel(capacity);
    let tun_tx = TunChannelTx {
        tun_tx_v4,
        tun_tx_v6,

        fragments_v4: Ipv4Fragments::default(),
    };
    let tun_rx = TunChannelRx { tun_rx };
    let udp_channel_factory = PacketChannelUdp {
        source_ip_v4,
        source_ip_v6,
        udp_tx,
        udp_rx_v4: Arc::new(Mutex::new(Some(udp_rx_v4))),
        udp_rx_v6: Arc::new(Mutex::new(Some(udp_rx_v6))),
    };
    (tun_tx, tun_rx, udp_channel_factory)
}

impl IpSend for TunChannelTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let ip_packet = match packet.try_into_ipvx() {
            Ok(p) => p,
            Err(e) => {
                log::trace!("Invalid IP packet: {e:?}");
                return Ok(());
            }
        };

        match ip_packet {
            Either::Left(ipv4) => {
                let ipv4 = if ipv4.header.fragment_offset() == 0 && !ipv4.header.more_fragments() {
                    ipv4
                } else if let Some(ipv4) = self.fragments_v4.assemble_ipv4_fragment(ipv4) {
                    ipv4
                } else {
                    // No complete IPv4 packet was reassembled, nothing to do
                    return Ok(());
                };

                match ipv4.try_into_udp() {
                    Ok(udp_packet) => {
                        self.tun_tx_v4
                            .send(udp_packet)
                            .await
                            .expect("receiver exists");
                    }
                    Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
                }
            }
            Either::Right(ipv6) => match ipv6.try_into_udp() {
                Ok(udp_packet) => {
                    self.tun_tx_v6
                        .send(udp_packet)
                        .await
                        .expect("receiver exists");
                }
                Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
            },
        }

        Ok(())
    }
}

impl IpRecv for TunChannelRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let Some(packet) = self.tun_rx.recv().await else {
            log::trace!("tun_rx sender dropped and no more packet can be received");
            let () = std::future::pending().await;
            unreachable!();
        };
        Ok(iter::once(packet))
    }
}

impl UdpTransportFactory for PacketChannelUdp {
    type Send = UdpChannelTx;
    type RecvV4 = UdpChannelV4Rx;
    type RecvV6 = UdpChannelV6Rx;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::RecvV4), (Self::Send, Self::RecvV6))> {
        let connection_id = rand_core::OsRng.next_u32().max(1);
        let source_port = match params.port {
            0 => rand::random_range(1u16..u16::MAX),
            p => p,
        };

        let channel_tx = UdpChannelTx {
            source_ip_v4: self.source_ip_v4,
            source_ip_v6: self.source_ip_v6,
            source_port,
            connection_id,
            udp_tx: self.udp_tx.clone(),
        };

        let channel_rx_v4 = UdpChannelV4Rx {
            return_udp_rx_v4: self.udp_rx_v4.clone(),
            udp_rx_v4: self.udp_rx_v4.clone().lock().await.take(),
        };
        let channel_rx_v6 = UdpChannelV6Rx {
            return_udp_rx_v6: self.udp_rx_v6.clone(),
            udp_rx_v6: self.udp_rx_v6.clone().lock().await.take(),
        };
        Ok((
            (channel_tx.clone(), channel_rx_v4),
            (channel_tx, channel_rx_v6),
        ))
    }
}

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV4_MAX_LEN: usize = 65535;

impl UdpTransport for UdpChannelTx {}

impl UdpSend for UdpChannelTx {
    type SendManyBuf = ();

    async fn send_to(&self, udp_payload: Packet, destination: SocketAddr) -> io::Result<()> {
        // send an IP packet on the channel.
        // the IP and UDP headers will need to be added to `udp_payload`

        match destination {
            SocketAddr::V4(dest) => {
                self.udp_tx
                    .send(
                        create_ipv4_payload(
                            self.source_ip_v4,
                            self.source_port,
                            *dest.ip(),
                            dest.port(),
                            &udp_payload,
                        )
                        .await,
                    )
                    .await
                    .expect("receiver exists");
            }
            SocketAddr::V6(dest) => {
                self.udp_tx
                    .send(
                        create_ipv6_payload(
                            &self.source_ip_v6,
                            self.source_port,
                            dest.ip(),
                            dest.port(),
                            &udp_payload,
                            self.connection_id,
                        )
                        .await,
                    )
                    .await
                    .expect("receiver exists");
            }
        }

        Ok(())
    }
}
impl UdpRecv for UdpChannelV4Rx {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let ipv4 = self
            .udp_rx_v4
            .as_mut()
            .expect("UdpChannelV4Rx holds sender for its entire lifetime")
            .recv()
            .await
            .expect("sender exists");

        let source_addr = ipv4.header.source();

        let udp = ipv4.into_payload();
        let source_port = udp.header.source_port.get();

        // Packet with IP and UDP headers shed.
        let inner_packet = udp.into_payload();
        let socket_addr = SocketAddr::from((source_addr, source_port));

        Ok((inner_packet, socket_addr))
    }
}

impl UdpRecv for UdpChannelV6Rx {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let ipv6 = self
            .udp_rx_v6
            .as_mut()
            .expect("UdpChannelV4Rx holds sender for its entire lifetime")
            .recv()
            .await
            .expect("sender exists");

        let source_addr = ipv6.header.source();

        let udp = ipv6.into_payload();
        let source_port = udp.header.source_port.get();

        // Packet with IP and UDP headers shed.
        let inner_packet = udp.into_payload();
        let socket_addr = SocketAddr::from((source_addr, source_port));

        Ok((inner_packet, socket_addr))
    }
}

async fn create_ipv4_payload(
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    udp_payload: &[u8],
) -> Packet<Ip> {
    let udp_len: u16 = (UDP_HEADER_LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(IPV4_HEADER_LEN).unwrap() + udp_len;

    let mut packet = BytesMut::zeroed(usize::from(total_len));

    let ipv4 = Ipv4::<Udp>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv4.header =
        Ipv4Header::new_for_length(source_ip, destination_ip, IpNextProtocol::Udp, udp_len);

    static NEXT_ID: AtomicU16 = AtomicU16::new(1);
    ipv4.header.identification = NEXT_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .into();

    // TODO: Remove dependency on pnet_packet
    let ipv4_checksum = pnet_packet::util::checksum(ipv4.header.as_bytes(), 5);
    ipv4.header.header_checksum = ipv4_checksum.into();

    let udp = &mut ipv4.payload;
    udp.header.source_port = source_port.into();
    udp.header.destination_port = destination_port.into();
    udp.header.length = udp_len.into();
    udp.payload.copy_from_slice(udp_payload);

    // TODO: Remove dependency on pnet_packet
    let csum = pnet_packet::util::ipv4_checksum(
        udp.as_bytes(),
        3,
        &[],
        &source_ip,
        &destination_ip,
        IpNextHeaderProtocols::Udp,
    );
    udp.header.checksum = csum.into();

    Packet::from_bytes(packet)
        .try_into_ip()
        .expect("packet is valid")
}

async fn create_ipv6_payload(
    source_ip: &Ipv6Addr,
    source_port: u16,
    destination_ip: &Ipv6Addr,
    destination_port: u16,
    udp_payload: &[u8],
    connection_id: u32,
) -> Packet<Ip> {
    let udp_len: u16 = (UDP_HEADER_LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(IPV6_HEADER_LEN).unwrap() + udp_len;

    let mut packet = BytesMut::zeroed(usize::from(total_len));

    let ipv6 = Ipv6::<Udp>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv6.header.set_version(6);
    ipv6.header.set_flow_label(connection_id);
    ipv6.header.next_header = IpNextProtocol::Udp;
    ipv6.header.source_address = source_ip.to_bits().into();
    ipv6.header.destination_address = destination_ip.to_bits().into();
    ipv6.header.hop_limit = 64;

    let udp = &mut ipv6.payload;
    udp.header.source_port = source_port.into();
    udp.header.destination_port = destination_port.into();
    udp.header.length = udp_len.into();
    udp.payload.copy_from_slice(udp_payload);

    // TODO: Remove dependency on pnet_packet
    let csum = pnet_packet::util::ipv6_checksum(
        udp.as_bytes(),
        3,
        &[],
        source_ip,
        destination_ip,
        IpNextHeaderProtocols::Udp,
    );
    udp.header.checksum = csum.into();

    Packet::from_bytes(packet)
        .try_into_ip()
        .expect("packet is valid")
}

mod fragmentation {
    use zerocopy::{FromBytes, FromZeros};

    use crate::{
        packet::Udp,
        udp::channel::{IPV4_HEADER_LEN, IPV4_MAX_LEN},
    };
    use std::{collections::VecDeque, net::Ipv4Addr};

    use crate::packet::{Ipv4, Packet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct FragmentId {
        identification: u16,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
    }

    // TODO: Switch to a total memory limit
    /// The maximum number of unique fragmented IPv4 that can be concurrently assembled.
    /// When this limit is reached, the fragments belonging to the oldest packet is dropped
    /// to make space.
    ///
    /// The sum of all fragments for a given packet cannot exceed the maximum IPv4 length,
    /// which is 65535 bytes. In total, this means that the maximum size that can be
    /// buffered is 64 * 65535 = 4194304 bytes, or 4 MiB.
    const MAX_CONCURRENT_FRAGS: usize = 64;

    #[derive(Debug)]
    pub struct Ipv4Fragments {
        // The `VecDeque` is holds the fragments for each unique packet being assembled.
        // It is also a FIFO queue, so that the oldest fragments are dropped when the maximum
        // number of fragments is reached. The inner `Vec` is used to store the fragments.
        // INVARIANT: The inner `Vec` must always be sorted by fragment_offset
        fragments: VecDeque<(FragmentId, Vec<Packet<Ipv4>>)>,
    }

    impl Default for Ipv4Fragments {
        fn default() -> Self {
            Self {
                fragments: VecDeque::with_capacity(MAX_CONCURRENT_FRAGS),
            }
        }
    }

    impl Ipv4Fragments {
        /// Return the number of unique packets that are currently being assembled.
        pub fn incomplete_packet_count(&self) -> usize {
            self.fragments.len()
        }

        pub fn assemble_ipv4_fragment(
            &mut self,
            ipv4_packet: Packet<Ipv4>,
        ) -> Option<Packet<Ipv4>> {
            let fragment_map = &mut self.fragments;
            let header = ipv4_packet.header;
            let fragment_offset = header.fragment_offset();
            let more_fragments = header.more_fragments();
            debug_assert!(more_fragments || fragment_offset != 0);

            // All fragments except the last must have a length that is a multiple of 8
            // bytes, and the last fragment must not exceed the maximum IPv4 length.
            let fragment_len = ipv4_packet.payload.len();
            if (more_fragments && fragment_len % 8 != 0)
                || fragment_len + fragment_offset as usize * 8 > IPV4_MAX_LEN
            {
                log::trace!(
                    "Invalid fragment size: {fragment_len} or fragment offset: {fragment_offset}, dropping"
                );
                return None;
            }

            let id = get_frag_id(&ipv4_packet);

            let Some(frag_pos) = fragment_map.iter_mut().position(|(id2, _)| id2 == &id) else {
                if fragment_map.len() >= MAX_CONCURRENT_FRAGS {
                    let (dropped_id, _) =
                        fragment_map.pop_front().expect("Fragment map is not empty");
                    log::trace!(
                        "Fragment map at full capacity {MAX_CONCURRENT_FRAGS}, dropping oldest fragment with ID {dropped_id:?} to make space"
                    );
                    // TODO: send "Fragment Reassembly Timeout" ICMP message, per RFC792
                }
                // Since this was the first fragment, we don't check if the packet
                // can be reassembled yet.
                fragment_map.push_back((id, vec![ipv4_packet]));
                return None;
            };
            let (_, fragments) = fragment_map
                .get_mut(frag_pos)
                .expect("Fragment exists because of the above check");

            // Check if the fragment with the same offset already exists.
            let Err(i) =
                fragments.binary_search_by_key(&fragment_offset, |f| f.header.fragment_offset())
            else {
                log::trace!(
                    "Fragment with offset {fragment_offset} already existed for for ID {id:?} and was dropped"
                );
                return None;
            };

            // Check if the new fragment overlaps with existing fragments.
            // Note that the fragments are sorted by fragment_offset, so we only need to check
            // the previous and next fragments.
            if let Some(prev_i) = i.checked_sub(1)
                && let prev_frag_offset = &fragments[prev_i].header.fragment_offset()
                && let prev_frag_len = &fragments[prev_i].payload.len()
                && prev_frag_offset + (prev_frag_len / 8) as u16 > fragment_offset
            {
                log::trace!(
                    "Fragment with offset {fragment_offset} overlaps with existing fragment with offset {prev_frag_offset} and length {prev_frag_len} for ID {id:?}, dropping",
                );
                return None;
            }
            if let Some(next_frag) = fragments.get(i)
                && let next_frag_offset = next_frag.header.fragment_offset()
                && fragment_offset + (fragment_len / 8) as u16 > next_frag_offset
            {
                log::trace!(
                    "Fragment with offset {fragment_offset} and length {fragment_len} overlaps with existing fragment with offset {next_frag_offset} for ID {id:?}, dropping",
                );
                return None;
            }

            fragments.insert(i, ipv4_packet);

            let [first, .., last] = &fragments[..] else {
                unreachable!("There are at least 2 fragments.");
            };
            // Check that we have the first and last fragment
            if last.header.more_fragments() || first.header.fragment_offset() != 0 {
                return None;
            }

            // Check if the IP packet can be reassembled.
            // The fragments must be consecutive, i.e. each fragment must begin where the previous one ended.
            // Note that fragment offset is given in units of 8 bytes.
            let fragment_offsets = fragments.iter().map(|f| f.header.fragment_offset());
            let fragment_ends = fragments
                .iter()
                .map(|f| f.header.fragment_offset() + (f.payload.len() / 8) as u16);
            if !fragment_offsets
                .skip(1)
                .eq(fragment_ends.take(fragments.len() - 1))
            {
                return None;
            }

            let len =
                last.header.fragment_offset() as usize * 8 + last.payload.len() + IPV4_HEADER_LEN;
            let (_, packet_fragments) = fragment_map
                .remove(frag_pos)
                .expect("The same fragment as we accessed above must exist");
            // To potentially avoid allocating a new packet, we will use the first fragment
            // and extend it with the payloads of the other fragments.
            let mut remaining_fragments = packet_fragments.into_iter();
            let first_packet = remaining_fragments
                .next()
                .expect("At least one fragment exists");

            let mut bytes = first_packet.into_bytes();
            let additional_bytes_needed = len.saturating_sub(bytes.buf_mut().len());
            bytes.buf_mut().reserve(additional_bytes_needed);
            for frag in remaining_fragments {
                bytes.buf_mut().extend_from_slice(&frag.payload);
            }

            // The header of the first packet is updated to reflect that the packet is no
            // longer fragmented.
            {
                let ip = Ipv4::<Udp>::mut_from_bytes(&mut bytes).expect("valid IP packet buffer");
                ip.header.total_len = (len as u16).into();

                // This set `more_fragments`, `dont_fragment`, and `fragment_offset` to zero.
                ip.header.flags_and_fragment_offset.zero();

                // We do not need to recompute the checksum, because the checksum is
                // only read by the `ExitDevice` and discarded
                ip.header.header_checksum.zero();
            }

            // NOTE: We could change the `tun_tx_vx` channels to take a tuple of source ip,
            // destination ip, and `Packet<Udp>`, instead of `Packet<Ipv4<Udp>>`, to avoid
            // having to reconstruct the IP head and validate the IP packet with
            // `try_into_ipvx`
            Some(
                bytes
                    .try_into_ipvx()
                    .expect("Previously valid Ipv4 packet should still be valid")
                    .unwrap_left(),
            )
        }
    }

    fn get_frag_id(ipv4_packet: &Packet<Ipv4>) -> FragmentId {
        FragmentId {
            identification: ipv4_packet.header.identification.get(),
            source_ip: ipv4_packet.header.source(),
            destination_ip: ipv4_packet.header.destination(),
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::packet::{IpNextProtocol, Ipv4FlagsFragmentOffset, Ipv4Header};
        use crate::udp::channel::{IPV4_HEADER_LEN, UDP_HEADER_LEN};
        use bytes::BytesMut;
        use rand::rng;
        use rand::seq::SliceRandom;
        use std::collections::HashMap;
        use std::net::Ipv4Addr;
        use zerocopy::IntoBytes;

        fn make_ip_fragment(
            identification: u16,
            source_ip: Ipv4Addr,
            destination_ip: Ipv4Addr,
            offset: u16,
            more_fragments: bool,
            payload: &[u8],
        ) -> Packet<Ipv4> {
            // Build a minimal UDP payload
            let total_len = IPV4_HEADER_LEN + payload.len();
            let mut buf = BytesMut::zeroed(total_len);
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(
                source_ip,
                destination_ip,
                IpNextProtocol::Udp,
                payload.len() as u16,
            );
            ipv4.header.identification = identification.into();
            let mut flags = Ipv4FlagsFragmentOffset::new();
            flags.set_more_fragments(more_fragments);
            flags.set_fragment_offset(offset);
            ipv4.header.flags_and_fragment_offset = flags;
            ipv4.payload.copy_from_slice(payload);

            Packet::from_bytes(buf)
                .try_into_ipvx()
                .unwrap()
                .unwrap_left()
        }

        fn make_udp_bytes(payload: &[u8]) -> BytesMut {
            let len = UDP_HEADER_LEN + payload.len();
            let mut buf = BytesMut::zeroed(len);
            let udp = Udp::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (len as u16).into();
            udp.header.checksum = 0.into();
            assert_eq!(udp.payload.len(), payload.len());
            udp.payload.copy_from_slice(payload);
            buf
        }

        #[test]
        fn test_ipv4_defragmentation() {
            let mut fragments = Ipv4Fragments::default();
            let src1 = Ipv4Addr::new(10, 0, 0, 1);
            let dst1 = Ipv4Addr::new(10, 0, 0, 2);
            let src2 = Ipv4Addr::new(10, 0, 0, 3);
            let dst2 = Ipv4Addr::new(10, 0, 0, 4);
            let id1 = 100;
            let id2 = 200;
            // Two packets
            let payload1 = make_udp_bytes(b"ABCDEFGHIJKLMN");
            let payload2 = make_udp_bytes(b"MY SLIGHTLY LONGER PACKET");

            // Split each into 3 fragments
            let mut all_frags = vec![
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 0, true, &payload1[0..8]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 1, true, &payload1[8..16]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 2, false, &payload1[16..]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 0, true, &payload2[0..16]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 2, true, &payload2[16..24]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 3, true, &payload2[24..32]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 4, false, &payload2[32..]),
                ),
            ];
            all_frags.shuffle(&mut rng());
            let mut seen = HashMap::new();
            for (id, frag) in all_frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                let count = seen.entry(id).or_insert(0);
                *count += 1;
                if let Some(ip_packet) = res {
                    let udp_packet = ip_packet.try_into_udp().unwrap();
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );

                    if id == id1 {
                        assert_eq!(*count, 3, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload1[..]);
                    } else {
                        assert_eq!(*count, 4, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload2[..]);
                    };
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(
                        udp_packet.header.source(),
                        if id == id1 { src1 } else { src2 }
                    );
                    assert_eq!(
                        udp_packet.header.destination(),
                        if id == id1 { dst1 } else { dst2 }
                    );
                }

                // Last fragment for this id
            }

            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }

        #[test]
        fn test_ipv4_defragmentation_single_packet() {
            let mut fragments = Ipv4Fragments::default();
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 2);
            let id = 42;
            let payload = make_udp_bytes(b"HELLOFRAGMENTS");
            // Split into 3 fragments
            let mut frags = vec![
                make_ip_fragment(id, src, dst, 0, true, &payload[0..8]),
                make_ip_fragment(id, src, dst, 1, true, &payload[8..16]),
                make_ip_fragment(id, src, dst, 2, false, &payload[16..]),
            ];
            frags.shuffle(&mut rng());
            let mut count = 0;
            for frag in frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                count += 1;
                if let Some(ip_packet) = res {
                    let udp_packet = ip_packet.try_into_udp().unwrap();
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );
                    assert_eq!(count, 3, "Should reassemble on last fragment");
                    assert_eq!(udp_packet.payload.as_bytes(), &payload[..]);
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(udp_packet.header.source(), src);
                    assert_eq!(udp_packet.header.destination(), dst);
                } else {
                    assert!(count < 3, "Should not reassemble until last fragment");
                }
            }
            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }

        #[test]
        fn test_fragment_eviction_max_concurrent_frags() {
            let mut fragments = Ipv4Fragments::default();
            let src = Ipv4Addr::new(1, 2, 3, 4);
            let dst = Ipv4Addr::new(5, 6, 7, 8);
            let payload = make_udp_bytes(b"0123456789");

            let id = 1000;
            // Each packet will be split into 2 fragments
            let old_frag_first_half = make_ip_fragment(id, src, dst, 0, true, &payload[0..8]);
            let old_frag_second_half = make_ip_fragment(id, src, dst, 1, false, &payload[8..]);
            // Only insert the first fragment for now
            assert!(
                fragments
                    .assemble_ipv4_fragment(old_frag_first_half)
                    .is_none()
            );

            let mut second_halves = Vec::new();
            for i in 0..super::MAX_CONCURRENT_FRAGS {
                let id = 1000 + i as u16;
                // Each packet will be split into 2 fragments
                let frag1 = make_ip_fragment(id, src, dst, 0, true, &payload[0..8]);
                let frag2 = make_ip_fragment(id, src, dst, 1, false, &payload[8..]);
                // Only insert the first fragment for now
                assert!(fragments.assemble_ipv4_fragment(frag1).is_none());
                second_halves.push(frag2);
            }
            for second_half in second_halves {
                // Insert the second fragment for all but the oldest
                let res = fragments.assemble_ipv4_fragment(second_half);
                assert!(res.is_some(), "Should reassemble remaining fragments");
            }
            assert!(
                fragments
                    .assemble_ipv4_fragment(old_frag_second_half)
                    .is_none(),
                "Should not reassemble oldest fragment, as first half should have been discarded"
            );

            assert_eq!(
                fragments.incomplete_packet_count(),
                1,
                "Only second half of the first packet should be left"
            );
        }

        #[test]
        /// Test that overlapping fragments are detected and dropped.
        fn test_fragmentation_overlap() {
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 2);
            let id = 42;
            let payload = make_udp_bytes(b"HELLOFRAGMENTS");
            // Create two overlapping fragments
            // Note that the `fragmentation_offset` is in units of 8 bytes and should be `2`
            // for the second fragment to not overlap with the first.
            let frag1 = make_ip_fragment(id, src, dst, 0, true, &payload[0..16]);
            let frag2 = make_ip_fragment(id, src, dst, 1, false, &payload[16..]);
            let id = get_frag_id(&frag1);
            let frag_is_buffered = |fragments: &Ipv4Fragments, frag: &Packet<Ipv4>| {
                fragments
                    .fragments
                    .iter()
                    .find(|(id2, _)| id2 == &id)
                    .expect("Fragment ID should exist")
                    .1
                    .iter()
                    .any(|f| f.as_bytes() == frag.as_bytes())
            };

            // Assert that after insert both fragments, no packet is reassembled
            {
                let mut fragments = Ipv4Fragments::default();
                fragments.assemble_ipv4_fragment(frag1.clone());
                assert!(frag_is_buffered(&fragments, &frag1));
                fragments.assemble_ipv4_fragment(frag2.clone());
                assert!(
                    !frag_is_buffered(&fragments, &frag2),
                    "Second fragment should be dropped because it overlaps with the first"
                );
            }

            // Repeat in reverse order
            {
                let mut fragments = Ipv4Fragments::default();
                fragments.assemble_ipv4_fragment(frag2.clone());
                assert!(frag_is_buffered(&fragments, &frag2));
                fragments.assemble_ipv4_fragment(frag1.clone());
                assert!(
                    !frag_is_buffered(&fragments, &frag1),
                    "First fragment should be dropped because it overlaps with the second"
                );
            }
        }
    }
}
