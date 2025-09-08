//! Implementations of [UdpTransport] traits for tokio channels.
//!
//! See [get_packet_channels]

use bytes::BytesMut;
use pnet_packet::ip::IpNextHeaderProtocols;
use rand_core::RngCore;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic::AtomicU16},
};
use tokio::sync::{Mutex, OwnedMutexGuard, mpsc};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    packet::{
        Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv6, Ipv6Header, Packet, PacketBufPool, Udp,
        UdpHeader,
    },
    tun::channel::{Ipv4Fragments, TunChannelRx, TunChannelTx},
    udp::{UdpRecv, UdpSend, UdpTransportFactory},
};

use super::UdpTransportFactoryParams;

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
    /// The receiver for IPv4 UDP packets. Source: [UdpChannelFactory::udp_rx_v4]
    udp_rx_v4: OwnedMutexGuard<Ipv4UdpReceiver>,
}

/// An implementation of [`UdpRecv`] for IPv6 UDP packets. Create using
/// [`get_packet_channels`].
pub struct UdpChannelV6Rx {
    /// The receiver for IPv6 UDP packets. Source: [UdpChannelFactory::udp_rx_v6].
    udp_rx_v6: OwnedMutexGuard<Ipv6UdpReceiver>,
}

/// An implementation of [`UdpTransportFactory`], producing [`UdpSend`] and
/// [`UdpRecv`] implementations that use channels to send and receive packets.
///
/// Calling [UdpChannelFactory::bind] will claim exclusive access to the inner channels for the
/// lifetime of the [UdpChannelTx], [UdpChannelV6Rx] and [UdpChannelV4Rx]. Another call to `bind`
/// will *block* until those have been dropped.
pub struct UdpChannelFactory {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,

    udp_tx: mpsc::Sender<Packet<Ip>>,
    udp_rx_v4: Arc<Mutex<Ipv4UdpReceiver>>,
    udp_rx_v6: Arc<Mutex<Ipv6UdpReceiver>>,
}

/// Create a set of channel-based TUN and UDP endpoints for in-process device communication.
///
/// This function returns a tuple of ([TunChannelTx], [TunChannelRx], [UdpChannelFactory]), which
/// can be used to connect two wireguard devices (e.g. for a multihop tunnel or for testing)
/// entirely in memory.
///
/// # Arguments
/// * `capacity` - The channel buffer size for each direction.
/// * `source_ip_v4` - The IPv4 address to use as the source for outgoing packets.
/// * `source_ip_v6` - The IPv6 address to use as the source for outgoing packets.
///
/// # Example
/// ```ignore
/// use boringtun::{
///     device::{DeviceHandle, DeviceConfig},
///     tun::channel::{TunChannelTx, TunChannelRx},
///     udp::channel::{get_packet_channels, UdpChannelFactory},
///     udp::socket::UdpSocketFactory,
/// };
/// use std::net::{Ipv4Addr, Ipv6Addr};
/// use std::sync::Arc;
/// use tokio::runtime::Runtime;
///
/// let capacity = 100;
/// let source_v4 = Ipv4Addr::new(10, 0, 0, 1);
/// let source_v6 = Ipv6Addr::UNSPECIFIED;
/// let (tun_tx, tun_rx, udp) = get_packet_channels(capacity, source_v4, source_v6);
///
/// // Create entry and exit devices using the returned channels
/// let entry_device = DeviceHandle::new(UdpSocketFactory, tun_tx, tun_rx, /* device_config */);
/// let exit_device = DeviceHandle::new(udp, Arc::new(/* async_tun */), Arc::new(/* async_tun */), /* device_config */);
/// // Now entry_device and exit_device can communicate in-process via the channels.
/// ```
pub fn new_udp_tun_channel(
    capacity: usize,
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,
) -> (TunChannelTx, TunChannelRx, UdpChannelFactory) {
    let (udp_tx, tun_rx) = mpsc::channel(capacity);
    let (tun_tx_v4, udp_rx_v4) = mpsc::channel(capacity);
    let (tun_tx_v6, udp_rx_v6) = mpsc::channel(capacity);
    let tun_tx = TunChannelTx {
        tun_tx_v4,
        tun_tx_v6,

        fragments_v4: Ipv4Fragments::default(),
    };
    let tun_rx = TunChannelRx { tun_rx };
    let udp_channel_factory = UdpChannelFactory {
        source_ip_v4,
        source_ip_v6,
        udp_tx,
        udp_rx_v4: Arc::new(Mutex::new(udp_rx_v4)),
        udp_rx_v6: Arc::new(Mutex::new(udp_rx_v6)),
    };
    (tun_tx, tun_rx, udp_channel_factory)
}

impl UdpTransportFactory for UdpChannelFactory {
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
            udp_rx_v4: self.udp_rx_v4.clone().lock_owned().await,
        };
        let channel_rx_v6 = UdpChannelV6Rx {
            udp_rx_v6: self.udp_rx_v6.clone().lock_owned().await,
        };
        Ok((
            (channel_tx.clone(), channel_rx_v4),
            (channel_tx, channel_rx_v6),
        ))
    }
}

impl UdpSend for UdpChannelTx {
    type SendManyBuf = ();

    async fn send_to(&self, udp_payload: Packet, destination: SocketAddr) -> io::Result<()> {
        // send an IP packet on the channel.
        // the IP and UDP headers will need to be added to `udp_payload`

        let packet = match destination {
            SocketAddr::V4(dest) => create_ipv4_payload(
                self.source_ip_v4,
                self.source_port,
                *dest.ip(),
                dest.port(),
                &udp_payload,
            ),
            SocketAddr::V6(dest) => create_ipv6_payload(
                &self.source_ip_v6,
                self.source_port,
                dest.ip(),
                dest.port(),
                &udp_payload,
                self.connection_id,
            ),
        };

        self.udp_tx.send(packet).await.expect("receiver exists");

        Ok(())
    }
}
impl UdpRecv for UdpChannelV4Rx {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let ipv4 = self.udp_rx_v4.recv().await.expect("sender exists");

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
        let ipv6 = self.udp_rx_v6.recv().await.expect("sender exists");

        let source_addr = ipv6.header.source();

        let udp = ipv6.into_payload();
        let source_port = udp.header.source_port.get();

        // Packet with IP and UDP headers shed.
        let inner_packet = udp.into_payload();
        let socket_addr = SocketAddr::from((source_addr, source_port));

        Ok((inner_packet, socket_addr))
    }
}

fn create_ipv4_payload(
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    udp_payload: &[u8],
) -> Packet<Ip> {
    let udp_len: u16 = (UdpHeader::LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(Ipv4Header::LEN).unwrap() + udp_len;

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

fn create_ipv6_payload(
    source_ip: &Ipv6Addr,
    source_port: u16,
    destination_ip: &Ipv6Addr,
    destination_port: u16,
    udp_payload: &[u8],
    connection_id: u32,
) -> Packet<Ip> {
    let udp_len: u16 = (UdpHeader::LEN + udp_payload.len()).try_into().unwrap();
    let total_len = u16::try_from(Ipv6Header::LEN).unwrap() + udp_len;

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
