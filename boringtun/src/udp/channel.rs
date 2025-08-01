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

/// An implementation of [IpSend], [IpRecv], and [UdpTransportFactory] using tokio channels.
///
/// Enables connecting one [Device](crate::device::Device) directly to another.
/// Can be used to set up a multi-hop wireguard tunnel.
#[derive(Clone)]
pub struct PacketChannel {
    inner: Arc<PacketChannelInner>,
}

#[derive(Clone, Copy, Debug)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Clone)]
pub struct UdpChannel {
    ip_version: IpVersion,
    source_port: u16,
    connection_id: u32,
    inner: Arc<PacketChannelInner>,
}

pub struct PacketChannelInner {
    source_ip_v4: Ipv4Addr,
    source_ip_v6: Ipv6Addr,

    // FIXME: remove Mutexes
    udp_tx: mpsc::Sender<Packet<Ip>>,
    tun_rx: Mutex<mpsc::Receiver<Packet<Ip>>>,

    tun_tx_v4: mpsc::Sender<Packet<Ipv4<Udp>>>,
    udp_rx_v4: Mutex<mpsc::Receiver<Packet<Ipv4<Udp>>>>,

    tun_tx_v6: mpsc::Sender<Packet<Ipv6<Udp>>>,
    udp_rx_v6: Mutex<mpsc::Receiver<Packet<Ipv6<Udp>>>>,
}

impl PacketChannel {
    pub fn new(capacity: usize, source_ip_v4: Ipv4Addr, source_ip_v6: Ipv6Addr) -> Self {
        let (udp_tx, tun_rx) = mpsc::channel(capacity);
        let (tun_tx_v4, udp_rx_v4) = mpsc::channel(capacity);
        let (tun_tx_v6, udp_rx_v6) = mpsc::channel(capacity);

        let tun_rx = Mutex::new(tun_rx);
        let udp_rx_v4 = Mutex::new(udp_rx_v4);
        let udp_rx_v6 = Mutex::new(udp_rx_v6);

        Self {
            inner: Arc::new(PacketChannelInner {
                source_ip_v4,
                source_ip_v6,

                udp_tx,
                tun_rx,

                tun_tx_v4,
                udp_rx_v4,

                tun_tx_v6,
                udp_rx_v6,
            }),
        }
    }
}

impl IpSend for PacketChannel {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        let ip_packet = match packet.try_into_ipvx() {
            Ok(p) => p,
            Err(e) => {
                log::trace!("Invalid IP packet: {e:?}");
                return Ok(());
            }
        };

        match ip_packet {
            Either::Left(ipv4) => match ipv4.try_into_udp() {
                Ok(udp_packet) => {
                    self.inner
                        .tun_tx_v4
                        .send(udp_packet)
                        .await
                        .expect("receiver exists");
                }
                Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
            },
            Either::Right(ipv6) => match ipv6.try_into_udp() {
                Ok(udp_packet) => {
                    self.inner
                        .tun_tx_v6
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

impl IpRecv for PacketChannel {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut tun_rx = self
            .inner
            .tun_rx
            .try_lock()
            .expect("multiple concurrent calls to recv");
        let packet = tun_rx.recv().await.expect("sender exists");
        Ok(iter::once(packet))
    }
}

impl UdpTransportFactory for PacketChannel {
    type Send = Arc<UdpChannel>;
    type Recv = Arc<UdpChannel>;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::Recv), (Self::Send, Self::Recv))> {
        let connection_id = rand_core::OsRng.next_u32().max(1);
        let source_port = match params.port {
            0 => rand_u16().max(1),
            p => p,
        };

        let channel_v4 = Arc::new(UdpChannel {
            ip_version: IpVersion::V4,
            source_port,
            connection_id,
            inner: self.inner.clone(),
        });

        let channel_v6 = Arc::new(UdpChannel {
            ip_version: IpVersion::V6,
            source_port,
            connection_id,
            inner: self.inner.clone(),
        });

        Ok((
            (channel_v4.clone(), channel_v4),
            (channel_v6.clone(), channel_v6),
        ))
    }
}

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

impl UdpTransport for Arc<UdpChannel> {}

impl UdpSend for Arc<UdpChannel> {
    type SendManyBuf = ();

    async fn send_to(&self, udp_payload: Packet, destination: SocketAddr) -> io::Result<()> {
        // send an IP packet on the channel.
        // the IP and UDP headers will need to be added to `udp_payload`

        match destination {
            SocketAddr::V4(dest) => {
                self.inner
                    .udp_tx
                    .send(
                        create_ipv4_payload(
                            self.inner.source_ip_v4,
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
                self.inner
                    .udp_tx
                    .send(
                        create_ipv6_payload(
                            &self.inner.source_ip_v6,
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

impl UdpRecv for Arc<UdpChannel> {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.ip_version {
            IpVersion::V4 => {
                let mut udp_rx = self
                    .inner
                    .udp_rx_v4
                    .try_lock()
                    .expect("multiple concurrent calls to recv_from");

                let ipv4 = udp_rx.recv().await.expect("sender exists");

                let udp = &ipv4.payload;

                let source_addr = ipv4.header.source();
                let source_port = udp.header.source_port.get();
                let source_addr = SocketAddr::from((source_addr, source_port));

                let len = udp.payload.len().min(buf.len());

                buf[..len].copy_from_slice(&udp.payload);

                Ok((len, source_addr))
            }

            IpVersion::V6 => {
                let mut udp_rx = self
                    .inner
                    .udp_rx_v6
                    .try_lock()
                    .expect("multiple concurrent calls to recv_from");

                let ipv6 = udp_rx.recv().await.expect("sender exists");
                let udp = &ipv6.payload;

                let source_addr = ipv6.header.source();
                let source_port = udp.header.source_port.get();
                let source_addr = SocketAddr::from((source_addr, source_port));

                let len = udp.payload.len().min(buf.len());

                buf[..len].copy_from_slice(&udp.payload);

                Ok((len, source_addr))
            }
        }
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

    let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv4.header =
        Ipv4Header::new_for_length(source_ip, destination_ip, IpNextProtocol::Udp, udp_len);

    static NEXT_ID: AtomicU16 = AtomicU16::new(1);
    ipv4.header.identification = NEXT_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .into();

    // TODO: Remove dependency on pnet_packet
    let ipv4_checksum = pnet_packet::util::checksum(ipv4.header.as_bytes(), 5);
    ipv4.header.header_checksum = ipv4_checksum.into();

    let mut payload = packet.split_off(IPV4_HEADER_LEN);

    let udp = Udp::<[u8]>::mut_from_bytes(&mut payload).expect("bad UDP packet buffer");
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

    packet.unsplit(payload);

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

    let ipv6 = Ipv6::<[u8]>::mut_from_bytes(&mut packet).expect("bad IP packet buffer");
    ipv6.header.set_version(6);
    ipv6.header.set_flow_label(connection_id);
    ipv6.header.next_header = IpNextProtocol::Udp;
    ipv6.header.source_address = source_ip.to_bits().into();
    ipv6.header.destination_address = destination_ip.to_bits().into();
    ipv6.header.hop_limit = 64;

    let mut payload = packet.split_off(IPV6_HEADER_LEN);

    let udp = Udp::<[u8]>::mut_from_bytes(&mut payload).expect("bad UDP packet buffer");
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

    packet.unsplit(payload);
    Packet::from_bytes(packet)
        .try_into_ip()
        .expect("packet is valid")
}

fn rand_u16() -> u16 {
    u16::try_from(rand_core::OsRng.next_u32().overflowing_shr(16).0).unwrap()
}
