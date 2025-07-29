// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;

pub mod api;
#[cfg(unix)]
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

use std::collections::HashMap;
use std::io::{self};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::BitOrAssign;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::join;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::packet::PacketBufPool;
use crate::task::Task;
use crate::tun::buffer::{BufferedIpRecv, BufferedIpSend};
use crate::tun::{IpRecv, IpSend};
use crate::udp::buffer::BufferedUdpTransport;
use crate::udp::{UdpSocketFactory, UdpTransport, UdpTransportFactory, UdpTransportFactoryParams};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};
use rand_core::{OsRng, RngCore};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

/// Maximum number of packet buffers that each channel may contain
const MAX_PACKET_BUFS: usize = 8000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{1}: {0}")]
    Bind(#[source] io::Error, String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
    #[error("Device error: {0}")]
    OpenDevice(#[from] tun::Error),
}

pub struct DeviceHandle<T: DeviceTransports> {
    device: Arc<RwLock<Device<T>>>,
}

#[derive(Default)]
pub struct DeviceConfig {
    pub api: Option<api::ApiServer>,
}

/// By default, use a UDP socket for sending datagrams and a tunnel device for IP packets.
#[cfg(feature = "tun")]
pub type DefaultDeviceTransports = (
    UdpSocketFactory,
    Arc<tun::AsyncDevice>,
    Arc<tun::AsyncDevice>,
);

impl<UF, IS, IR> DeviceTransports for (UF, IS, IR)
where
    UF: UdpTransportFactory,
    IS: IpSend,
    IR: IpRecv,
{
    type UdpTransportFactory = UF;
    type IpSend = IS;
    type IpRecv = IR;
}

pub trait DeviceTransports: 'static {
    type UdpTransportFactory: UdpTransportFactory;
    type IpSend: IpSend;
    type IpRecv: IpRecv;
}

pub struct Device<T: DeviceTransports> {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    fwmark: Option<u32>,

    tun_tx: T::IpSend,
    tun_rx: T::IpRecv,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    rate_limiter: Option<Arc<RateLimiter>>,

    port: u16,
    udp_factory: T::UdpTransportFactory,
    connection: Option<Connection<T>>,

    /// The task that responds to API requests.
    api: Option<Task>,
}

pub(crate) struct Connection<T: DeviceTransports> {
    udp4: Arc<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
    udp6: Arc<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,

    listen_port: Option<u16>,

    /// The task that reads IPv4 traffic from the UDP socket.
    incoming_ipv4: Task,

    /// The task that reads IPv6 traffic from the UDP socket.
    incoming_ipv6: Task,

    /// The task tha handles keepalives/heartbeats/etc.
    timers: Task,

    /// The task that reads traffic from the TUN device.
    outgoing: Task,
}

impl<T: DeviceTransports> Connection<T> {
    pub async fn set_up(device: Arc<RwLock<Device<T>>>) -> Result<Self, Error> {
        let mut device_guard = device.write().await;
        let (udp4, udp6) = device_guard.open_listen_socket().await?;
        drop(device_guard);

        let packet_pool = PacketBufPool::new(MAX_PACKET_BUFS);

        let buffered_udp_v4 =
            BufferedUdpTransport::new(MAX_PACKET_BUFS, udp4.clone(), packet_pool.clone());
        let buffered_udp_v6 =
            BufferedUdpTransport::new(MAX_PACKET_BUFS, udp6.clone(), packet_pool.clone());

        let outgoing = Task::spawn(
            "handle_outgoing",
            Device::handle_outgoing(
                Arc::downgrade(&device),
                buffered_udp_v4.clone(),
                buffered_udp_v6.clone(),
                packet_pool.clone(),
            ),
        );
        let timers = Task::spawn(
            "handle_timers",
            Device::handle_timers(
                Arc::downgrade(&device),
                buffered_udp_v4.clone(),
                buffered_udp_v6.clone(),
            ),
        );

        let incoming_ipv4 = Task::spawn(
            "handle_incoming ipv4",
            Device::handle_incoming(
                Arc::downgrade(&device),
                buffered_udp_v4,
                packet_pool.clone(),
            ),
        );
        let incoming_ipv6 = Task::spawn(
            "handle_incoming ipv6",
            Device::handle_incoming(
                Arc::downgrade(&device),
                buffered_udp_v6.clone(),
                packet_pool,
            ),
        );

        Ok(Connection {
            listen_port: udp4.local_addr()?.map(|sa| sa.port()),
            udp4,
            udp6,
            incoming_ipv4,
            incoming_ipv6,
            timers,
            outgoing,
        })
    }
}

#[cfg(feature = "tun")]
impl DeviceHandle<DefaultDeviceTransports> {
    pub async fn from_tun_name(
        udp_factory: UdpSocketFactory,
        tun_name: &str,
        config: DeviceConfig,
    ) -> Result<DeviceHandle<DefaultDeviceTransports>, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(tun_name);
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        let tun = tun::create_as_async(&tun_config)?;
        let tun_tx = Arc::new(tun);
        let tun_rx = Arc::clone(&tun_tx);
        Ok(DeviceHandle::new(udp_factory, tun_tx, tun_rx, config).await)
    }
}

impl<T: DeviceTransports> DeviceHandle<T> {
    pub async fn new(
        udp_factory: T::UdpTransportFactory,
        tun_tx: T::IpSend,
        tun_rx: T::IpRecv,
        config: DeviceConfig,
    ) -> DeviceHandle<T> {
        DeviceHandle {
            device: Device::new(udp_factory, tun_tx, tun_rx, config).await,
        }
    }

    pub async fn stop(self) {
        Self::stop_inner(self.device.clone()).await
    }

    async fn stop_inner(device: Arc<RwLock<Device<T>>>) {
        log::debug!("Stopping boringtun device");

        let mut device = device.write().await;

        if let Some(api_task) = device.api.take() {
            api_task.stop().await;
        };

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }
    }
}

impl<T: DeviceTransports> Drop for DeviceHandle<T> {
    fn drop(&mut self) {
        log::debug!("Dropping boringtun device");
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::warn!("Failed to get tokio runtime handle");
            return;
        };
        log::info!(
            "DeviceHandle strong count: {}",
            Arc::strong_count(&self.device)
        );
        log::info!("DeviceHandle weak count: {}", Arc::weak_count(&self.device));
        let device = self.device.clone();
        handle.spawn(async move {
            Self::stop_inner(device).await;
        });
    }
}

/// Do we need to reconfigure the socket?
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reconfigure {
    Yes,
    No,
}

impl BitOrAssign for Reconfigure {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = match (*self, rhs) {
            (Reconfigure::No, Reconfigure::No) => Reconfigure::No,
            _ => Reconfigure::Yes,
        };
    }
}

impl<T: DeviceTransports> Device<T> {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.blocking_lock();
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            log::info!("Peer removed");

            Some(peer)
        } else {
            None
        }
    }

    /// Update or add peer
    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        replace_allowed_ips: bool,
        endpoint: Option<SocketAddr>,
        new_allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            self.remove_peer(&pub_key);
            return;
        }

        let (index, old_allowed_ips) = if let Some(old_peer) = self.remove_peer(&pub_key) {
            // TODO: Update existing peer?
            let peer = old_peer.blocking_lock();
            let index = peer.index();
            let old_allowed_ips = peer
                .allowed_ips()
                .map(|(addr, cidr)| AllowedIP { addr, cidr })
                .collect();
            drop(peer);

            // TODO: Match pubkey instead of index
            self.peers_by_ip
                .remove(&|p| p.blocking_lock().index() == index);

            (index, old_allowed_ips)
        } else {
            (self.next_index(), vec![])
        };

        // Update an existing peer or add peer
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            index,
            None,
        );

        let allowed_ips = if !replace_allowed_ips {
            // append old allowed IPs
            old_allowed_ips
                .into_iter()
                .chain(new_allowed_ips.iter().copied())
                .collect()
        } else {
            new_allowed_ips.to_vec()
        };

        let peer = Peer::new(tunn, index, endpoint, &allowed_ips, preshared_key);
        let peer = Arc::new(Mutex::new(peer));

        self.peers_by_idx.insert(index, Arc::clone(&peer));
        self.peers.insert(pub_key, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in &allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        log::info!("Peer added");
    }

    pub async fn new(
        udp_factory: T::UdpTransportFactory,
        tun_tx: T::IpSend,
        tun_rx: T::IpRecv,
        config: DeviceConfig,
    ) -> Arc<RwLock<Device<T>>> {
        let device = Device {
            api: None,
            udp_factory,
            tun_tx,
            tun_rx,
            fwmark: Default::default(),
            key_pair: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            rate_limiter: None,
            port: 0,
            connection: None,
        };

        let device = Arc::new(RwLock::new(device));

        if let Some(channel) = config.api {
            device.write().await.api = Some(Task::spawn(
                "handle_api",
                Device::handle_api(Arc::downgrade(&device), channel),
            ));
        }

        device
    }

    async fn set_port(&mut self, port: u16) -> Reconfigure {
        if self.port != port {
            self.port = port;
            Reconfigure::Yes
        } else {
            Reconfigure::No
        }
    }

    /// Bind two UDP sockets. One for IPv4, one for IPv6.
    async fn open_listen_socket(
        &mut self,
    ) -> Result<
        (
            Arc<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
            Arc<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
        ),
        Error,
    > {
        let params = UdpTransportFactoryParams {
            addr_v4: Ipv4Addr::UNSPECIFIED,
            addr_v6: Ipv6Addr::UNSPECIFIED,
            port: self.port,
            #[cfg(target_os = "linux")]
            fwmark: self.fwmark,
        };
        let (udp_sock4, udp_sock6) = self.udp_factory.bind(&params).await?;
        Ok((udp_sock4, udp_sock6))
    }

    async fn set_key(&mut self, private_key: x25519::StaticSecret) -> Reconfigure {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return Reconfigure::No;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().await.tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        Reconfigure::Yes
    }

    #[cfg(any(target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        if let Some(conn) = &mut self.connection {
            // TODO: errors
            conn.udp4.set_fwmark(mark).unwrap();
            conn.udp6.set_fwmark(mark).unwrap();
        }

        // // Then on all currently connected sockets
        // for peer in self.peers.values() {
        //     if let Some(ref sock) = peer.blocking_lock().endpoint().conn {
        //         sock.set_mark(mark)?
        //     }
        // }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    async fn handle_timers(
        device: Weak<RwLock<Self>>,
        udp4: BufferedUdpTransport<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
        udp6: BufferedUdpTransport<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
    ) {
        // TODO: fix rate limiting
        /*
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;
        */

        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;

            let Some(device) = device.upgrade() else {
                break;
            };
            let device = device.read().await;
            // TODO: pass in peers instead?
            let peer_map = &device.peers;

            // Go over each peer and invoke the timer function
            for peer in peer_map.values() {
                let mut p = peer.lock().await;
                let endpoint_addr = match p.endpoint().addr {
                    Some(addr) => addr,
                    None => continue,
                };

                match p.update_timers(&mut dst_buf[..]) {
                    TunnResult::Done => {}
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {}
                    TunnResult::Err(e) => log::error!("Timer error = {e:?}: {e:?}"),
                    TunnResult::WriteToNetwork(packet) => {
                        drop(p);
                        match endpoint_addr {
                            SocketAddr::V4(_) => udp4.send_to(packet, endpoint_addr).await.ok(),
                            SocketAddr::V6(_) => udp6.send_to(packet, endpoint_addr).await.ok(),
                        };
                    }
                    _ => unreachable!("unexpected result from update_timers"),
                };
            }
        }
    }

    /// Read from UDP socket, decapsulate, write to tunnel device
    async fn handle_incoming(
        device: Weak<RwLock<Self>>,
        udp: BufferedUdpTransport<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
        packet_pool: PacketBufPool,
    ) -> Result<(), Error> {
        let (tun, private_key, public_key, rate_limiter) = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;

            let tun = device.tun_tx.clone();
            let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
            let rate_limiter = device.rate_limiter.clone().unwrap();
            (tun, private_key, public_key, rate_limiter)
        };

        let buffered_tun_send = BufferedIpSend::new(MAX_PACKET_BUFS, tun);

        let decapsulate_task = Task::spawn("decapsulate", async move {
            // NOTE: Reusing this appears to be faster than grabbing a buffer and using it for replies
            let mut src_buf = packet_pool.get();

            while let Ok((n, addr)) = udp.recv_from(&mut src_buf[..]).await {
                debug_assert!(n <= src_buf.len());
                let mut dst_buf = packet_pool.get();

                let parsed_packet = match rate_limiter.verify_packet(
                    Some(addr.ip()),
                    &src_buf[..n],
                    &mut dst_buf[..],
                ) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        if let Err(_err) = udp.send_to(cookie, addr).await {
                            log::trace!("udp.send_to failed");
                            break;
                        }
                        continue;
                    }
                    Err(_) => continue,
                };

                let Some(device) = device.upgrade() else {
                    break;
                };
                let device_guard = &device.read().await;
                let peers = &device_guard.peers;
                let peers_by_idx = &device_guard.peers_by_idx;
                let peer = match &parsed_packet {
                    Packet::HandshakeInit(p) => parse_handshake_anon(&private_key, &public_key, p)
                        .ok()
                        .and_then(|hh| peers.get(&x25519::PublicKey::from(hh.peer_static_public))),
                    Packet::HandshakeResponse(p) => peers_by_idx.get(&(p.receiver_idx >> 8)),
                    Packet::PacketCookieReply(p) => peers_by_idx.get(&(p.receiver_idx >> 8)),
                    Packet::PacketData(p) => peers_by_idx.get(&(p.receiver_idx >> 8)),
                };
                let Some(peer) = peer else {
                    continue;
                };
                let mut peer = peer.lock().await;
                let mut flush = false;
                match peer
                    .tunnel
                    .handle_verified_packet(parsed_packet, &mut dst_buf[..])
                {
                    TunnResult::Done => (),
                    TunnResult::Err(_) => continue,
                    TunnResult::WriteToNetwork(packet) => {
                        flush = true;
                        if let Err(_err) = udp.send_to(packet, addr).await {
                            log::trace!("udp.send_to failed");
                            break;
                        }
                    }
                    TunnResult::WriteToTunnelV4(packet, addr) => {
                        let len = packet.len();
                        dst_buf.truncate(len); // hacky but works
                        let Ok(dst_buf) = dst_buf.try_into_ip() else {
                            log::trace!("Invalid packet");
                            continue;
                        };
                        if peer.is_allowed_ip(addr)
                            && let Err(_err) = buffered_tun_send.send(dst_buf).await
                        {
                            log::trace!("buffered_tun_send.send failed");
                            break;
                        }
                    }
                    TunnResult::WriteToTunnelV6(packet, addr) => {
                        let len = packet.len();
                        dst_buf.truncate(len); // hacky but works
                        let Ok(dst_buf) = dst_buf.try_into_ip() else {
                            log::trace!("Invalid packet");
                            continue;
                        };
                        if peer.is_allowed_ip(addr)
                            && let Err(_err) = buffered_tun_send.send(dst_buf).await
                        {
                            log::trace!("buffered_tun_send.send failed");
                            break;
                        }
                    }
                };

                if flush {
                    let mut dst_buf = packet_pool.get();
                    // Flush pending queue
                    loop {
                        match peer.tunnel.decapsulate(None, &[], &mut dst_buf[..]) {
                            TunnResult::WriteToNetwork(packet) => {
                                if let Err(_err) = udp.send_to(packet, addr).await {
                                    log::trace!("udp.send_to failed");
                                    break;
                                }
                            }
                            TunnResult::Done => break,
                            // TODO: why do we ignore this error?
                            TunnResult::Err(_) => continue,

                            // TODO: fix the types so we can't end up here.
                            _ => panic!("unexpected TunnResult"),
                        }
                    }
                }
            }
        });

        let _ = decapsulate_task.await;

        Ok(())
    }

    /// Read from tunnel device, encapsulate, and write to UDP socket for the corresponding peer
    async fn handle_outgoing(
        device: Weak<RwLock<Self>>,
        udp4: BufferedUdpTransport<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
        udp6: BufferedUdpTransport<<T::UdpTransportFactory as UdpTransportFactory>::Transport>,
        packet_pool: PacketBufPool,
    ) {
        let tun = {
            let Some(device) = device.upgrade() else {
                return;
            };
            let device = device.write().await;
            // FIXME: remove clone, fix tun_rx ownership
            device.tun_rx.clone()
        };

        let mut buffered_tun_recv = BufferedIpRecv::new(MAX_PACKET_BUFS, packet_pool.clone(), tun);

        let encapsulate_task = Task::spawn("encapsulate", async move {
            let mut dst_buf = packet_pool.get();

            loop {
                let packets = match buffered_tun_recv.recv(&packet_pool).await {
                    Ok(packets) => packets,
                    Err(e) => {
                        log::error!("Unexpected error on tun interface: {:?}", e);
                        break;
                    }
                };

                for packet in packets {
                    // Determine peer to use from the destination address
                    let Some(dst_addr) = packet.destination() else {
                        continue;
                    };
                    let Some(device) = device.upgrade() else {
                        break;
                    };
                    let peers = &device.read().await.peers_by_ip;
                    let mut peer = match peers.find(dst_addr) {
                        Some(peer) => peer.lock().await,
                        // Drop packet if no peer has allowed IPs for destination
                        None => continue,
                    };

                    match peer
                        .tunnel
                        .encapsulate(&packet.into_bytes(), &mut dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            log::error!("Encapsulate error={e:?}: {e:?}");
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            let endpoint_addr = peer.endpoint().addr;
                            if let Some(SocketAddr::V4(addr)) = endpoint_addr {
                                if udp4.send_to(packet, addr.into()).await.is_err() {
                                    break;
                                }
                            } else if let Some(SocketAddr::V6(addr)) = endpoint_addr {
                                if udp6.send_to(packet, addr.into()).await.is_err() {
                                    break;
                                }
                            } else {
                                log::error!("No endpoint");
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
            }
        });

        let _ = encapsulate_task.await;
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

impl<T: DeviceTransports> Connection<T> {
    async fn stop(self) {
        let Self {
            udp4,
            udp6,
            listen_port: _,
            incoming_ipv4,
            incoming_ipv6,
            timers,
            outgoing,
        } = self;
        drop((udp4, udp6));

        join!(
            incoming_ipv4.stop(),
            incoming_ipv6.stop(),
            timers.stop(),
            outgoing.stop(),
        );
    }
}

impl<T: DeviceTransports> Drop for Device<T> {
    fn drop(&mut self) {
        log::info!("Stopping Device");
    }
}
