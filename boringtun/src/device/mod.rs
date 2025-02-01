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
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::BitOrAssign;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::join;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};
use rand_core::{OsRng, RngCore};
use tun::AbstractDevice;

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
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
}

pub struct DeviceHandle {
    device: Arc<RwLock<Device>>,
}

#[derive(Debug)]
pub struct DeviceConfig {
    pub n_threads: usize,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,

    pub api: Option<api::ConfigRx>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            api: None,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    fwmark: Option<u32>,

    tun: Arc<tun::AsyncDevice>,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    cleanup_paths: Vec<String>,

    mtu: AtomicU16,

    rate_limiter: Option<Arc<RateLimiter>>,

    port: u16,
    connection: Option<Connection>,

    /// The task that responds to API requests.
    api: Option<Task>,
}

struct Task {
    name: &'static str,
    handle: Option<JoinHandle<()>>,
}
pub(crate) struct Connection {
    udp4: Arc<tokio::net::UdpSocket>,
    udp6: Arc<tokio::net::UdpSocket>,
    listen_port: u16,

    /// The task that reads IPv4 traffic from the UDP socket.
    incoming_ipv4: Task,

    /// The task that reads IPv6 traffic from the UDP socket.
    incoming_ipv6: Task,

    /// The task tha handles keepalives/heartbeats/etc.
    timers: Task,

    /// The task that reads traffic from the TUN device.
    outgoing: Task,
}

impl Connection {
    pub async fn set_up(device: Arc<RwLock<Device>>) -> Result<Self, Error> {
        let device_guard = device.read().await;
        let (udp4, udp6) = device_guard.open_listen_socket().await?;
        drop(device_guard);

        let udp4 = Arc::new(udp4);
        let udp6 = Arc::new(udp6);

        let outgoing = Task::spawn(
            "handle_outgoing",
            Device::handle_outgoing(Arc::downgrade(&device), udp4.clone(), udp6.clone()),
        );
        let timers = Task::spawn(
            "handle_timers",
            Device::handle_timers(Arc::downgrade(&device), udp4.clone(), udp6.clone()),
        );
        let incoming_ipv4 = Task::spawn(
            "handle_incoming ipv4",
            Device::handle_incoming(Arc::downgrade(&device), udp4.clone()),
        );
        let incoming_ipv6 = Task::spawn(
            "handle_incoming ipv6",
            Device::handle_incoming(Arc::downgrade(&device), udp6.clone()),
        );

        Ok(Connection {
            listen_port: udp4.local_addr()?.port(),
            udp4,
            udp6,
            incoming_ipv4,
            incoming_ipv6,
            timers,
            outgoing,
        })
    }
}

impl DeviceHandle {
    pub async fn new(tun: tun::AsyncDevice, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        Ok(DeviceHandle {
            device: Device::new(tun, config).await?,
        })
    }

    pub async fn stop(self) {
        Self::stop_inner(self.device.clone()).await
    }

    async fn stop_inner(device: Arc<RwLock<Device>>) {
        log::debug!("Stopping boringtun device");

        let mut device = device.write().await;

        if let Some(api_task) = device.api.take() {
            api_task.stop().await;
        };

        if let Some(connection) = device.connection.take() {
            connection.stop().await;
        }

        for path in &device.cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = tokio::fs::remove_file(path).await;
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
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

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.blocking_lock();
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            log::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        log::debug!("!!! update_peer");

        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.contains_key(&pub_key) {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        );

        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        log::info!("Peer added");
    }

    pub async fn new(
        tun: tun::AsyncDevice,
        config: DeviceConfig,
    ) -> Result<Arc<RwLock<Device>>, Error> {
        // Create a tunnel device
        //let tun = Arc::new(TunSocket::new(tun_name_or_fd)?.set_non_blocking()?);
        // TODO: nonblocking
        //let tun = Arc::new(TunSocket::new(tun_name_or_fd)?);

        //let tun = Arc::new(tun::create_as_async(tun_conf));
        let mtu = tun.mtu().expect("get mtu");

        let device = Device {
            api: None,
            tun: Arc::new(tun),
            fwmark: Default::default(),
            key_pair: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            cleanup_paths: Default::default(),
            mtu: AtomicU16::new(mtu),
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

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if tun_name_or_fd == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
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
        &self,
    ) -> Result<(tokio::net::UdpSocket, tokio::net::UdpSocket), Error> {
        let mut port = self.port;
        let addrv4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        let udp_sock4 = tokio::net::UdpSocket::bind(addrv4).await?;
        if port == 0 {
            // Random port was assigned
            // TODO: we need REUSEADDR or something for both sockets to share a port.
            //port = udp_sock4.local_addr()?.port();
        }

        let addrv6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        let udp_sock6 = tokio::net::UdpSocket::bind(addrv6).await?;

        #[cfg(target_os = "linux")]
        if let Some(mark) = self.fwmark {
            use nix::sys::socket::{setsockopt, sockopt};
            use std::os::fd::AsRawFd;
            // TODO: errors
            setsockopt(udp_sock4.as_raw_fd(), sockopt::Mark, &mark).unwrap();
            setsockopt(udp_sock6.as_raw_fd(), sockopt::Mark, &mark).unwrap();
        }

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

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        use nix::sys::socket::{setsockopt, sockopt};
        use std::os::fd::AsRawFd;

        self.fwmark = Some(mark);

        if let Some(conn) = &mut self.connection {
            // TODO: errors
            setsockopt(conn.udp4.as_raw_fd(), sockopt::Mark, &mark).unwrap();
            setsockopt(conn.udp6.as_raw_fd(), sockopt::Mark, &mark).unwrap();
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

    async fn handle_timers(device: Weak<RwLock<Self>>, udp4: Arc<UdpSocket>, udp6: Arc<UdpSocket>) {
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
    async fn handle_incoming(device: Weak<RwLock<Self>>, udp: Arc<UdpSocket>) -> Result<(), Error> {
        let mut src_buf = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        let (tun, private_key, public_key, rate_limiter) = {
            let Some(device) = device.upgrade() else {
                return Ok(());
            };
            let device = device.read().await;

            let tun = device.tun.clone();
            let (private_key, public_key) = device.key_pair.clone().expect("Key not set");
            let rate_limiter = device.rate_limiter.clone().unwrap();
            (tun, private_key, public_key, rate_limiter)
        };

        loop {
            // Read packets from the socket.
            let (packet_len, addr) = udp.recv_from(&mut src_buf[..]).await.map_err(|e| {
                log::error!("UDP recv_from error {e:?}");
                Error::IoError(e)
            })?;

            let packet = &src_buf[..packet_len];
            let parsed_packet =
                match rate_limiter.verify_packet(Some(addr.ip()), packet, &mut dst_buf) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        let _: Result<_, _> = udp.send_to(cookie, &addr).await;
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
            let Some(peer) = peer else { continue };
            let mut peer = peer.lock().await;
            let mut flush = false;
            match peer
                .tunnel
                .handle_verified_packet(parsed_packet, &mut dst_buf[..])
            {
                TunnResult::Done => {}
                TunnResult::Err(_) => continue,
                TunnResult::WriteToNetwork(packet) => {
                    flush = true;
                    let _: Result<_, _> = udp.send_to(packet, &addr).await;
                }
                TunnResult::WriteToTunnelV4(packet, addr) => {
                    if peer.is_allowed_ip(addr) {
                        tun.send(packet).await.unwrap();
                    }
                }
                TunnResult::WriteToTunnelV6(packet, addr) => {
                    if peer.is_allowed_ip(addr) {
                        tun.send(packet).await.unwrap();
                    }
                }
            };
            if flush {
                // Flush pending queue
                loop {
                    match peer.tunnel.decapsulate(None, &[], &mut dst_buf[..]) {
                        TunnResult::WriteToNetwork(packet) => {
                            // TODO: why do we ignore this error?
                            let _ = udp.send_to(packet, &addr).await;
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

        Ok(())
    }

    /// Read from tunnel device, encapsulate, and write to UDP socket for the corresponding peer
    async fn handle_outgoing(
        device: Weak<RwLock<Self>>,
        udp4: Arc<UdpSocket>,
        udp6: Arc<UdpSocket>,
    ) {
        let (mtu, tun) = {
            let Some(device) = device.upgrade() else {
                return;
            };
            let device = device.read().await;

            // TODO: pass in peers and sockets instead of device?

            // TODO: check every time. TODO: ordering
            let mtu = usize::from(device.mtu.load(Ordering::SeqCst));
            let tun = device.tun.clone();
            (mtu, tun)
        };

        let mut src_buf = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        loop {
            let n = match tun.recv(&mut src_buf[..mtu]).await {
                Ok(src) => src,
                Err(e) => {
                    log::error!("Unexpected error on tun interface: {:?}", e);
                    continue;
                }
            };
            let src = &src_buf[..n];

            let dst_addr = match Tunn::dst_address(src) {
                Some(addr) => addr,
                None => continue,
            };

            let Some(device) = device.upgrade() else {
                break;
            };
            let peers = &device.read().await.peers_by_ip;
            let mut peer = match peers.find(dst_addr) {
                Some(peer) => peer.lock().await,
                None => continue,
            };

            match peer.tunnel.encapsulate(src, &mut dst_buf) {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    log::error!("Encapsulate error={e:?}: {e:?}");
                }
                TunnResult::WriteToNetwork(packet) => {
                    let endpoint_addr = peer.endpoint().addr;
                    if let Some(addr @ SocketAddr::V4(_)) = endpoint_addr {
                        let _: Result<_, _> = udp4.send_to(packet, addr).await;
                    } else if let Some(addr @ SocketAddr::V6(_)) = endpoint_addr {
                        let _: Result<_, _> = udp6.send_to(packet, addr).await;
                    } else {
                        log::error!("No endpoint");
                    }
                }
                _ => panic!("Unexpected result from encapsulate"),
            };
        }
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

impl Connection {
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

impl Task {
    async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            match handle.await {
                Err(e) if e.is_panic() => {
                    log::error!("task {} panicked: {e:#?}", self.name);
                }
                _ => {
                    log::debug!("stopped task {}", self.name);
                }
            }
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            log::debug!("dropped task {}", self.name);
            handle.abort();
        }
    }
}

trait TaskOutput: Sized + Send + 'static {
    fn handle(self) {}
}

impl TaskOutput for () {}

impl<T, E> TaskOutput for Result<T, E>
where
    Self: Send + 'static,
    E: std::fmt::Debug,
{
    fn handle(self) {
        if let Err(e) = self {
            log::error!("task errored {e:?}");
        }
    }
}

impl Task {
    pub fn spawn<Fut, O>(name: &'static str, fut: Fut) -> Self
    where
        Fut: Future<Output = O> + Send + 'static,
        O: TaskOutput,
    {
        let handle = tokio::spawn(async move {
            let output = fut.await;
            log::debug!("task {name:?} exited"); // TODO: trace?
            TaskOutput::handle(output);
        });

        Task {
            name,
            handle: Some(handle),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        log::info!("Stopping Device");
    }
}
