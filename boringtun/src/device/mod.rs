// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;

pub mod api;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

//#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
//#[path = "kqueue.rs"]
//pub mod poll;
//
//#[cfg(target_os = "linux")]
//#[path = "epoll.rs"]
//pub mod poll;



use std::collections::HashMap;
use std::io::{self, Write as _};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::Mutex;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tun::{AbstractDevice};

//use dev_lock::LockReadGuard;

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

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
//type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<RwLock<Device>>, // The interface this handle owns
                                 //threads: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
pub struct DeviceConfig {
    pub n_threads: usize,
    // TODO: support connected sockets?
    //pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,

    #[cfg(target_os = "linux")]
    pub api: Option<api::ConfigRx>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            //use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            api: None,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    //queue: Arc<EventPoll<Handler>>,
    listen_port: u16,
    fwmark: Option<u32>,

    tun: Arc<tun::AsyncDevice>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,

    //yield_notice: Option<EventRef>,
    //exit_notice: Option<EventRef>,
    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    cleanup_paths: Vec<String>,

    mtu: AtomicU16,

    rate_limiter: Option<Arc<RateLimiter>>,
}

impl DeviceHandle {
    pub async fn new(tun: tun::AsyncDevice, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        log::warn!("YOU TRYING TO CREATE A DEVICE?!?! BAHAHAH GOOD LUCK.");
        let device = Device::new(tun, config).await?;

        //let mut threads = vec![];
        //
        //for i in 0..n_threads {
        //    threads.push({
        //        let dev = Arc::clone(&interface_lock);
        //        thread::spawn(move || DeviceHandle::event_loop(i, &dev))
        //    });
        //}

        Ok(DeviceHandle {
            device,
            //threads,
        })
    }

    /*pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }*/

    pub fn clean(&mut self) {
        for path in &self.device.blocking_read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    /*
    fn event_loop(_i: usize, device: &Lock<Device>) {
        // TODO: Do we really need this?
        /*
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };
        */

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => log::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
    */
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        //self.device.read().trigger_exit();
        // TODO
        self.clean();
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
                p.shutdown_endpoint(); // close open udp socket and free the closure
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

    pub async fn new(tun: tun::AsyncDevice, config: DeviceConfig) -> Result<Arc<RwLock<Device>>, Error> {
        // Create a tunnel device
        //let tun = Arc::new(TunSocket::new(tun_name_or_fd)?.set_non_blocking()?);
        // TODO: nonblocking
        //let tun = Arc::new(TunSocket::new(tun_name_or_fd)?);

        //let tun = Arc::new(tun::create_as_async(tun_conf));
        let mtu = tun.mtu().expect("get mtu");

        let device = Device {
            tun: Arc::new(tun),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicU16::new(mtu),
            rate_limiter: None,
        };

        let device = Arc::new(RwLock::new(device));

        if let Some(channel) = config.api {
            Device::register_api_handler(&device, channel);
        }

        // Start listening on a random port
        // TODO: remove Option from Device::udp*
        Device::open_listen_socket(Arc::clone(&device), 0).await?;

        tokio::spawn(Self::handle_outgoing(Arc::clone(&device)));
        //device.register_notifiers()?;
        Self::register_timers(Arc::clone(&device))?;

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

    async fn open_listen_socket(device: Arc<RwLock<Self>>, mut port: u16) -> Result<(), Error> {
        // TODO: should this function recreate handle_incoming?

        let mut self_ = device.write().await;

        for peer in self_.peers.values() {
            peer.lock().await.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self_.listen_port = port;

        /*
        tokio::spawn(Self::handle_incoming(
            device.clone(),
            udp_sock4.try_clone().unwrap(),
        ));
        tokio::spawn(Self::handle_incoming(
            device.clone(),
            udp_sock6.try_clone().unwrap(),
        ));
        */

        self_.udp4 = Some(udp_sock4);
        self_.udp6 = Some(udp_sock6);

        Ok(())
    }

    fn set_port(&mut self, port: u16) {
        self.listen_port = port;
    }

    fn set_key(&mut self, device_arc: Arc<RwLock<Device>>, private_key: x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.blocking_lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        // TODO stuff
        // TODO: ipv6
        let udp = self.udp4.as_ref().unwrap().try_clone().unwrap();

        tokio::spawn(Device::handle_incoming(device_arc, udp));
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.blocking_lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    /*
    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }
    */

    fn register_timers(device: Arc<RwLock<Self>>) -> Result<(), Error> {
        // TODO: use tokio timers

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

        tokio::spawn(async move {
            let mut dst_buf = [0u8; MAX_UDP_SIZE];

            let device_lock = device.read().await;
            let udp4 = device_lock.udp4.as_ref().unwrap().try_clone().unwrap();
            // TODO: ipv6 isn't important. fixme
            //let udp6 = self.udp4.as_ref().unwrap().try_clone().unwrap();

            drop(device_lock);

            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                let device = device.read().await;
                let peer_map = &device.peers;

                /*
                let (udp4, udp6) = match (device.udp4.as_ref(), device.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    // TODO: what. why do we need both v4 and v6?
                    _ => continue,
                };
                */

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.blocking_lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => log::error!("Timer error = {e:?}: {e:?}"),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => {
                                    udp4.send_to(packet, &endpoint_addr.into()).ok()
                                }
                                SocketAddr::V6(_) => {
                                    // FIXME
                                    //udp6.send_to(packet, &endpoint_addr.into()).ok()
                                    None
                                }
                            };
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
            }
        });

        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        // TODO
        //self.queue
        //    .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        // TODO
        //self.queue
        //    .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        // TODO
        //self.queue
        //    .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    /// Read from UDP socket, decapsulate, write to tunnel device
    async fn handle_incoming(device: Arc<RwLock<Self>>, udp: socket2::Socket) -> Result<(), Error> {
        log::info!("handle_incoming!");

        let device_lock = device.read().await;

        // TODO: check every time. TODO: ordering
        // TODO: wrap MTU in arc, and clone it
        let tun = device_lock.tun.clone();

        let mut src_buf = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        // TODO: restart task if key pair is modified
        // Handler that handles anonymous packets over UDP
        let (private_key, public_key) = device_lock.key_pair.clone().expect("Key not set");
        let rate_limiter = device_lock.rate_limiter.clone().unwrap();

        // TOOD: these 3 need to be updated. or task needs to be restarted if they change
        //let use_connected_socket = device_lock.config.use_connected_socket;
        //let listen_port = device_lock.listen_port;
        //let fwmark = device_lock.fwmark;

        drop(device_lock);

        loop {
            // Loop while we have packets on the anonymous connection

            // Safety: the `recv_from` implementation promises not to write uninitialised
            // bytes to the buffer, so this casting is safe.
            let src = unsafe { &mut *(&mut src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
            while let Ok((packet_len, addr)) = udp.recv_from(src) {
                let packet = &src_buf[..packet_len];
                // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                let parsed_packet = match rate_limiter.verify_packet(
                    Some(addr.as_socket().unwrap().ip()),
                    packet,
                    &mut dst_buf,
                ) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        let _: Result<_, _> = udp.send_to(cookie, &addr);
                        continue;
                    }
                    Err(_) => continue,
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

                let peer = match peer {
                    None => continue,
                    Some(peer) => peer,
                };

                let mut p = peer.lock().await;

                // We found a peer, use it to decapsulate the message+
                let mut flush = false; // Are there packets to send from the queue?
                match p
                    .tunnel
                    .handle_verified_packet(parsed_packet, &mut dst_buf[..])
                {
                    TunnResult::Done => {}
                    TunnResult::Err(_) => continue,
                    TunnResult::WriteToNetwork(packet) => {
                        flush = true;
                        let _: Result<_, _> = udp.send_to(packet, &addr);
                    }
                    TunnResult::WriteToTunnelV4(packet, addr) => {
                        if p.is_allowed_ip(addr) {
                            log::info!("wrote stuff, {}", packet.len());
                            tun.send(packet).await.unwrap();
                        } else {
                            log::info!("ip not allowed >:(, {}", addr);
                        }
                    }
                    TunnResult::WriteToTunnelV6(packet, addr) => {
                        if p.is_allowed_ip(addr) {
                            tun.send(packet).await.unwrap();
                        }
                    }
                };

                if flush {
                    // Flush pending queue
                    while let TunnResult::WriteToNetwork(packet) =
                        p.tunnel.decapsulate(None, &[], &mut dst_buf[..])
                    {
                        let _: Result<_, _> = udp.send_to(packet, &addr);
                    }
                }

                // This packet was OK, that means we want to create a connected socket for this peer
                let addr = addr.as_socket().unwrap();
                p.set_endpoint(addr);
                // TODO: support connected sockets?
                /*if use_connected_socket {
                    if let Ok(sock) = p.connect_endpoint(listen_port, fwmark) {
                        Self::register_conn_handler(Arc::clone(peer), sock, ip_addr).unwrap();
                    }
                }*/
            }
        }

        Ok(())
    }

    /*fn register_conn_handler(
        device: Arc<RwLock<Self>>,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
        tun: Arc<TunSocket>,
    ) -> Result<(), Error> {
        tokio::spawn(async move {
            let mut src_buf = [0u8; MAX_UDP_SIZE];
            let mut dst_buf = [0u8; MAX_UDP_SIZE];

            loop {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let _src_buf =
                    unsafe { &mut *(&mut src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

                // TODO: tokio async read/write
                while let Ok(read_bytes) = udp.recv(_src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &src_buf[..read_bytes],
                        &mut dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send(packet); // TODO: async
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                tun.write4(packet); // TODO: async
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if p.is_allowed_ip(addr) {
                                tun.write6(packet); // TODO: async
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }
                }
            }
        });
        Ok(())
    }*/

    /// Read from tunnel device, encapsulate, and write to UDP socket for the corresponding peer
    async fn handle_outgoing(device: Arc<RwLock<Self>>) -> Result<(), Error> {
        let device_lock = device.read().await;

        let udp4 = device_lock.udp4.as_ref().unwrap().try_clone().unwrap();
        // TODO: ipv6 isn't important. fixme
        //let udp6 = self.udp4.as_ref().unwrap().try_clone().unwrap();

        // TODO: check every time. TODO: ordering
        let mtu = usize::from(device_lock.mtu.load(Ordering::SeqCst));
        let tun = device_lock.tun.clone();

        let mut src_buf = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        drop(device_lock);

        loop {
            log::info!("reading from tun device");
            // TODO: async read/write
            let n = match tun.recv(&mut src_buf[..mtu]).await {
                Ok(src) => src,
                Err(e) => {
                    log::error!("Unexpected error on tun interface: {:?}", e);
                    continue;
                }
            };
            log::info!("read {} bytes from tun device", n);
            let src = &src_buf[..n];

            let dst_addr = match Tunn::dst_address(src) {
                Some(addr) => addr,
                None => continue,
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
                    let mut endpoint = peer.endpoint_mut();
                    if let Some(conn) = endpoint.conn.as_mut() {
                        // Prefer to send using the connected socket
                        // TODO: async
                        let _: Result<_, _> = conn.write(packet);
                    } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                        // TODO: async
                        let _: Result<_, _> = udp4.send_to(packet, &addr.into());
                    } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                        // FIXME
                        // let _: Result<_, _> = udp6.send_to(packet, &addr.into());
                    } else {
                        log::error!("No endpoint");
                    }
                }
                _ => panic!("Unexpected result from encapsulate"),
            };
        }
        Ok(())
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
