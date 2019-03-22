// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
pub mod dev_lock;
pub mod drop_privileges;
mod integration_tests;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod udp;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

#[cfg(unix)]
#[path = "udp_unix.rs"]
pub mod udp;

use crypto::x25519::*;
use noise::handshake::parse_handshake_anon;
use std::collections::HashMap;
use std::convert::From;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use allowed_ips::*;
use dev_lock::*;
use noise::errors::*;
use noise::*;
use peer::*;
use poll::*;
use tun::*;
use udp::*;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug)]
pub enum Error {
    Socket(String),
    Bind(String),
    FCntl(String),
    EventQueue(String),
    IOCtl(String),
    Connect(String),
    SetSockOpt(String),
    InvalidTunnelName,
    #[cfg(target_os = "macos")]
    GetSockOpt(String),
    GetSockName(String),
    UDPRead(String),
    #[cfg(target_os = "linux")]
    Timer(String),
    IfaceRead(String),
    DropPrivileges(String),
    ApiSocket(std::io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and aquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

pub struct DeviceConfig {
    pub n_threads: usize,
    pub log_level: Verbosity,
    pub use_connected_socket: bool,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            log_level: Verbosity::None,
            use_connected_socket: true,
        }
    }
}

pub struct Device {
    key_pair: Option<(Arc<X25519SecretKey>, Arc<X25519PublicKey>)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<Arc<UDPSocket>>,
    udp6: Option<Arc<UDPSocket>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<Arc<X25519PublicKey>, Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
    peers_by_idx: HashMap<u32, Arc<Peer>>,
    next_index: u32,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(name, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for _ in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(&dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            std::fs::remove_file(&path).ok();
        }
    }

    fn event_loop(device: &Lock<Device>) {
        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock);
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
                        handler.cancel();
                    }
                    WaitResult::Error(e) => eprintln!("Poll error {:}", e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        let next_index = self.next_index;
        self.next_index += 1;
        assert!(next_index < (1 << 24), "Too many peers created");
        next_index
    }

    fn remove_peer(&mut self, pub_key: &X25519PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now perge all references to is:
            peer.shutdown_endpoint(); // close open udp socket and free the closure
            self.peers_by_idx.remove(&peer.index()); // peers_by_idx
            self.peers_by_ip
                .remove(&|p: &Arc<Peer>| Arc::ptr_eq(&peer, p)); // peers_by_ip

            peer.log(Verbosity::Info, "Peer removed");
        }
    }

    fn update_peer(
        &mut self,
        pub_key: X25519PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIP>,
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        let pub_key = Arc::new(pub_key);

        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let mut tunn = Tunn::new(
            Arc::clone(&device_key_pair.0),
            Arc::clone(&pub_key),
            preshared_key,
            keepalive,
            next_index,
        )
        .unwrap();

        if self.config.log_level > Verbosity::None {
            let pub_key = base64::encode(pub_key.as_bytes());
            let peer_name = format!(
                "peer({}…{})",
                &pub_key[0..4],
                &pub_key[pub_key.len() - 4..]
            );
            tunn.set_logger(
                Box::new(move |e: &str| println!("{:?} {} {}", chrono::Utc::now(), peer_name, e)),
                self.config.log_level,
            );
        }

        let peer = Peer::new(tunn, next_index, endpoint, &allowed_ips, preshared_key);

        let peer = Arc::new(peer);
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(addr, cidr as _, Arc::clone(&peer));
        }

        peer.log(Verbosity::Info, "Peer added");
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: Default::default(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
        };

        device.register_api_handler()?;
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timer()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        //Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        self.udp4.take().and_then(|s| unsafe {
            self.queue.clear_event_by_fd(s.as_raw_fd());
            Some(())
        });

        self.udp6.take().and_then(|s| unsafe {
            self.queue.clear_event_by_fd(s.as_raw_fd());
            Some(())
        });

        for peer in self.peers.values() {
            peer.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = Arc::new(
            UDPSocket::new()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.port()?;
        }

        let udp_sock6 = Arc::new(
            UDPSocket::new6()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        self.register_udp_handler(Arc::clone(&udp_sock4))?;
        self.register_udp_handler(Arc::clone(&udp_sock6))?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: X25519SecretKey) {
        let mut bad_peers = vec![];

        let private_key = Arc::new(private_key);
        if let Some(..) = &self.key_pair {
            for peer in self.peers.values() {
                if let Err(_) = peer.set_static_private(Arc::clone(&private_key)) {
                    bad_peers.push(peer);
                    // In case we encounter an error, we will remove that peer
                    // An error will be a result of bad public key/secret key combination
                }
            }
        }
        let public_key = private_key.public_key();
        self.key_pair = Some((private_key, Arc::new(public_key)));

        // Remove all the bad peers
        for _ in bad_peers {
            unimplemented!();
        }
    }

    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_fwmark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_fwmark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.endpoint().conn {
                sock.set_fwmark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_: &mut LockReadGuard<Device>| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_: &mut LockReadGuard<Device>| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timer(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(|d: &mut LockReadGuard<Device>| {
                // The timed event will check timer expiration of the peers
                // TODO: split into several timers
                // Allocate temporary buffer for update_timers to write to
                let mut tmp_buff: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let peer_map = &d.peers;

                let udp4 = d.udp4.as_ref();
                let udp6 = d.udp6.as_ref();

                if udp4.is_none() || udp6.is_none() {
                    return Action::Continue;
                }

                let udp4 = udp4.unwrap();
                let udp6 = udp6.unwrap();

                // Go over every peers and invoke the timer function
                for peer in peer_map.values() {
                    let endpoint_addr = match peer.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match peer.update_timers(&mut tmp_buff[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            peer.shutdown_endpoint(); // close open udp socket
                                                      // TODO: remove peer from timers?
                        }
                        TunnResult::Err(e) => eprintln!("Timer error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            peer.add_tx_bytes(match endpoint_addr {
                                SocketAddr::V4(_) => udp4.sendto(packet, endpoint_addr),
                                SocketAddr::V6(_) => udp6.sendto(packet, endpoint_addr),
                            });
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: Arc<UDPSocket>) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // Handler that handles anonymous packets over UDP
                const HANDSHAKE_INIT: (u8, usize) = (1, 148);
                const HANDSHAKE_RESPONSE: (u8, usize) = (2, 92);
                const COOKIE_REPLY: (u8, usize) = (3, 64);
                const DATA: u8 = 4;
                const DATA_OVERHEAD_SZ: usize = 32;

                let mut src: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let mut dst: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let mut iter = MAX_ITR;

                let key_pair = &d.key_pair;
                let peers_by_key = &d.peers;
                let peers_by_idx = &d.peers_by_idx;

                let iface = &d.iface;

                let (private_key, public_key) = key_pair.as_ref().expect("Key not set");

                // Loop while we have packets on the anonymous connection
                while let Ok((addr, packet)) = udp.recvfrom(&mut src[..]) {
                    if packet.is_empty() {
                        continue;
                    }

                    let peer = match (packet[0], packet.len()) {
                        HANDSHAKE_INIT => {
                            // Handshake, this is the most common scenario
                            if let Ok(hh) = parse_handshake_anon(&private_key, &public_key, packet)
                            // TODO: avoid doing half a handshake and then a full handshake
                            {
                                // Extract the peer key from handshake message, and search for the peer
                                peers_by_key.get(&X25519PublicKey::from(&hh.peer_static_public[..]))
                            } else {
                                continue;
                            }
                        }
                        HANDSHAKE_RESPONSE => {
                            let peer_idx = u32::from_le_bytes(make_array(&packet[8..])) >> 8;
                            peers_by_idx.get(&peer_idx)
                        }
                        COOKIE_REPLY => {
                            let peer_idx = u32::from_le_bytes(make_array(&packet[4..])) >> 8;
                            peers_by_idx.get(&peer_idx)
                        }
                        (DATA, DATA_OVERHEAD_SZ...std::usize::MAX) => {
                            // A data packet, with at least a header
                            let peer_idx = u32::from_le_bytes(make_array(&packet[4..])) >> 8;
                            peers_by_idx.get(&peer_idx)
                        }
                        _ => continue,
                    };

                    let peer = match peer {
                        Some(peer) => peer,
                        _ => continue,
                    };

                    // We found a peer, use it to decapsulate the message
                    match peer.decapsulate(packet, &mut dst[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            eprintln!("Decapsulate error {:?}", e);
                            continue;
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            peer.add_tx_bytes(udp.sendto(packet, addr));
                            {
                                // Flush pending queue
                                let mut tmp: [u8; MAX_UDP_SIZE] =
                                    unsafe { std::mem::uninitialized() };
                                while let TunnResult::WriteToNetwork(packet) =
                                    peer.decapsulate(&[], &mut tmp[..])
                                {
                                    peer.add_tx_bytes(udp.write(packet));
                                }
                            }
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if peer.is_allowed_ip(IpAddr::from(addr)) {
                                peer.add_rx_bytes(iface.write4(packet))
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if peer.is_allowed_ip(IpAddr::from(addr)) {
                                peer.add_rx_bytes(iface.write6(packet))
                            }
                        }
                    };
                    // This packet was OK, that means we want to create a connected socket for this peer
                    peer.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = peer.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock).unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(&self, peer: Arc<Peer>, udp: Arc<UDPSocket>) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let mut src: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let mut dst: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let iface = &d.iface;
                let mut iter = MAX_ITR;

                while let Ok(src) = udp.read(&mut src[..]) {
                    match peer.decapsulate(src, &mut dst[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            peer.add_tx_bytes(udp.write(packet));
                            {
                                // Flush pending queue
                                let mut tmp: [u8; MAX_UDP_SIZE] =
                                    unsafe { std::mem::uninitialized() };
                                while let TunnResult::WriteToNetwork(packet) =
                                    peer.decapsulate(&[], &mut tmp[..])
                                {
                                    peer.add_tx_bytes(udp.write(packet));
                                }
                            }
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if peer.is_allowed_ip(IpAddr::from(addr)) {
                                peer.add_rx_bytes(iface.write4(packet))
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if peer.is_allowed_ip(IpAddr::from(addr)) {
                                peer.add_rx_bytes(iface.write6(packet))
                            }
                        }
                    };

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            self.iface.as_raw_fd(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // The iface_handler handles packets received from the wireguard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mut src: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let mut dst: [u8; MAX_UDP_SIZE] = unsafe { std::mem::uninitialized() };
                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let peers = &d.peers_by_ip;
                {
                    let mut iter = MAX_ITR;
                    while let Ok(src) = iface.read(&mut src[..]) {
                        let dst_addr = match Tunn::dst_address(src) {
                            Some(addr) => addr,
                            None => continue,
                        };

                        let peer = match peers.find(dst_addr) {
                            Some(peer) => peer,
                            None => continue,
                        };

                        match peer.encapsulate(src, &mut dst[..]) {
                            TunnResult::Done => {}
                            TunnResult::Err(e) => eprintln!("Encapsulate error {:?}", e),
                            TunnResult::WriteToNetwork(packet) => {
                                let endpoint = peer.endpoint();
                                if let Some(ref conn) = endpoint.conn {
                                    // Prefer to send using the connected socket
                                    peer.add_tx_bytes(conn.write(packet));
                                } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                    peer.add_tx_bytes(udp4.sendto(packet, addr));
                                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                    peer.add_tx_bytes(udp6.sendto(packet, addr));
                                } else {
                                    eprintln!("No endpoint for peer");
                                }
                            }
                            _ => panic!("Unexpected result from encapsulate"),
                        };

                        iter -= 1;
                        if iter == 0 {
                            break;
                        }
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
}
