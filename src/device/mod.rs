pub mod allowed_ips;
pub mod api;
pub mod dev_lock;
pub mod peer;
#[cfg_attr(any(target_os = "macos", target_os = "ios"), path = "kqueue.rs")]
#[cfg_attr(target_os = "linux", path = "epoll.rs")]
pub mod poll;
#[cfg_attr(unix, path = "sock_unix.rs")]
pub mod sock;
#[cfg_attr(any(target_os = "macos", target_os = "ios"), path = "tun_darwin.rs")]
#[cfg_attr(target_os = "linux", path = "tun_linux.rs")]
pub mod tun;
#[cfg_attr(unix, path = "udp_unix.rs")]
pub mod udp;

use crypto::x25519::X25519Key;
use noise::handshake::*;
use std::collections::HashMap;
use std::convert::From;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::Arc;

use allowed_ips::*;
use dev_lock::*;
use noise::errors::*;
use noise::*;
use peer::*;
use poll::*;
use sock::*;
use tun::*;
use udp::*;

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug)]
pub enum Error {
    Socket(String),
    Bind(String),
    Listen(String),
    FCntl(String),
    Accept(String),
    EventQueue(String),
    IOCtl(String),
    Connect(String),
    SetSockOpt(String),
    InvalidTunnelName,
    GetSockOpt(String),
    UDPRead(String),
    Timer(String),
    IfaceRead(String),
}

pub trait Descriptor {
    fn descriptor(&self) -> RawFd;
}

pub struct DeviceHandle {
    device: Lock<Device>,
}

impl DeviceHandle {
    pub fn new(device: Device) -> DeviceHandle {
        DeviceHandle {
            device: Lock::new(device),
        }
    }

    pub fn event_loop(&self) -> bool {
        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = self.device.read();
            loop {
                match device_lock.queue.wait() {
                    Ok(handler) => {
                        if let Some(()) = (*handler)(&mut device_lock) {
                            // In case a thread requires a write lock, it will call the notification
                            // handler that returns Some(()), we then release the read lock briefly
                            break;
                        }
                    }
                    Err(e) => eprintln!("Poll error {:?}", e),
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Device {
    key_pair: Option<(X25519Key, X25519Key)>,
    factory: EventFactory<Handler>,
    queue: EventPoll<Handler>,
    notifier: Option<EventRef<Handler>>,

    listen_port: u16,
    next_index: u32,

    iface: Arc<TunSocket>,
    udp4: Option<Arc<UDPSocket>>,
    udp6: Option<Arc<UDPSocket>>,

    peers: HashMap<X25519Key, Arc<Peer>>,
    peers_by_idx: HashMap<u32, Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
}

// Event handler function
type Handler = Box<Fn(&mut LockReadGuard<Device>) -> Option<()> + Send + Sync>;

impl Device {
    fn next_index(&mut self) -> u32 {
        let next_index = self.next_index;
        self.next_index += 1;
        next_index
    }

    fn update_peer(
        &mut self,
        pub_key: X25519Key,
        _remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIP>,
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        let next_index = self.next_index();

        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let mut tunn = Tunn::new(
            &device_key_pair.0,
            &pub_key,
            preshared_key.clone(),
            next_index,
        )
        .unwrap();

        {
            let pub_key = pub_key.clone();
            tunn.set_logger(
                Box::new(move |e: &str| eprintln!("{:?}: {}", pub_key, e)),
                Verbosity::from(Verbosity::Debug),
            );
        }

        let peer = Peer::new(tunn, endpoint, &allowed_ips, keepalive, preshared_key);

        let peer = Arc::new(peer);
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(addr, cidr as _, Arc::clone(&peer));
        }
    }

    pub fn new(name: &str) -> Result<Device, Error> {
        // The event factory is Arc so we can easily share it with closures
        let ef = EventFactory::<Handler>::new();
        let epoll = ef.new_poll()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);

        let mut device = Device {
            factory: ef,
            queue: epoll,
            iface,
            ..Default::default()
        };

        device.register_api_handler()?;
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifier()?;
        device.register_timer()?;

        Ok(device)
    }

    pub fn set_mtu(&self, mtu: i32) -> Result<(), Error> {
        self.iface.set_mtu(mtu)
    }

    fn open_listen_socket(&mut self, port: u16) -> Result<(), Error> {
        if let Some(_) = &self.udp4 {
            //TODO: handle port change - iterate over the peers, and establish new connections
            panic!("Changing the listen port is not allowed yet");
        }

        //Binds the network facing interfaces
        self.listen_port = port;

        let udp_sock4 = Arc::new(
            UDPSocket::new()
                .and_then(|s| s.set_non_blocking())
                .and_then(|s| s.set_reuse_port())
                .and_then(|s| s.bind(port))?,
        );

        let udp_sock6 = Arc::new(
            UDPSocket::new6()
                .and_then(|s| s.set_non_blocking())
                .and_then(|s| s.set_reuse_port())
                .and_then(|s| s.bind(port))?,
        );

        self.register_udp_handler(Arc::clone(&udp_sock4))?;
        self.register_udp_handler(Arc::clone(&udp_sock6))?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        Ok(())
    }

    fn set_key(&mut self, private_key: X25519Key) {
        if let Some(..) = &self.key_pair {
            for (_, ref p) in &self.peers {
                p.set_static_private(private_key.as_bytes());
            }
        }
        let public_key = private_key.public_key();
        self.key_pair = Some((private_key, public_key));
    }

    fn set_fwmark(&mut self, _mark: u32) {
        panic!("TODO: fwmark");
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifier(&mut self) -> Result<(), Error> {
        let notification_ev = self
            .factory
            // The notification event handler simply returns Some(()) to let the waiter know
            .new_notifier(Box::new(|_: &mut LockReadGuard<Device>| Some(())))?;

        self.factory.register_event(&self.queue, &notification_ev)?;
        self.notifier = Some(notification_ev);
        Ok(())
    }

    fn register_timer(&self) -> Result<(), Error> {
        let timer_ev = self.factory.new_periodic_event(
            Box::new(|d: &mut LockReadGuard<Device>| {
                // The timed event will check timer expiration of the peers
                // TODO: split into several timers
                let mut dst = [0u8; MAX_UDP_SIZE];
                let peer_map = &d.peers;

                let udp4 = d.udp4.as_ref();
                let udp6 = d.udp6.as_ref();

                if udp4.is_none() || udp6.is_none() {
                    return None;
                }

                let udp4 = udp4.unwrap();
                let udp6 = udp6.unwrap();

                // Go over every peers and invoke the timer function
                for (_, peer) in peer_map {
                    let endpoint_addr = match peer.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match peer.update_timers(&mut dst[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            // TODO: close peer socket, remove from timers
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

                None
            }),
            std::time::Duration::from_millis(250),
        )?;

        self.factory.register_event(&self.queue, &timer_ev)
    }

    pub fn trigger_notifier(&self) {
        self.factory
            .trigger_notification(self.notifier.as_ref().unwrap())
    }

    pub fn cancel_notifier(&self) {
        self.factory
            .stop_notification(self.notifier.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: Arc<UDPSocket>) -> Result<(), Error> {
        let udp_ev = self.factory.new_event(
            udp.descriptor(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // Handler that handles anonymous packets over UDP
                const HANDSHAKE_INIT: (u8, usize) = (1, 148);
                const HANDSHAKE_RESPONSE: (u8, usize) = (2, 92);
                const COOKIE_REPLY: (u8, usize) = (3, 64);

                let mut src = [0u8; MAX_UDP_SIZE];
                let mut dst = [0u8; MAX_UDP_SIZE];
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
                            if let Ok(hh) = parse_handshake_anon(
                                private_key.as_bytes(),
                                public_key.as_bytes(),
                                packet,
                            )
                            // TODO: avoid doing half a handshake and then a full handshake
                            {
                                // Extract the peer key from handshake message, and search for the peer
                                peers_by_key.get(&X25519Key::from(hh.peer_static_public))
                            } else {
                                continue;
                            }
                        }
                        HANDSHAKE_RESPONSE => {
                            let peer_idx = u32::from_le_bytes(make_array(&packet[8..])) >> 8;
                            peers_by_idx.get(&peer_idx)
                        }
                        COOKIE_REPLY => {
                            let peer_idx = u32::from_le_bytes(make_array(&packet[4..])) & !0xff;
                            peers_by_idx.get(&peer_idx)
                        }
                        (4, 32...std::usize::MAX) => {
                            // A data packet, with at least a header
                            let peer_idx = u32::from_le_bytes(make_array(&packet[4..])) & !0xff;
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
                            peer.add_tx_bytes(udp.sendto(packet, addr))
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
                    if let Ok(sock) = peer.connect_endpoint(d.listen_port) {
                        d.register_conn_handler(Arc::clone(peer), sock).unwrap();
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }

                None
            }),
            false,
        );

        self.factory.register_event(&self.queue, &udp_ev)
    }

    fn register_conn_handler(&self, peer: Arc<Peer>, udp: Arc<UDPSocket>) -> Result<(), Error> {
        let conn_ev = self.factory.new_event(
            udp.descriptor(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let mut src = [0u8; MAX_UDP_SIZE];
                let mut dst = [0u8; MAX_UDP_SIZE];
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
                                let mut tmp = [0u8; MAX_UDP_SIZE];
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

                None
            }),
            false,
        );

        self.factory.register_event(&self.queue, &conn_ev)
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        let iface_ev = self.factory.new_event(
            self.iface.descriptor(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // The iface_handler handles packets received from the wireguard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mut src = [0u8; MAX_UDP_SIZE];
                let mut dst = [0u8; MAX_UDP_SIZE];
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
                None
            }),
            false,
        );

        self.factory.register_event(&self.queue, &iface_ev)
    }
}
