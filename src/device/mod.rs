pub mod allowed_ips;
pub mod api;
pub mod dev_lock;
#[cfg_attr(any(target_os = "macos", target_os = "ios"), path = "kqueue.rs")]
#[cfg_attr(target_os = "linux", path = "epoll.rs")]
pub mod events;
pub mod peer;
#[cfg_attr(unix, path = "sock_unix.rs")]
pub mod sock;
#[cfg_attr(any(target_os = "macos", target_os = "ios"), path = "tun_darwin.rs")]
#[cfg_attr(target_os = "linux", path = "tun_linux.rs")]
pub mod tun;
#[cfg_attr(unix, path = "udp_unix.rs")]
pub mod udp;

use crypto::x25519::X25519Key;
use noise::handshake::*;
use noise::*;
use std::collections::HashMap;
use std::convert::From;
use std::net::*;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use allowed_ips::*;
use api::*;
use dev_lock::*;
use events::*;
use peer::*;
use sock::*;
use tun::*;
use udp::*;

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
            let mut dev = self.device.read();
            loop {
                if let Some(event) = dev.event_queue.wait() {
                    if let Some(()) = event.handle(&mut dev) {
                        // In case a thread requires a write lock, it will call the notification
                        // handler so we release the read lock temporarily
                        break;
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Device {
    key_pair: Option<(X25519Key, X25519Key)>,

    event_queue: EventQueue,

    iface: TunSocket,
    api: UNIXSocket,

    listen_port: u16,
    listener4: Option<UDPSocket>,
    listener6: Option<UDPSocket>,

    next_index: u32,

    peers: HashMap<X25519Key, Arc<Peer>>,
    peers_by_idx: HashMap<u32, Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
}

// Event handler function
type HandlerFunction = fn(RawFd, &mut LockReadGuard<Device>, Event) -> Option<()>;

const COOP_HANDLER: HandlerFunction =
    |_: RawFd, _: &mut LockReadGuard<Device>, _: Event| -> Option<()> {
        // Ask the thread for a cooperative yield of its read lock
        Some(())
    };

const TIMER_HANDLER: HandlerFunction =
    |_: RawFd, device: &mut LockReadGuard<Device>, _: Event| -> Option<()> {
        {
            // TODO: split into several timers
            let mut dst = [0u8; 1536];
            let peer_map = &device.peers;
            // Go over all the peers and invoke the timer function
            for (_, peer) in peer_map {
                let endpoint = match peer.connected_endpoint(device, &peer) {
                    Some(endpoint) => endpoint,
                    _ => continue,
                };

                let udp_conn = endpoint.conn.as_ref().unwrap();

                match peer.update_timers(&mut dst[..]) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => eprintln!("Error({:?})", e),
                    TunnResult::WriteToNetwork(packet) => peer.add_tx_bytes(udp_conn.write(packet)),
                    _ => panic!("Unexpected op"),
                };
            }
        }
        device.event_queue.reset_timer();
        None
    };

// This function handles packets from a connected socket, where the peer is already known
const CONNECTED_SOCKET_HANDLER: HandlerFunction =
    |_: RawFd, device: &mut LockReadGuard<Device>, event: Event| -> Option<()> {
        let mut src = [0u8; 1536];
        let mut dst = [0u8; 1536];
        let mut iter = 64; // Don't loop forever to let other connections run too

        {
            let peer = match event.data().extra {
                EventType::ConnectedPeer(ref peer) => peer,
                _ => panic!("CONNECTED_SOCKET_HANDLER, unexpected EventType"),
            };

            let endpoint = peer.endpoint();
            let udp_conn = endpoint.conn.as_ref().unwrap();
            let iface = &device.iface;

            while let Ok(src) = udp_conn.read(&mut src[..]) {
                match peer.decapsulate(src, &mut dst[..]) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => eprintln!("Error({:?})", e),
                    TunnResult::WriteToNetwork(packet) => {
                        peer.add_tx_bytes(udp_conn.write(packet));
                        {
                            // Flush queue
                            let mut tmp = [0u8; 1536];
                            while let TunnResult::WriteToNetwork(packet) =
                                peer.decapsulate(&[], &mut tmp[..])
                            {
                                peer.add_tx_bytes(udp_conn.write(packet));
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
        }

        device.event_queue.enable_event(event).unwrap();
        None
    };

// This function accepts packets from the interface and sends them to the right peer
const IFACE_HANDLER: HandlerFunction =
    |_: RawFd, device: &mut LockReadGuard<Device>, e: Event| -> Option<()> {
        let mut src = [0u8; 1536];
        let mut dst = [0u8; 1536];
        let mut iter = 64;
        {
            let peer_map = &device.peers_by_ip;
            let iface = &device.iface;

            while let Ok(src) = iface.read(&mut src[..]) {
                let addr = match Tunn::dst_address(src) {
                    Some(addr) => addr,
                    None => continue,
                };

                let peer = match peer_map.find(addr) {
                    Some(ref peer) => Arc::clone(peer),
                    None => continue,
                };

                let endpoint = peer.connected_endpoint(device, &peer).unwrap();
                let udp_conn = endpoint.conn.as_ref().unwrap();

                match peer.encapsulate(src, &mut dst[..]) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => println!("Error({:?})", e),
                    TunnResult::WriteToNetwork(packet) => peer.add_tx_bytes(udp_conn.write(packet)),
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
        }

        device.event_queue.enable_event(e).unwrap();
        None
    };

const LISTEN_SOCKET_HANDLER: HandlerFunction = |_: RawFd,
                                                d: &mut LockReadGuard<Device>,
                                                e: Event|
 -> Option<()> {
    const HANDSHAKE_INIT: (u8, usize) = (1, 148);
    const HANDSHAKE_RESPONSE: (u8, usize) = (2, 92);
    const COOKIE_REPLY: (u8, usize) = (3, 64);

    let mut buf = [0u8; 1536];
    let mut dst = [0u8; 1536];

    // Both the listener and the keys are very rarely changed, therefore it is wiser to hold the lock outside the inner loop
    let conn_lock = &d.listener4;
    let key_lock = &d.key_pair;
    let peer_map = &d.peers;
    let peer_idx_map = &d.peers_by_idx;

    // We can safely unwrap here, because this event can only be registered if we established a listener and set a key for the connection
    let iface = &d.iface;
    let udp_conn = conn_lock.as_ref().unwrap();
    let (private_key, public_key) = key_lock.as_ref().unwrap();

    // Loop while we have packets on the anonymous connection
    while let Ok((addr, packet)) = udp_conn.recvfrom(&mut buf[..]) {
        if packet.is_empty() {
            continue;
        }

        let peer = match (packet[0], packet.len()) {
            HANDSHAKE_INIT => {
                // Handshake, this is the most common scenario
                if let Ok(hh) =
                    parse_handshake_anon(private_key.as_bytes(), public_key.as_bytes(), packet)
                // TODO: avoid doing half a handshake and then a full handshake
                {
                    // Extract the peer key from handshake message, and search for the peer
                    peer_map.get(&X25519Key::from(hh.peer_static_public))
                } else {
                    continue;
                }
            }
            HANDSHAKE_RESPONSE => {
                let peer_idx = super::noise::h2n::read_u32(&packet[8..12]) >> 8;
                peer_idx_map.get(&peer_idx)
            }
            COOKIE_REPLY => {
                let peer_idx = super::noise::h2n::read_u32(&packet[4..8]) & !0xff;
                peer_idx_map.get(&peer_idx)
            }
            (4, 32...std::usize::MAX) => {
                // A data packet, with at least a header
                let peer_idx = super::noise::h2n::read_u32(&packet[4..8]) & !0xff;
                peer_idx_map.get(&peer_idx)
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
                println!("Error: {:?}", e);
                continue;
            }
            TunnResult::WriteToNetwork(packet) => peer.add_tx_bytes(udp_conn.sendto(packet, addr)),
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
        // This packet is OK, that means we need to create a connected socket for this peer
        peer.set_endpoint(addr, None);
        peer.connected_endpoint(d, &peer);
        // TODO: the previous connection is dropped here, but allocated event is not freed
    }

    d.event_queue.enable_event(e).unwrap();
    None
};

impl Device {
    fn update_peer(
        &mut self,
        pub_key: X25519Key,
        remove: bool,
        replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIP>,
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let next_index = self.next_index;
        self.next_index += 1;

        let tunn = Tunn::new(
            &device_key_pair.0,
            &pub_key,
            preshared_key.clone(),
            next_index,
        )
        .unwrap();
        let peer = Peer::new(tunn, endpoint, &allowed_ips, keepalive, preshared_key);

        let peer = Arc::new(peer);
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip.insert(addr, cidr as _, Arc::clone(&peer));
        }
    }

    pub fn new(name: &str) -> Result<Device, Error> {
        // Create a tunnel device
        let iface = TunSocket::new(name)?.set_non_blocking()?;
        // Create the control API socket for the device
        if let Err(_) = std::fs::create_dir("/var/run/wireguard/") {};
        let path = format!("/var/run/wireguard/{}.sock", iface.name()?);
        let api = UNIXSocket::new()
            .and_then(|s| s.set_non_blocking())
            .and_then(|s| s.bind(&path))
            .and_then(|s| s.listen())?;

        let device = Device {
            iface,
            api,
            event_queue: EventQueue::new()?,
            ..Default::default()
        };

        // Register handlers for the tunnel and for the api
        device.event_queue.register_event(Event::new_read_event(
            &device.api,
            &UNIX_SOCKET_HANDLER,
            EventType::None,
        ))?;

        device.event_queue.register_event(Event::new_read_event(
            &device.iface,
            &IFACE_HANDLER,
            EventType::None,
        ))?;

        Ok(device)
    }

    pub fn set_mtu(&self, mtu: i32) -> Result<(), Error> {
        self.iface.set_mtu(mtu)
    }

    fn open_listen_socket(&mut self, port: u16) -> Result<(), Error> {
        if let Some(_) = &self.listener4 {
            // TODO: handle port change - iterate over the peers, and establish new connections
            panic!("Changing the listen port is not allowed yet");
        }
        // Binds the network facing interface
        let udp_sock4 = UDPSocket::new()
            .and_then(|s| s.set_non_blocking())
            .and_then(|s| s.set_reuse_port())
            .and_then(|s| s.bind(port))?;

        let udp_sock6 = UDPSocket::new6()
            .and_then(|s| s.set_non_blocking())
            .and_then(|s| s.set_reuse_port())
            .and_then(|s| s.bind(port))?;

        self.event_queue.register_event(Event::new_read_event(
            &udp_sock4,
            &LISTEN_SOCKET_HANDLER,
            EventType::None,
        ))?;

        self.event_queue.register_event(Event::new_read_event(
            &udp_sock6,
            &LISTEN_SOCKET_HANDLER,
            EventType::None,
        ))?;

        self.listen_port = port;
        self.listener4 = Some(udp_sock4);
        self.listener6 = Some(udp_sock6);

        self.event_queue
            .start_timer(std::time::Duration::from_millis(250), &TIMER_HANDLER)?;

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

    fn set_fwmark(&mut self, mark: u32) {
        panic!("TODO: fwmark");
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }
}
