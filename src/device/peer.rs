use device::udp::UDPSocket;
use device::*;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<UDPSocket>,
}

pub struct Peer {
    tunnel: Box<Tunn>,      // The associated tunnel struct
    keepalive: Option<u16>, // Optional keepalive
    rx_bytes: AtomicUsize,
    tx_bytes: AtomicUsize,
    endpoint: spin::RwLock<Endpoint>,
    allowed_ips_v4: IPv4Map<Ipv4Addr, bool>,
    allowed_ips_v6: IPv6Map<Ipv6Addr, bool>,
}

#[derive(Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Box<Tunn>,
        endpoint: Option<SocketAddr>,
        allowed_ips: &Vec<AllowedIP>,
        keepalive: Option<u16>,
    ) -> Peer {
        let mut peer = Peer {
            tunnel,
            keepalive,
            rx_bytes: AtomicUsize::new(0),
            tx_bytes: AtomicUsize::new(0),
            endpoint: spin::RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips_v4: Default::default(),
            allowed_ips_v6: Default::default(),
        };

        for AllowedIP { addr, cidr } in allowed_ips {
            match addr {
                IpAddr::V4(addr) => peer.allowed_ips_v4.insert(*addr, *cidr as _, true),
                IpAddr::V6(addr) => peer.allowed_ips_v6.insert(*addr, *cidr as _, true),
            }
        }

        peer
    }

    pub fn encapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.tunnel_to_network(src, dst)
    }

    pub fn decapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.network_to_tunnel(src, dst)
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> spin::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub fn set_endpoint(&self, addr: SocketAddr, sock: Option<UDPSocket>) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            *endpoint = Endpoint {
                addr: Some(addr),
                conn: sock,
            }
        };
    }

    pub fn connected_endpoint(
        &self,
        d: &Device,
        p: &Arc<Peer>,
    ) -> Option<spin::RwLockReadGuard<'_, Endpoint>> {
        {
            // In the common case this is called by the iface handler and we have a connection
            let endpoint = self.endpoint.read();
            if let Endpoint { conn: Some(_), .. } = *endpoint {
                return Some(endpoint);
            };
        }

        // In some cases we don't have a connection established, but have an endpoint address we can connect to
        {
            let mut endpoint = self.endpoint.write();
            if let Endpoint {
                addr: Some(ref addr),
                ref mut conn,
            } = *endpoint
            {
                let new_connection = UDPSocket::new()
                    .and_then(|s| s.set_non_blocking())
                    .and_then(|s| s.set_reuse_port())
                    .and_then(|s| s.bind(d.listen_port))
                    .and_then(|s| s.connect(addr))
                    .unwrap();

                d.event_queue
                    .register_event(Event::new_read_event(
                        &new_connection,
                        &CONNECTED_SOCKET_HANDLER,
                        EventType::ConnectedPeer(Arc::clone(p)),
                    ))
                    .unwrap();

                *conn = Some(new_connection);
            } else {
                // No connection and no address to connect to
                return None;
            }
        }

        return self.connected_endpoint(d, p); // Will return the connection with a read lock
    }

    pub fn add_rx_bytes(&self, amt: usize) {
        self.rx_bytes.fetch_add(amt, Ordering::Relaxed);
    }

    pub fn add_tx_bytes(&self, amt: usize) {
        self.tx_bytes.fetch_add(amt, Ordering::Relaxed);
    }

    pub fn get_rx_bytes(&self) -> usize {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn get_tx_bytes(&self) -> usize {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn allowed_ips<'a>(&'a self) -> (&'a IPv4Map<Ipv4Addr, bool>, &'a IPv6Map<Ipv6Addr, bool>) {
        (&self.allowed_ips_v4, &self.allowed_ips_v6)
    }

    pub fn allowed_ip_v4(&self, addr: Ipv4Addr) -> bool {
        if let Some(_) = self.allowed_ips_v4.find(addr) {
            true
        } else {
            false
        }
    }

    pub fn allowed_ip_v6(&self, addr: Ipv6Addr) -> bool {
        if let Some(_) = self.allowed_ips_v6.find(addr) {
            true
        } else {
            false
        }
    }
}
