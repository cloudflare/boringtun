use device::udp::UDPSocket;
use device::*;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<Arc<UDPSocket>>,
}

pub struct Peer {
    tunnel: Box<Tunn>,      // The associated tunnel struct
    keepalive: Option<u16>, // Optional keepalive
    rx_bytes: AtomicUsize,
    tx_bytes: AtomicUsize,
    endpoint: spin::RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
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
        preshared_key: Option<[u8; 32]>,
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
            allowed_ips: Default::default(),
            preshared_key,
        };

        for AllowedIP { addr, cidr } in allowed_ips {
            peer.allowed_ips.insert(*addr, *cidr as _, ());
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

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one

            if let Some(ref conn) = endpoint.conn {
                conn.shutdown();
            }

            *endpoint = Endpoint {
                addr: Some(addr),
                conn: None, // TODO: shutdown sock
            }
        };
    }

    pub fn connect_endpoint(&self, port: u16) -> Result<Arc<UDPSocket>, Error> {
        let mut endpoint = self.endpoint.write();

        if let Some(_) = endpoint.conn {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let udp_conn = Arc::new(match endpoint.addr {
            Some(addr @ SocketAddr::V4(_)) => UDPSocket::new()
                .and_then(|s| s.set_non_blocking())
                .and_then(|s| s.set_reuse_port())
                .and_then(|s| s.bind(port))
                .and_then(|s| s.connect(&addr))?,
            Some(addr @ SocketAddr::V6(_)) => UDPSocket::new6()
                .and_then(|s| s.set_non_blocking())
                .and_then(|s| s.set_reuse_port())
                .and_then(|s| s.bind(port))
                .and_then(|s| s.connect(&addr))?,
            None => panic!("Attempt to connect to undefined endpoint"),
        });

        endpoint.conn = Some(Arc::clone(&udp_conn));

        Ok(udp_conn)
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

    pub fn is_allowed_ip(&self, addr: IpAddr) -> bool {
        match self.allowed_ips.find(addr) {
            Some(_) => true,
            None => false,
        }
    }

    pub fn allowed_ips(&self) -> Iter<(())> {
        self.allowed_ips.iter()
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn preshared_key<'a>(&'a self) -> Option<&'a [u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn set_static_private(&self, static_private: &[u8]) {
        self.tunnel.set_static_private(static_private)
    }
}
