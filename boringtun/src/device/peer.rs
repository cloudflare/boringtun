// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::device::{AllowedIps, Error};
use crate::noise::{Tunn, TunnResult};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
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
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            conn.shutdown(Shutdown::Both).unwrap();
        }
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                conn.shutdown(Shutdown::Both).unwrap();
            }

            endpoint.addr = Some(addr);
        }
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .expect("Attempt to connect to undefined endpoint");

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );

        endpoint.conn = Some(udp_conn.try_clone().unwrap());

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips.iter().map(|(_, ip, cidr)| (ip, cidr))
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Tunn;
    use crate::x25519;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn create_test_tunnel() -> Tunn {
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([1u8; 32]);
        Tunn::new(private_key, public_key, None, None, 0, None)
    }

    fn create_test_allowed_ips() -> Vec<AllowedIP> {
        vec![
            AllowedIP::from_str("192.168.1.0/24").unwrap(),
            AllowedIP::from_str("10.0.0.0/8").unwrap(),
            AllowedIP::from_str("2001:db8::/32").unwrap(),
        ]
    }

    #[test]
    fn test_allowed_ip_from_str_valid() {
        // Test IPv4
        let ip4 = AllowedIP::from_str("192.168.1.0/24").unwrap();
        assert_eq!(ip4.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(ip4.cidr, 24);

        // Test IPv6
        let ip6 = AllowedIP::from_str("2001:db8::/32").unwrap();
        assert_eq!(ip6.addr, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
        assert_eq!(ip6.cidr, 32);

        // Test host addresses
        let host4 = AllowedIP::from_str("8.8.8.8/32").unwrap();
        assert_eq!(host4.addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(host4.cidr, 32);
    }

    #[test]
    fn test_allowed_ip_from_str_invalid() {
        // No CIDR
        assert!(AllowedIP::from_str("192.168.1.1").is_err());
        
        // Invalid IP
        assert!(AllowedIP::from_str("999.999.999.999/24").is_err());
        
        // Invalid CIDR for IPv4
        assert!(AllowedIP::from_str("192.168.1.0/33").is_err());
        
        // Invalid CIDR for IPv6
        assert!(AllowedIP::from_str("2001:db8::/129").is_err());
        
        // Multiple slashes
        assert!(AllowedIP::from_str("192.168.1.0/24/8").is_err());
        
        // Empty string
        assert!(AllowedIP::from_str("").is_err());
    }

    #[test]
    fn test_endpoint_default() {
        let endpoint = Endpoint::default();
        assert!(endpoint.addr.is_none());
        assert!(endpoint.conn.is_none());
    }

    #[test]
    fn test_peer_creation() {
        let tunnel = create_test_tunnel();
        let index = 12345;
        let endpoint = Some(SocketAddr::from_str("192.168.1.1:51820").unwrap());
        let allowed_ips = create_test_allowed_ips();
        let preshared_key = Some([42u8; 32]);

        let peer = Peer::new(tunnel, index, endpoint, &allowed_ips, preshared_key);

        assert_eq!(peer.index(), index);
        assert_eq!(peer.endpoint().addr, endpoint);
        assert!(peer.endpoint().conn.is_none());
        assert_eq!(peer.preshared_key(), Some(&[42u8; 32]));
    }

    #[test]
    fn test_peer_creation_no_endpoint() {
        let tunnel = create_test_tunnel();
        let index = 54321;
        let allowed_ips = create_test_allowed_ips();

        let peer = Peer::new(tunnel, index, None, &allowed_ips, None);

        assert_eq!(peer.index(), index);
        assert!(peer.endpoint().addr.is_none());
        assert!(peer.preshared_key().is_none());
    }

    #[test]
    fn test_is_allowed_ip() {
        let tunnel = create_test_tunnel();
        let allowed_ips = create_test_allowed_ips();
        let peer = Peer::new(tunnel, 1, None, &allowed_ips, None);

        // Should allow IPs in the allowed ranges
        assert!(peer.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(peer.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(peer.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));

        // Should not allow IPs outside the allowed ranges
        assert!(!peer.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!peer.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))));
        
        // Test IPv6
        assert!(peer.is_allowed_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1))));
        assert!(!peer.is_allowed_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_allowed_ips_iterator() {
        let tunnel = create_test_tunnel();
        let allowed_ips = create_test_allowed_ips();
        let peer = Peer::new(tunnel, 1, None, &allowed_ips, None);

        let collected: Vec<(IpAddr, u8)> = peer.allowed_ips().collect();
        assert_eq!(collected.len(), 3);
        
        // Check that all our test IPs are present
        let has_192_168 = collected.iter().any(|(ip, cidr)| {
            matches!(ip, IpAddr::V4(v4) if v4.octets() == [192, 168, 1, 0]) && *cidr == 24
        });
        let has_10_0 = collected.iter().any(|(ip, cidr)| {
            matches!(ip, IpAddr::V4(v4) if v4.octets() == [10, 0, 0, 0]) && *cidr == 8
        });
        let has_ipv6 = collected.iter().any(|(ip, cidr)| {
            matches!(ip, IpAddr::V6(_)) && *cidr == 32
        });
        
        assert!(has_192_168);
        assert!(has_10_0);
        assert!(has_ipv6);
    }

    #[test]
    fn test_set_endpoint() {
        let tunnel = create_test_tunnel();
        let peer = Peer::new(tunnel, 1, None, &[], None);
        
        let new_endpoint = SocketAddr::from_str("10.0.0.1:12345").unwrap();
        peer.set_endpoint(new_endpoint);
        
        assert_eq!(peer.endpoint().addr, Some(new_endpoint));
    }

    #[test]
    fn test_set_endpoint_replaces_existing() {
        let tunnel = create_test_tunnel();
        let initial_endpoint = SocketAddr::from_str("192.168.1.1:51820").unwrap();
        let peer = Peer::new(tunnel, 1, Some(initial_endpoint), &[], None);
        
        let new_endpoint = SocketAddr::from_str("10.0.0.1:12345").unwrap();
        peer.set_endpoint(new_endpoint);
        
        assert_eq!(peer.endpoint().addr, Some(new_endpoint));
    }

    #[test]
    fn test_shutdown_endpoint_no_connection() {
        let tunnel = create_test_tunnel();
        let peer = Peer::new(tunnel, 1, None, &[], None);
        
        // Should not panic when no connection exists
        peer.shutdown_endpoint();
        assert!(peer.endpoint().conn.is_none());
    }

    #[test]
    fn test_peer_getters() {
        let tunnel = create_test_tunnel();
        let index = 99999;
        let preshared = [123u8; 32];
        let peer = Peer::new(tunnel, index, None, &[], Some(preshared));
        
        assert_eq!(peer.index(), index);
        assert_eq!(peer.preshared_key(), Some(&preshared));
        
        // These should return tunnel values
        assert!(peer.time_since_last_handshake().is_none()); // No active session
        assert!(peer.persistent_keepalive().is_none()); // No keepalive set
    }

    #[test]
    fn test_update_timers() {
        let tunnel = create_test_tunnel();
        let mut peer = Peer::new(tunnel, 1, None, &[], None);
        let mut buffer = [0u8; 1024];
        
        // Should complete without error
        let result = peer.update_timers(&mut buffer);
        assert!(matches!(result, TunnResult::Done));
    }

    #[test]
    fn test_allowed_ip_ordering() {
        let ip1 = AllowedIP::from_str("192.168.1.0/24").unwrap();
        let ip2 = AllowedIP::from_str("192.168.2.0/24").unwrap();
        let ip3 = AllowedIP::from_str("192.168.1.0/25").unwrap(); // Same network, different CIDR

        assert!(ip1 < ip2);
        assert!(ip1 < ip3); // Same addr, smaller CIDR comes first
        
        // Test equality
        let ip1_copy = AllowedIP::from_str("192.168.1.0/24").unwrap();
        assert_eq!(ip1, ip1_copy);
    }

    #[test]
    fn test_endpoint_concurrent_access() {
        use std::sync::Arc;
        use std::thread;
        
        let tunnel = create_test_tunnel();
        let peer = Arc::new(Peer::new(tunnel, 1, None, &[], None));
        
        let handles: Vec<_> = (0..4).map(|i| {
            let peer_clone = Arc::clone(&peer);
            thread::spawn(move || {
                for j in 0..10 {
                    let addr = SocketAddr::from_str(&format!("192.168.1.{}:{}", i, 1000 + j)).unwrap();
                    peer_clone.set_endpoint(addr);
                    
                    // Read endpoint
                    let _ = peer_clone.endpoint().addr;
                    
                    if j % 3 == 0 {
                        peer_clone.shutdown_endpoint();
                    }
                }
            })
        }).collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should complete without deadlock or panic
        assert!(peer.endpoint().addr.is_some());
    }
}
