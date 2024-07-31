// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::device::{AllowedIps, Error, MakeExternalBoringtun};
use crate::noise::errors::WireGuardError;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};

use std::os::fd::AsRawFd;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: TunnLock,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: RwLock<AllowedIps<()>>,
    preshared_key: RwLock<Option<[u8; 32]>>,
    protect: Arc<dyn MakeExternalBoringtun>,
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
        protect: Arc<dyn MakeExternalBoringtun>,
    ) -> Peer {
        Peer {
            tunnel: TunnLock::new(tunnel),
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: RwLock::new(allowed_ips.iter().map(|ip| (ip, ())).collect()),
            preshared_key: RwLock::new(preshared_key),
            protect,
        }
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            // TODO(pna) what does this Both do?
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

    pub fn connect_endpoint(&self, port: u16) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .expect("Attempt to connect to undefined endpoint");

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.set_nonblocking(true)?;
        // fw_mark is being set inside make_external(), so no need to set it twice as in Cloudflare's repo.
        self.protect.make_external(udp_conn.as_raw_fd());
        // Also mind that all socket setup functions should be called before .connect().
        udp_conn.connect(&addr.into())?;

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );
        // TODO(pna): WTF is this?
        endpoint.conn = Some(udp_conn.try_clone().unwrap());

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.read().find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> Vec<AllowedIP> {
        self.allowed_ips
            .read()
            .iter()
            .map(|(_, ip, cidr)| AllowedIP {
                addr: ip,
                cidr: cidr,
            })
            .collect()
    }

    pub fn add_allowed_ips(&self, new_allowed_ips: &[AllowedIP]) {
        let mut allowed_ips = self.allowed_ips.write();

        for AllowedIP { addr, cidr } in new_allowed_ips {
            allowed_ips.insert(*addr, *cidr as u32, ());
        }
    }

    pub fn set_allowed_ips(&self, allowed_ips: &[AllowedIP]) {
        *self.allowed_ips.write() = allowed_ips.iter().map(|ip| (ip, ())).collect();
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn last_handshake_time(&self) -> Option<std::time::Duration> {
        self.tunnel.last_handshake_time()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn set_persistent_keepalive(&self, keepalive: u16) {
        self.tunnel.set_persistent_keepalive(keepalive);
    }

    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        *self.preshared_key.read()
    }

    pub fn set_preshared_key(&self, key: [u8; 32]) {
        let mut preshared_key = self.preshared_key.write();

        let _ = preshared_key.replace(key);
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

/// A portback of https://github.com/NordSecurity/boringtun/blob/51b0a45e6de490cfabbc09c8c14dccf1e0172c59/boringtun/src/noise/mod.rs#L136
pub(crate) struct TunnLock {
    inner: RwLock<Tunn>,
}

impl TunnLock {
    pub fn new(tunn: Tunn) -> Self {
        Self {
            inner: RwLock::new(tunn),
        }
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &self,
        static_private: x25519_dalek::StaticSecret,
        static_public: x25519_dalek::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<(), WireGuardError> {
        self.inner
            .write()
            .set_static_private(static_private, static_public, rate_limiter)
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.write().encapsulate(src, dst)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.inner.write().decapsulate(src_addr, datagram, dst)
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.inner.read().stats()
    }

    pub fn peer_static_public(&self) -> x25519_dalek::PublicKey {
        self.inner.read().peer_static_public
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.write().update_timers(dst)
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.inner.read().persistent_keepalive()
    }

    pub fn set_persistent_keepalive(&self, keepalive: u16) {
        self.inner.write().set_persistent_keepalive(keepalive);
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.inner.read().time_since_last_handshake()
    }

    pub fn last_handshake_time(&self) -> Option<Duration> {
        self.inner.read().last_handshake_time()
    }

    pub fn handle_verified_packet<'a>(&self, packet: Packet, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.write().handle_verified_packet(packet, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Introduced this test to prevent LLT-5351 recurring in the future:
    #[test]
    fn test_connect_endpoint() {
        let a_secret_key = StaticSecret::random_from_rng(&mut rand::rngs::StdRng::from_entropy());

        let b_secret_key = StaticSecret::random_from_rng(&mut rand::rngs::StdRng::from_entropy());
        let b_public_key = PublicKey::from(&b_secret_key);

        let tunnel = Tunn::new(a_secret_key, b_public_key, None, None, 0, None).unwrap();
        let peer = Peer::new(
            tunnel,
            0,
            Some(SocketAddr::new(IpAddr::from([1, 2, 3, 4]), 54321)),
            &[],
            None,
            Arc::new(crate::device::MakeExternalBoringtunNoop),
        );

        peer.connect_endpoint(12345).unwrap();
    }
}
