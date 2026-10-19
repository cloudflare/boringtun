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
  activation_pending: bool,
  activation_requested_at: Option<std::time::Instant>,
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
      activation_pending: false,
      activation_requested_at: None,
    }
  }

  /// Update routing metadata without replacing the encrypted session or peer index.
  pub(crate) fn update_config(
    &mut self,
    replace_ips: bool,
    allowed_ips: &[AllowedIP],
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
  ) {
    if replace_ips {
      self.allowed_ips.clear();
    }
    for ip in allowed_ips {
      self.allowed_ips.insert(ip.addr, ip.cidr as u32, ());
    }
    if let Some(endpoint) = endpoint {
      self.set_endpoint(endpoint);
    }
    if let Some(keepalive) = keepalive {
      self.tunnel.set_persistent_keepalive(keepalive);
    }
  }

  pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
    if std::mem::take(&mut self.activation_pending) {
      // An in-progress handshake keeps its native retry timer. Expired
      // handshakes can restart without clearing established sessions.
      return self.tunnel.format_handshake_initiation(dst, false);
    }
    self.tunnel.update_timers(dst)
  }

  pub(crate) fn request_activation(&mut self) -> bool {
    if self.endpoint().addr.is_none() {
      return false;
    }
    if self
      .activation_requested_at
      .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(6))
    {
      return true; // coalesced, not proof that the endpoint is reachable
    }
    self.activation_requested_at = Some(std::time::Instant::now());
    self.activation_pending = true;
    true
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

  pub fn connect_endpoint(&self, port: u16, fwmark: Option<u32>) -> Result<socket2::Socket, Error> {
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
mod yat_tests {
  use super::*;
  use crate::x25519::{PublicKey, StaticSecret};

  fn packet(result: TunnResult<'_>) -> Vec<u8> {
    match result {
      TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
      _ => panic!("expected a WireGuard network packet"),
    }
  }

  fn candidate_pair() -> (Peer, Tunn) {
    let left = StaticSecret::from([31; 32]);
    let right = StaticSecret::from([32; 32]);
    let candidate = Peer::new(
      Tunn::new(
        left.clone(),
        PublicKey::from(&right),
        None,
        Some(25),
        31,
        None,
      ),
      31,
      Some("192.0.2.2:58020".parse().unwrap()),
      &[],
      None,
    );
    (
      candidate,
      Tunn::new(right, PublicKey::from(&left), None, Some(25), 32, None),
    )
  }

  #[test]
  fn activation_handshakes_without_routes_and_coalesces_without_replacing_session() {
    let (mut candidate, mut remote) = candidate_pair();
    let mut buf = [0; 2048];
    assert!(candidate.request_activation());
    assert!(candidate.request_activation());
    let init = packet(candidate.update_timers(&mut buf));
    assert_eq!(&init[..4], &1u32.to_le_bytes());
    let response = packet(remote.decapsulate(None, &init, &mut buf));
    let keepalive = packet(candidate.tunnel.decapsulate(None, &response, &mut buf));
    let receiver = keepalive[4..8].to_vec();
    assert!(matches!(
      remote.decapsulate(None, &keepalive, &mut buf),
      TunnResult::Done
    ));
    assert!(candidate.time_since_last_handshake().is_some());
    assert!(candidate.request_activation());
    assert!(matches!(
      candidate.update_timers(&mut buf),
      TunnResult::Done
    ));
    let transport = packet(candidate.tunnel.encapsulate(&[], &mut buf));
    assert_eq!(&transport[..4], &4u32.to_le_bytes());
    assert_eq!(&transport[4..8], receiver.as_slice());
    assert!(matches!(
      remote.decapsulate(None, &transport, &mut buf),
      TunnResult::Done
    ));
    assert_eq!(candidate.index(), 31);
    assert_eq!(candidate.allowed_ips().count(), 0);
    assert_eq!(
      candidate.endpoint().addr.unwrap().to_string(),
      "192.0.2.2:58020"
    );
  }

  #[test]
  fn activation_requires_an_existing_endpoint() {
    let (mut candidate, _) = candidate_pair();
    candidate.endpoint_mut().addr = None;
    assert!(!candidate.request_activation());
    assert!(!candidate.activation_pending);
  }

  #[test]
  #[cfg(feature = "mock-instant")]
  fn activation_restarts_an_expired_native_handshake() {
    let (mut candidate, mut remote) = candidate_pair();
    let mut buf = [0; 2048];
    let _lost = packet(
      candidate
        .tunnel
        .format_handshake_initiation(&mut buf, false),
    );
    mock_instant::MockClock::advance(std::time::Duration::from_secs(91));
    let _ = candidate.update_timers(&mut buf);
    assert!(candidate.tunnel.is_expired());
    // Persistent keepalive alone leaves the expired tunnel stopped.
    assert!(matches!(
      candidate.update_timers(&mut buf),
      TunnResult::Err(_)
    ));
    assert!(candidate.request_activation());
    let init = packet(candidate.update_timers(&mut buf));
    let response = packet(remote.decapsulate(None, &init, &mut buf));
    let keepalive = packet(candidate.tunnel.decapsulate(None, &response, &mut buf));
    assert!(matches!(
      remote.decapsulate(None, &keepalive, &mut buf),
      TunnResult::Done
    ));
    assert!(!candidate.tunnel.is_expired());
    assert!(candidate.time_since_last_handshake().is_some());
    assert_eq!(candidate.allowed_ips().count(), 0);
  }

  #[test]
  fn allowed_ip_handoff_preserves_established_session_and_receiver_index() {
    let left_key = StaticSecret::from([7; 32]);
    let right_key = StaticSecret::from([8; 32]);
    let mut left = Peer::new(
      Tunn::new(
        left_key.clone(),
        PublicKey::from(&right_key),
        None,
        Some(25),
        17,
        None,
      ),
      17,
      Some("192.0.2.2:58020".parse().unwrap()),
      &["10.24.0.2/32".parse().unwrap()],
      None,
    );
    let mut right = Tunn::new(
      right_key,
      PublicKey::from(&left_key),
      None,
      Some(25),
      18,
      None,
    );
    let mut buf = [0u8; 2048];
    let init = packet(left.tunnel.format_handshake_initiation(&mut buf, false));
    let response = packet(right.decapsulate(None, &init, &mut buf));
    let keepalive = packet(left.tunnel.decapsulate(None, &response, &mut buf));
    assert!(matches!(
      right.decapsulate(None, &keepalive, &mut buf),
      TunnResult::Done
    ));
    assert!(left.time_since_last_handshake().is_some());
    let index = left.index();
    let counters = left.tunnel.stats();
    // Route moves to relay, then returns. Neither transition may reset Tunn.
    left.update_config(true, &[], None, Some(25));
    assert!(!left.is_allowed_ip(Ipv4Addr::new(10, 24, 0, 2)));
    left.update_config(true, &["10.24.0.2/32".parse().unwrap()], None, Some(25));
    assert!(left.is_allowed_ip(Ipv4Addr::new(10, 24, 0, 2)));
    assert_eq!(left.index(), index);
    assert_eq!(left.tunnel.stats().1, counters.1);
    assert_eq!(left.tunnel.stats().2, counters.2);
    assert!(left.time_since_last_handshake().is_some());
    // Existing session immediately produces transport data (type 4), not
    // a new handshake (type 1), and the other side can authenticate it.
    let transport = packet(left.tunnel.encapsulate(&[], &mut buf));
    assert_eq!(&transport[..4], &4u32.to_le_bytes());
    assert!(matches!(
      right.decapsulate(None, &transport, &mut buf),
      TunnResult::Done
    ));
  }

  #[test]
  fn direct_handshake_succeeds_while_remote_data_routes_are_on_relay() {
    let left_key = StaticSecret::from([11; 32]);
    let right_key = StaticSecret::from([12; 32]);
    let mut left = Tunn::new(
      left_key.clone(),
      PublicKey::from(&right_key),
      None,
      Some(25),
      21,
      None,
    );
    // Right has handed the member /32 to its relay, but retains the
    // direct peer and endpoint. AllowedIPs gates inner IP traffic only.
    let mut right = Peer::new(
      Tunn::new(
        right_key,
        PublicKey::from(&left_key),
        None,
        Some(25),
        22,
        None,
      ),
      22,
      Some("192.0.2.1:58020".parse().unwrap()),
      &[],
      None,
    );
    let mut buf = [0u8; 2048];
    assert!(!right.is_allowed_ip(Ipv4Addr::new(10, 24, 0, 2)));
    let init = packet(left.format_handshake_initiation(&mut buf, false));
    let response = packet(right.tunnel.decapsulate(None, &init, &mut buf));
    let keepalive = packet(left.decapsulate(None, &response, &mut buf));
    assert!(matches!(
      right.tunnel.decapsulate(None, &keepalive, &mut buf),
      TunnResult::Done
    ));
    assert!(left.time_since_last_handshake().is_some());
    assert!(right.time_since_last_handshake().is_some());
    assert!(right.allowed_ips().next().is_none());
  }
}
