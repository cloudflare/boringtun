use crate::device::allowed_ips::AllowedIps;
use crate::device::peer::Peer;
use crate::device::tun::TunSocket;
use crate::device::{DeviceConfig, Error, IndexLfsr};
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<UdpSocket>,
    udp6: Option<UdpSocket>,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

impl Device {
    pub async fn event_loop(self) {}

    fn handle_udp_packet(
        &self,
        udp: &UdpSocket,
        addr: SocketAddr,
        packet: &[u8],
        dst_buf: &mut [u8],
    ) {
        let (private_key, public_key) = self.key_pair.as_ref().expect("Key not set");

        // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
        let parsed_packet = match self.rate_limiter.as_ref().unwrap().verify_packet(
            Some(addr.ip()),
            packet,
            dst_buf,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let _: Result<_, _> = udp.try_send_to(cookie, addr);
                return;
            }
            Err(_) => return,
        };

        let peer = match &parsed_packet {
            Packet::HandshakeInit(p) => parse_handshake_anon(private_key, public_key, p)
                .ok()
                .and_then(|hh| {
                    self.peers
                        .get(&x25519::PublicKey::from(hh.peer_static_public))
                }),
            Packet::HandshakeResponse(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
        };

        let peer = match peer {
            None => return,
            Some(peer) => peer,
        };

        let mut p = peer.lock();

        // We found a peer, use it to decapsulate the message+
        let mut flush = false; // Are there packets to send from the queue?
        match p
            .tunnel
            .handle_verified_packet(parsed_packet, &mut dst_buf[..])
        {
            TunnResult::Done => {}
            TunnResult::Err(_) => return,
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                let _: Result<_, _> = udp.try_send_to(packet, addr);
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    self.iface.write4(packet);
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    self.iface.write6(packet);
                }
            }
        };

        if flush {
            // Flush pending queue
            while let TunnResult::WriteToNetwork(packet) =
                p.tunnel.decapsulate(None, &[], &mut dst_buf[..])
            {
                let _: Result<_, _> = udp.try_send_to(packet, addr);
            }
        }
    }

    fn handle_iface_packet(&self, src: &[u8], dst_buf: &mut [u8]) {
        let dst_addr = match Tunn::dst_address(src) {
            Some(addr) => addr,
            None => return,
        };

        let mut peer = match self.peers_by_ip.find(dst_addr) {
            Some(peer) => peer.lock(),
            None => return,
        };

        match peer.tunnel.encapsulate(src, dst_buf) {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                tracing::error!(message = "Encapsulate error", error = ?e)
            }
            TunnResult::WriteToNetwork(packet) => {
                let endpoint = peer.endpoint_mut();
                if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                    let _: Result<_, _> = self.udp4.as_ref().unwrap().try_send_to(packet, addr);
                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                    let _: Result<_, _> = self.udp6.as_ref().unwrap().try_send_to(packet, addr);
                } else {
                    tracing::error!("No endpoint");
                }
            }
            _ => panic!("Unexpected result from encapsulate"),
        };
    }
}
