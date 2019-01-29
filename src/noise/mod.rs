pub mod errors;
pub mod h2n;
pub mod handshake;
mod session;
mod tests;
mod timers;

use crypto::x25519::X25519Key;
use noise::errors::WireGuardError;
use noise::handshake::Handshake;
use noise::timers::{TimerName, Timers};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
pub const IPV4_DST_IP_OFF: usize = 16;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
pub const IPV6_DST_IP_OFF: usize = 24;

const MAX_QUEUE_DEPTH: usize = 256;
const N_SESSIONS: usize = 4; // number of sessions in the ring, better keep a PoT

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

#[derive(Eq, PartialEq, PartialOrd, Debug)]
pub enum Verbosity {
    None,
    Info,
    Debug,
    All,
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    handshake: spin::Mutex<handshake::Handshake>, // The handshake currently in progress
    sessions: [Arc<spin::RwLock<Option<session::Session>>>; N_SESSIONS], // The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    current: AtomicUsize, // Index of most recently used session
    packet_queue: spin::Mutex<VecDeque<Vec<u8>>>, // Queue to store blocked packets
    timers: timers::Timers, // Keeps tabs on the expiring timers

    logger: Option<spin::Mutex<Box<Fn(&str) + Send>>>,
    verbosity: Verbosity,
}

impl Tunn {
    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: &X25519Key,
        peer_static_public: &X25519Key,
        index: u32,
    ) -> Result<Box<Tunn>, &'static str> {
        let tunn = Tunn {
            handshake: spin::Mutex::new(Handshake::new(
                static_private.as_bytes(),
                peer_static_public.as_bytes(),
                index << 8,
            )),

            sessions: Default::default(),
            current: Default::default(),

            packet_queue: spin::Mutex::new(VecDeque::new()),
            timers: Timers::new(),

            logger: None,
            verbosity: Verbosity::None,
        };

        Ok(Box::new(tunn))
    }

    pub fn set_logger(&mut self, logger: Box<Fn(&str) + Send>, verbosity: Verbosity) {
        self.logger = Some(spin::Mutex::new(logger));
        self.verbosity = verbosity;
    }

    /// Receives an IP packet from the tunnel interface and encapsulates it.
    /// Returns wireguard_result.
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn tunnel_to_network<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current.load(Ordering::Acquire);
        if let Some(ref session) = *self.sessions[current % N_SESSIONS].read() {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            TunnResult::WriteToNetwork(packet)
        } else {
            // If there is no session, queue the packet for future retry
            self.queue_packet(src);
            // Initiate a new handshake if none is in progress
            self.format_handshake_initiation(dst, false)
        }
    }

    /// Receives a UDP packet from the network and parses it.
    /// Returns wireguard_result.
    /// If the result is of type TunnResult::WriteToNetwork, must repeat the call with empty src,
    /// until TunnResult::Done is returned.
    pub fn network_to_tunnel<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        if src.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        match src[0] {
            1 => {
                self.log(Verbosity::Debug, "Received handhsake_initiation");
                let mut handshake = self.handshake.lock();
                match handshake.receive_handshake_initialization(src, dst) {
                    Ok((packet, session)) => {
                        self.log(Verbosity::Debug, "Sending handshake_reponse");
                        let index = session.local_index();
                        *self.sessions[index % N_SESSIONS].write() = Some(session);
                        self.timer_tick_session_established(false);
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        self.timer_tick(TimerName::TimeLastPacketSent);
                        TunnResult::WriteToNetwork(packet)
                    }
                    Err(e) => TunnResult::Err(e),
                }
            }
            2 => {
                self.log(Verbosity::Debug, "Received handhsake_response");
                let mut handshake = self.handshake.lock();
                match handshake.receive_handshake_response(src) {
                    Ok(session) => {
                        let keepalive_packet = session.format_packet_data(&[], dst);
                        let index = session.local_index();
                        *self.sessions[index % N_SESSIONS].write() = Some(session);
                        // Make session the current session
                        self.current.store(index, Ordering::Release);
                        self.timer_tick_session_established(true);
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        TunnResult::WriteToNetwork(keepalive_packet) // Send a keepalive as a response
                    }
                    Err(e) => TunnResult::Err(e),
                }
            }
            3 => {
                self.log(Verbosity::Debug, "Received cookie_reply");
                let mut handshake = self.handshake.lock();
                match handshake.receive_cookie_reply(src, dst) {
                    Ok(packet) => {
                        self.log(Verbosity::Debug, "Sending handhsake_initiation with cookie");
                        self.timer_tick(TimerName::TimeCookieReceived);
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        self.timer_tick(TimerName::TimeLastPacketSent);
                        TunnResult::WriteToNetwork(packet)
                    }
                    Err(e) => TunnResult::Err(e),
                }
            }
            4 => self.receive_packet_data(src, dst),
            _ => {
                self.log(Verbosity::Debug, &format!("Illegal packet {}", src[0]));
                TunnResult::Err(WireGuardError::InvalidPacket)
            }
        }
    }

    fn send_queued_packet<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.tunnel_to_network(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r @ _ => return r,
            }
        }
        TunnResult::Done
    }

    // Formats a new handhsake initiation message and store it in dst.
    fn format_handshake_initiation<'a>(&self, dst: &'a mut [u8], resend: bool) -> TunnResult<'a> {
        let mut handshake = self.handshake.lock();
        if handshake.is_in_progress() && !resend {
            return TunnResult::Done;
        }

        match handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                self.log(Verbosity::Debug, "Sending handshake_initiation");
                self.timer_tick(TimerName::TimeLastHandshakeStarted);
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    // Decrypts a data packet, and stores the decapsulated packet in dst.
    fn receive_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        if src.len() < session::IDX_OFF + session::IDX_SZ {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }
        // Extract the reciever index
        let idx = u32::from_le_bytes([
            src[session::IDX_OFF + 0],
            src[session::IDX_OFF + 1],
            src[session::IDX_OFF + 2],
            src[session::IDX_OFF + 3],
        ]) as usize;

        // Get the (possibly) right session
        if let Some(ref session) = *self.sessions[idx % N_SESSIONS].read() {
            match session.receive_packet_data(src, dst) {
                Ok(packet) => {
                    self.current.store(idx, Ordering::Relaxed); // The exact session we use is not important as long as it is valid
                    self.timer_tick(TimerName::TimeLastPacketReceived);
                    self.check_decapsulated_packet(packet)
                }
                Err(e) => TunnResult::Err(e),
            }
        } else {
            // No session for that index exists (any longer?)
            TunnResult::Err(WireGuardError::NoCurrentSession)
        }
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => Some(IpAddr::from([
                packet[IPV4_DST_IP_OFF + 0],
                packet[IPV4_DST_IP_OFF + 1],
                packet[IPV4_DST_IP_OFF + 2],
                packet[IPV4_DST_IP_OFF + 3],
            ])),
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => Some(IpAddr::from([
                packet[IPV6_DST_IP_OFF + 0],
                packet[IPV6_DST_IP_OFF + 1],
                packet[IPV6_DST_IP_OFF + 2],
                packet[IPV6_DST_IP_OFF + 3],
                packet[IPV6_DST_IP_OFF + 4],
                packet[IPV6_DST_IP_OFF + 5],
                packet[IPV6_DST_IP_OFF + 6],
                packet[IPV6_DST_IP_OFF + 7],
                packet[IPV6_DST_IP_OFF + 8],
                packet[IPV6_DST_IP_OFF + 9],
                packet[IPV6_DST_IP_OFF + 10],
                packet[IPV6_DST_IP_OFF + 11],
                packet[IPV6_DST_IP_OFF + 12],
                packet[IPV6_DST_IP_OFF + 13],
                packet[IPV6_DST_IP_OFF + 14],
                packet[IPV6_DST_IP_OFF + 15],
            ])),
            _ => None,
        }
    }

    fn check_decapsulated_packet<'a>(&self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (packet_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => (
                u16::from_be_bytes([packet[IPV4_LEN_OFF + 0], packet[IPV4_LEN_OFF + 1]]) as usize,
                IpAddr::from([
                    packet[IPV4_SRC_IP_OFF + 0],
                    packet[IPV4_SRC_IP_OFF + 1],
                    packet[IPV4_SRC_IP_OFF + 2],
                    packet[IPV4_SRC_IP_OFF + 3],
                ]),
            ),
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => (
                u16::from_be_bytes([packet[IPV6_LEN_OFF + 0], packet[IPV6_LEN_OFF + 1]]) as usize,
                IpAddr::from([
                    packet[IPV6_SRC_IP_OFF + 0],
                    packet[IPV6_SRC_IP_OFF + 1],
                    packet[IPV6_SRC_IP_OFF + 2],
                    packet[IPV6_SRC_IP_OFF + 3],
                    packet[IPV6_SRC_IP_OFF + 4],
                    packet[IPV6_SRC_IP_OFF + 5],
                    packet[IPV6_SRC_IP_OFF + 6],
                    packet[IPV6_SRC_IP_OFF + 7],
                    packet[IPV6_SRC_IP_OFF + 8],
                    packet[IPV6_SRC_IP_OFF + 9],
                    packet[IPV6_SRC_IP_OFF + 10],
                    packet[IPV6_SRC_IP_OFF + 11],
                    packet[IPV6_SRC_IP_OFF + 12],
                    packet[IPV6_SRC_IP_OFF + 13],
                    packet[IPV6_SRC_IP_OFF + 14],
                    packet[IPV6_SRC_IP_OFF + 15],
                ]),
            ),
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if packet_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..packet_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..packet_len], addr),
        }
    }

    fn queue_packet(&self, packet: &[u8]) {
        let mut q = self.packet_queue.lock();
        if q.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            q.push_back(packet.to_vec());
        }
    }

    fn requeue_packet(&self, packet: Vec<u8>) {
        let mut q = self.packet_queue.lock();
        if q.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            q.push_front(packet);
        }
    }

    fn dequeue_packet(&self) -> Option<Vec<u8>> {
        let mut q = self.packet_queue.lock();
        q.pop_front()
    }

    pub fn log(&self, lvl: Verbosity, entry: &str) {
        if let Some(ref logger) = self.logger {
            if self.verbosity >= lvl {
                logger.lock()(entry)
            }
        }
    }
}
