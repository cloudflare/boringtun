// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
mod session;
mod tests;
mod timers;

use crate::crypto::x25519::*;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::timers::{TimerName, Timers};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
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

#[derive(Eq, PartialEq, PartialOrd, Debug, Clone, Copy)]
pub enum Verbosity {
    None,
    Info,
    Debug,
    All,
}

impl FromStr for Verbosity {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "silent" => Ok(Verbosity::None),
            "info" => Ok(Verbosity::Info),
            "debug" => Ok(Verbosity::Debug),
            "max" => Ok(Verbosity::All),
            _ => Err(()),
        }
    }
}

type LogFunction = Box<Fn(&str) + Send>;

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    handshake: spin::Mutex<handshake::Handshake>, // The handshake currently in progress
    sessions: [Arc<spin::RwLock<Option<session::Session>>>; N_SESSIONS], // The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    current: AtomicUsize, // Index of most recently used session
    packet_queue: spin::Mutex<VecDeque<Vec<u8>>>, // Queue to store blocked packets
    timers: timers::Timers, // Keeps tabs on the expiring timers
    tx_bytes: AtomicUsize,
    rx_bytes: AtomicUsize,

    logger: Option<spin::Mutex<LogFunction>>,
    verbosity: Verbosity,
}

impl Tunn {
    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: Arc<X25519SecretKey>,
        peer_static_public: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) -> Result<Box<Tunn>, &'static str> {
        let tunn = Tunn {
            handshake: spin::Mutex::new(
                Handshake::new(
                    static_private,
                    peer_static_public,
                    index << 8,
                    preshared_key,
                )
                .map_err(|_| "Invalid parameters")?,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: spin::Mutex::new(VecDeque::new()),
            timers: Timers::new(persistent_keepalive),

            logger: None,
            verbosity: Verbosity::None,
        };

        Ok(Box::new(tunn))
    }

    /// Set the log function and logging level for the tunnel
    pub fn set_logger(&mut self, logger: LogFunction, verbosity: Verbosity) {
        self.logger = Some(spin::Mutex::new(logger));
        self.verbosity = verbosity;
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &self,
        static_private: Arc<X25519SecretKey>,
    ) -> Result<(), WireGuardError> {
        self.handshake.lock().set_static_private(static_private)?;
        for s in &self.sessions {
            *s.write() = None;
        }
        Ok(())
    }

    /// Receives an IP packet from the tunnel interface and encapsulates it.
    /// Returns wireguard_result.
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn tunnel_to_network<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current.load(Ordering::SeqCst);
        if let Some(ref session) = *self.sessions[current % N_SESSIONS].read() {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            if !src.is_empty() {
                // Only tick timer if not keepalive
                self.timer_tick(TimerName::TimeLastPacketSent);
            }
            self.timer_tick(TimerName::TimeLastDataPacketSent);
            self.tx_bytes.fetch_add(src.len(), Ordering::Relaxed);
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
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
                self.log(Verbosity::Debug, "Received handshake_initiation");
                let mut handshake = self.handshake.lock();
                match handshake.receive_handshake_initialization(src, dst) {
                    Ok((packet, session)) => {
                        self.log(Verbosity::Debug, "Sending handshake_response");
                        let index = session.local_index();
                        *self.sessions[index % N_SESSIONS].write() = Some(session);
                        self.timer_tick_session_established(false); // New session established, we are not the initiator
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
                        self.current.store(index, Ordering::SeqCst);
                        self.timer_tick_session_established(true); // New session established, we are the initiator
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        TunnResult::WriteToNetwork(keepalive_packet) // Send a keepalive as a response
                    }
                    Err(e) => TunnResult::Err(e),
                }
            }
            3 => {
                self.log(Verbosity::Debug, "Received cookie_reply");
                let mut handshake = self.handshake.lock();
                match handshake.receive_cookie_reply(src) {
                    Ok(_) => {
                        self.log(Verbosity::Debug, "Sending handhsake_initiation with cookie");
                        self.timer_tick(TimerName::TimeCookieReceived);
                        TunnResult::Done
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

    // Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.tunnel_to_network(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    // Formats a new handhsake initiation message and store it in dst. If force_resend is true will send
    // a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        let mut handshake = self.handshake.lock();
        if handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !handshake.is_in_progress();

        match handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                self.log(Verbosity::Debug, "Sending handshake_initiation");
                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
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
            src[session::IDX_OFF],
            src[session::IDX_OFF + 1],
            src[session::IDX_OFF + 2],
            src[session::IDX_OFF + 3],
        ]) as usize;

        // Get the (possibly) right session
        if let Some(ref session) = *self.sessions[idx % N_SESSIONS].read() {
            match session.receive_packet_data(src, dst) {
                Ok(packet) => {
                    self.current.store(idx, Ordering::Relaxed); // The exact session we use is not important as long as it is valid
                    if !packet.is_empty() {
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                    }
                    self.timer_tick(TimerName::TimeLastDataPacketReceived);
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
                packet[IPV4_DST_IP_OFF],
                packet[IPV4_DST_IP_OFF + 1],
                packet[IPV4_DST_IP_OFF + 2],
                packet[IPV4_DST_IP_OFF + 3],
            ])),
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => Some(IpAddr::from([
                packet[IPV6_DST_IP_OFF],
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
                u16::from_be_bytes([packet[IPV4_LEN_OFF], packet[IPV4_LEN_OFF + 1]]) as usize,
                IpAddr::from([
                    packet[IPV4_SRC_IP_OFF],
                    packet[IPV4_SRC_IP_OFF + 1],
                    packet[IPV4_SRC_IP_OFF + 2],
                    packet[IPV4_SRC_IP_OFF + 3],
                ]),
            ),
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => (
                u16::from_be_bytes([packet[IPV6_LEN_OFF], packet[IPV6_LEN_OFF + 1]]) as usize
                    + IPV6_MIN_HEADER_SIZE,
                IpAddr::from([
                    packet[IPV6_SRC_IP_OFF],
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

        self.rx_bytes.fetch_add(packet_len, Ordering::Relaxed);

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
                logger.lock()(&format!("[{:?}] {}", lvl, entry));
            }
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<u64>, usize, usize) {
        let time = if let Some(time) = self.time_since_last_handshake() {
            Some(time.as_secs())
        } else {
            None
        };
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);

        (time, tx_bytes, rx_bytes)
    }
}

#[inline(always)]
pub fn make_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]> + std::borrow::Borrow<[T]>,
    T: Copy,
{
    let mut arr: A = Default::default();
    let arr_len = arr.borrow().len();
    <A as AsMut<[T]>>::as_mut(&mut arr).copy_from_slice(&slice[0..arr_len]);
    arr
}
