// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

mod session;
mod tests;
mod timers;

use crate::crypto::x25519::*;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use slog::{debug, trace, Logger};

const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10; // The default value to use for rate limiting, when no other rate limiter is defined

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
const N_SESSIONS: usize = 8; // number of sessions in the ring, better keep a PoT

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    handshake: Mutex<handshake::Handshake>, // The handshake currently in progress
    sessions: [Arc<RwLock<Option<session::Session>>>; N_SESSIONS], // The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    current: AtomicUsize, // Index of most recently used session
    packet_queue: Mutex<VecDeque<Vec<u8>>>, // Queue to store blocked packets
    timers: timers::Timers, // Keeps tabs on the expiring timers
    tx_bytes: AtomicUsize,
    rx_bytes: AtomicUsize,

    rate_limiter: Arc<RateLimiter>,

    pub logger: Logger,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: Arc<X25519SecretKey>,
        peer_static_public: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<Box<Tunn>, &'static str> {
        let static_public = Arc::new(static_private.public_key());

        let tunn = Tunn {
            handshake: Mutex::new(
                Handshake::new(
                    static_private,
                    Arc::clone(&static_public),
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

            packet_queue: Mutex::new(VecDeque::new()),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            logger: slog::Logger::root(slog::Discard, slog::o!()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        };

        Ok(Box::new(tunn))
    }

    /// Set the log function and logging level for the tunnel
    pub fn set_logger(&mut self, logger: Logger) {
        self.logger = logger
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: Arc<X25519SecretKey>,
        static_public: Arc<X25519PublicKey>,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<(), WireGuardError> {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .lock()
            .set_static_private(static_private, static_public)?;
        for s in &self.sessions {
            *s.write() = None;
        }
        Ok(())
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current.load(Ordering::SeqCst);
        if let Some(ref session) = *self.sessions[current % N_SESSIONS].read() {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes.fetch_add(src.len(), Ordering::Relaxed);
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(make_array(&src[0..4]));

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(make_array(&src[4..8])),
                unencrypted_ephemeral: &src[8..40],
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(make_array(&src[4..8])),
                receiver_idx: u32::from_le_bytes(make_array(&src[8..12])),
                unencrypted_ephemeral: &src[12..44],
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(make_array(&src[4..8])),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(make_array(&src[4..8])),
                counter: u64::from_le_bytes(make_array(&src[8..16])),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    fn handle_handshake_init<'a>(
        &self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        debug!(self.logger, "Received handshake_initiation"; "remote_idx" => p.sender_idx);

        let (packet, session) = {
            let mut handshake = self.handshake.lock();
            handshake.receive_handshake_initialization(p, dst)?
        };

        // Store new session in ring buffer
        let index = session.local_index();
        *self.sessions[index % N_SESSIONS].write() = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        debug!(self.logger, "Sending handshake_response"; "local_idx" => index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        debug!(self.logger, "Received handshake_response"; "local_idx" => p.receiver_idx, "remote_idx" => p.sender_idx);

        let session = {
            let mut handshake = self.handshake.lock();
            handshake.receive_handshake_response(p)?
        };

        let keepalive_packet = session.format_packet_data(&[], dst);
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        *self.sessions[index].write() = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        debug!(self.logger, "Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        debug!(self.logger, "Received cookie_reply"; "local_idx" => p.receiver_idx);
        {
            let mut handshake = self.handshake.lock();
            handshake.receive_cookie_reply(p)?;
        }
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        debug!(self.logger, "Did set cookie");

        Ok(TunnResult::Done)
    }

    // Update the index of the currently used session, if needed
    fn set_current_session(&self, new_idx: usize) {
        let cur_idx = self.current.load(Ordering::Relaxed);
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].read().is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS].time()
                >= self.timers.session_timers[cur_idx % N_SESSIONS].time()
        {
            self.current.store(new_idx, Ordering::SeqCst);
            debug!(self.logger, "New session"; "session" => new_idx);
        }
    }

    // Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let lock = self.sessions[idx].read();
            let session = (*lock).as_ref().ok_or_else(|| {
                trace!(self.logger, "No current session available"; "remote_idx" => r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    // Formats a new handshake initiation message and store it in dst. If force_resend is true will send
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
                debug!(self.logger, "Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = make_array(&packet[IPV4_DST_IP_OFF..]);
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = make_array(&packet[IPV6_DST_IP_OFF..]);
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = make_array(&packet[IPV4_LEN_OFF..]);
                let addr_bytes: [u8; IPV4_IP_SZ] = make_array(&packet[IPV4_SRC_IP_OFF..]);
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = make_array(&packet[IPV6_LEN_OFF..]);
                let addr_bytes: [u8; IPV6_IP_SZ] = make_array(&packet[IPV6_SRC_IP_OFF..]);
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes.fetch_add(computed_len, Ordering::Relaxed);

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    // Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    // Push packet to the back of the queue
    fn queue_packet(&self, packet: &[u8]) {
        let mut q = self.packet_queue.lock();
        if q.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            q.push_back(packet.to_vec());
        }
    }

    // Push packet to the front of the queue
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

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current.load(Ordering::SeqCst);

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) =
                *self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS].read()
            {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<u64>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake().map(|t| t.as_secs());
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let loss = self.estimate_loss();
        let rtt = self.handshake.lock().last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.lock().is_expired()
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
