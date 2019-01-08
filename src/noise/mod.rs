pub mod errors;
mod h2n;
mod handshake;
mod session;
mod tests;
mod timers;

use base64::decode;
use noise::errors::WireGuardError;
use noise::h2n::read_u16_be;
use noise::handshake::Handshake;
use noise::timers::{TimerName, Timers};
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::{Mutex, RwLock};

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_LEN_SZ: usize = 2;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_LEN_SZ: usize = 2;

const KEY_LEN: usize = 32;

const MAX_QUEUE_DEPTH: usize = 256;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug)]
#[repr(u32)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occured, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information required to perform the operation
    pub size: u32,
}

#[derive(Eq, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Verbosity {
    None = 0,
    Info = 1,
    Debug = 2,
    All = 3,
}

impl From<u32> for Verbosity {
    fn from(num: u32) -> Self {
        match num {
            0 => Verbosity::None,
            1 => Verbosity::Info,
            2 => Verbosity::Debug,
            _ => Verbosity::All,
        }
    }
}

// Convinience macros to generate wireguard_result return values
macro_rules! DONE {
    () => {
        wireguard_result {
            op: result_type::WIREGUARD_DONE,
            size: 0,
        }
    };
}

macro_rules! ERR {
    ($v:expr) => {
        wireguard_result {
            op: result_type::WIREGUARD_ERROR,
            size: $v as u32,
        }
    };
}

macro_rules! TO_NETWORK {
    ($v:expr) => {
        wireguard_result {
            op: result_type::WRITE_TO_NETWORK,
            size: $v as u32,
        }
    };
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    handshake: Mutex<handshake::Handshake>, // The handshake currently in progress
    past_session: RwLock<Option<session::Session>>,
    current_session: RwLock<Option<session::Session>>,
    future_session: RwLock<Option<session::Session>>,
    packet_queue: Mutex<VecDeque<Vec<u8>>>, // Queue to store blocked packets
    timers: timers::Timers,

    log: Option<unsafe extern "C" fn(*const c_char)>, // Pointer to an external log function
    verbosity: Verbosity,
}

impl Tunn {
    /// Create a new tunnel using the client private key and the peer public key, base64 encoded
    /// # Errors
    /// Fails if keys are too short, or incorrectly encoded
    pub fn new(static_private: &str, peer_static_public: &str) -> Result<Box<Tunn>, &'static str> {
        let peer_static_public = match decode(peer_static_public) {
            Ok(key) => key,
            Err(_) => return Err("Failed to decode public key"),
        };

        if peer_static_public.len() != KEY_LEN {
            return Err("Incorrect public key size");
        }

        let static_private = match decode(static_private) {
            Ok(key) => key,
            Err(_) => return Err("Failed to decode private key"),
        };

        if static_private.len() != KEY_LEN {
            return Err("Incorrect private key size");
        }

        let tunn = Tunn {
            handshake: Mutex::new(Handshake::new(&static_private, &peer_static_public)),
            past_session: RwLock::new(None),
            current_session: RwLock::new(None),
            future_session: RwLock::new(None),
            packet_queue: Mutex::new(VecDeque::new()),
            timers: Timers::new(),

            log: None,
            verbosity: Verbosity::None,
        };

        Ok(Box::new(tunn))
    }

    /// Set the external forfunction pointer for the logging function.
    pub fn set_log(&mut self, log: Option<unsafe extern "C" fn(*const c_char)>, verbosity: u32) {
        self.log = log;
        self.verbosity = Verbosity::from(verbosity);
    }

    /// Receives an IP packet from the tunnel interface and encapsulates it.
    /// Returns wireguard_result.
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn tunnel_to_network(&self, src: &[u8], dst: &mut [u8]) -> wireguard_result {
        // Try to send the packet using an establsihed session
        let try_packet_res = self.format_packet_data(src, dst);
        if try_packet_res.op != result_type::WIREGUARD_ERROR {
            return try_packet_res;
        }
        // No session? Queue the packet
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP packet from the network and parses it.
    /// Returns wireguard_result.
    /// If wireguard_results is WRITE_TO_NETWORK, must repeat the call with empty src,
    /// until WIREGUARD_DONE is returned.
    pub fn network_to_tunnel(&self, src: &[u8], dst: &mut [u8]) -> wireguard_result {
        if src.is_empty() {
            // A repeat call indicates we may send something from the buffer
            return if let Some(packet) = self.dequeue_packet() {
                let try_packet_res = self.format_packet_data(&packet, dst);
                if try_packet_res.op == result_type::WIREGUARD_ERROR {
                    // If failed to send the packet, put it back in the queue
                    self.requeue_packet(packet);
                }
                try_packet_res
            } else {
                DONE!()
            };
        }

        match src[0] {
            1 => {
                self.log(Verbosity::Debug, "Received handhsake_initiation");
                match self
                    .handshake
                    .lock()
                    .map_err(|_| WireGuardError::LockFailed)
                    .and_then(|mut hs| hs.receive_handshake_initialization(src, dst))
                {
                    Ok((n, new_session)) => {
                        self.log(Verbosity::Debug, "Sending handshake_reponse");
                        {
                            let mut future_session = self.future_session.write().unwrap();
                            *future_session = Some(new_session);
                        }
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        self.timer_tick(TimerName::TimeLastPacketSent);
                        TO_NETWORK!(n)
                    }
                    Err(e) => ERR!(e),
                }
            }
            2 => {
                self.log(Verbosity::Debug, "Received handhsake_response");
                match self
                    .handshake
                    .lock()
                    .map_err(|_| WireGuardError::LockFailed)
                    .and_then(|mut hs| hs.receive_handshake_response(src))
                {
                    Ok(new_session) => {
                        {
                            let mut cur_session = self.current_session.write().unwrap();
                            let mut past_session = self.past_session.write().unwrap();
                            *past_session = cur_session.clone();
                            *cur_session = Some(new_session);
                        }
                        self.timer_tick_session_established(true);
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        self.format_packet_data(&[], dst) // Send a keepalive as response
                    }
                    Err(e) => ERR!(e),
                }
            }
            3 => {
                self.log(Verbosity::Debug, "Received cookie_reply");
                match self
                    .handshake
                    .lock()
                    .map_err(|_| WireGuardError::LockFailed)
                    .and_then(|mut hs| hs.receive_cookie_reply(src, dst))
                {
                    Ok(n) => {
                        self.log(Verbosity::Debug, "Sending handhsake_initiation with cookie");
                        self.timer_tick(TimerName::TimeCookieReceived);
                        self.timer_tick(TimerName::TimeLastPacketReceived);
                        self.timer_tick(TimerName::TimeLastPacketSent);
                        TO_NETWORK!(n)
                    }
                    Err(e) => ERR!(e),
                }
            }
            4 => self.receive_packet_data(src, dst),
            _ => {
                self.log(Verbosity::Debug, &format!("Illegal packet {}", src[0]));
                ERR!(WireGuardError::InvalidPacket)
            }
        }
    }

    // Formats a new handhsake initiation message and store it in dst.
    fn format_handshake_initiation(&self, dst: &mut [u8], resend: bool) -> wireguard_result {
        let mut handshake = self.handshake.lock().unwrap();
        if handshake.is_in_progress() && !resend {
            return DONE!();
        }

        match handshake.format_handshake_initiation(dst) {
            Ok(n) => {
                self.log(Verbosity::Debug, "Sending handshake_initiation");
                self.timer_tick(TimerName::TimeLastHandshakeStarted);
                self.timer_tick(TimerName::TimeLastPacketSent);
                TO_NETWORK!(n)
            }
            Err(e) => ERR!(e),
        }
    }

    // Encapsulates a data packet and stores in dst.
    fn format_packet_data(&self, src: &[u8], dst: &mut [u8]) -> wireguard_result {
        if let Some(ref session) = *self.current_session.read().unwrap() {
            let n = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            TO_NETWORK!(n)
        } else {
            ERR!(WireGuardError::NoCurrentSession)
        }
    }

    // Decrypts a data packet, and stores the decapsulated packet in dst.
    fn receive_packet_data(&self, src: &[u8], dst: &mut [u8]) -> wireguard_result {
        // Try to decrypt using the current session. This is the common scenario.
        if let Some(ref session) = *self.current_session.read().unwrap() {
            match session.receive_packet_data(src, dst) {
                Ok(n) => {
                    self.timer_tick(TimerName::TimeLastPacketReceived);
                    return self.check_decapsulated_packet(&dst[..n]);
                }
                Err(WireGuardError::WrongIndex) => {}
                Err(e) => return ERR!(e),
            }
        }

        // Try to decrypt with the previous session.
        // This happen when packets are sent during a handshake.
        if let Some(ref session) = *self.past_session.read().unwrap() {
            match session.receive_packet_data(src, dst) {
                Ok(n) => {
                    self.timer_tick(TimerName::TimeLastPacketReceived);
                    return self.check_decapsulated_packet(&dst[..n]);
                }
                Err(WireGuardError::WrongIndex) => {}
                Err(e) => return ERR!(e),
            }
        }

        // Try to decrypt using the future session. This will happen when we are the responder.
        let mut swap_session = false;
        let mut len = 0;
        if let Ok(mut future_session) = self.future_session.try_write() {
            if let Some(ref session) = *future_session {
                if let Ok(n) = session.receive_packet_data(src, dst) {
                    // Upon success, future session becomes the current session
                    let mut past_session = self.past_session.write().unwrap();
                    let mut current_session = self.current_session.write().unwrap();
                    *past_session = current_session.clone();
                    *current_session = Some((*session).clone());
                    swap_session = true;
                    len = n;
                    self.timer_tick(TimerName::TimeLastPacketReceived);
                    self.timer_tick_session_established(false);
                }
            }
            if swap_session {
                *future_session = None;
                return self.check_decapsulated_packet(&dst[..len]);
            }
        }

        return DONE!();
    }

    fn check_decapsulated_packet(&self, packet: &[u8]) -> wireguard_result {
        let len = packet.len();

        if len < IPV4_MIN_HEADER_SIZE {
            return DONE!(); // Invalid ip packet or keepalive
        }

        match packet[0] >> 4 {
            4 => {
                // This is IPv4 packet
                let packet_len =
                    read_u16_be(&packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IPV4_LEN_SZ]) as usize;
                if packet_len > len {
                    DONE!()
                } else {
                    wireguard_result {
                        op: result_type::WRITE_TO_TUNNEL_IPV4,
                        size: packet_len as u32,
                    }
                }
            }
            6 => {
                // This is IPv6 packet
                if len < IPV6_MIN_HEADER_SIZE {
                    DONE!()
                } else {
                    let packet_len =
                        read_u16_be(&packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IPV6_LEN_SZ]) as usize;
                    if packet_len > len {
                        DONE!()
                    } else {
                        wireguard_result {
                            op: result_type::WRITE_TO_TUNNEL_IPV6,
                            size: packet_len as u32,
                        }
                    }
                }
            }
            _ => DONE!(),
        }
    }

    fn queue_packet(&self, packet: &[u8]) {
        self.packet_queue
            .lock()
            .and_then(|mut q| {
                if q.len() < MAX_QUEUE_DEPTH {
                    // Drop if too many are already in queue
                    q.push_back(packet.to_vec());
                }
                Ok(true)
            })
            .unwrap();
    }

    fn requeue_packet(&self, packet: Vec<u8>) {
        self.packet_queue
            .lock()
            .and_then(|mut q| {
                if q.len() < MAX_QUEUE_DEPTH {
                    // Drop if too many are already in queue
                    q.push_front(packet);
                }
                Ok(true)
            })
            .unwrap();
    }

    fn dequeue_packet(&self) -> Option<Vec<u8>> {
        self.packet_queue
            .lock()
            .and_then(|mut q| Ok(q.pop_front()))
            .unwrap()
    }

    fn log(&self, lvl: Verbosity, entry: &str) {
        if let Some(p) = self.log {
            if self.verbosity >= lvl {
                let cstr = CString::new(entry).unwrap();
                unsafe {
                    p(cstr.as_ptr());
                }
            }
        }
    }
}
