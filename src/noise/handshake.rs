// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{HandshakeInit, HandshakeResponse, PacketCookieReply};
use crate::crypto::blake2s::Blake2s;
use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::crypto::x25519::{X25519PublicKey, X25519SecretKey};
use crate::noise::errors::WireGuardError;
use crate::noise::make_array;
use crate::noise::session::Session;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

// static CONSTRUCTION: &'static [u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
// static IDENTIFIER: &'static [u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub static LABEL_MAC1: &[u8] = b"mac1----";
pub static LABEL_COOKIE: &[u8] = b"cookie--";
const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

// initiator.chaining_key = HASH(CONSTRUCTION)
static INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
static INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

macro_rules! HASH {
    ($data1:expr, $data2:expr) => {
        Blake2s::new_hash().hash(&$data1).hash(&$data2).finalize()
    };
}

macro_rules! HMAC {
    ($key:expr, $data1:expr) => {
        Blake2s::new_hmac(&$key).hash(&$data1).finalize()
    };
    ($key:expr, $data1:expr, $data2:expr) => {
        Blake2s::new_hmac(&$key)
            .hash(&$data1)
            .hash(&$data2)
            .finalize()
    };
}

macro_rules! SEAL {
    ($ct:expr, $key:expr, $counter:expr, $data:expr, $aad:expr) => {
        ChaCha20Poly1305::new_aead(&$key).seal_wg($counter, &$aad, &$data, &mut $ct);
    };
}

macro_rules! OPEN {
    ($pt:expr, $key:expr, $counter:expr, $data:expr, $aad:expr) => {
        ChaCha20Poly1305::new_aead(&$key).open_wg($counter, &$aad, &$data, &mut $pt);
    };
}

#[derive(Debug)]
// This struct represents a 12 byte [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp
struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug)]
// This struct computes a [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp from current system time
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    // Create a new TimeStamper
    pub fn new() -> TimeStamper {
        TimeStamper {
            duration_at_start: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            instant_at_start: Instant::now(),
        }
    }
    // Take time reading and generate a 12 byte timestamp
    pub fn stamp(&self) -> [u8; 12] {
        const TAI64_BASE: u64 = (1u64 << 62) + 37;
        let mut ext_stamp = [0u8; 12];
        let stamp = Instant::now().duration_since(self.instant_at_start) + self.duration_at_start;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + TAI64_BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

impl Tai64N {
    // A zeroed out timestamp
    fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    // Parse a timestamp from a 12 byte u8 slice
    fn parse(buf: &[u8]) -> Result<Tai64N, WireGuardError> {
        if buf.len() < 12 {
            return Err(WireGuardError::InvalidTai64nTimestamp);
        }

        let secs = u64::from_be_bytes(make_array(&buf[0..]));
        let nano = u32::from_be_bytes(make_array(&buf[8..]));

        // WireGuard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(WireGuardError::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(WireGuardError::InvalidTai64nTimestamp);
        //}

        Ok(Tai64N { secs, nano })
    }

    // Check if this timestamp represents a time that is chronologically after the time represented
    // by the other timestamp
    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

#[derive(Debug)]
// Parameters used by the noise protocol
struct NoiseParams {
    static_public: Arc<X25519PublicKey>,      // Our static public key
    static_private: Arc<X25519SecretKey>,     // Our static private key
    peer_static_public: Arc<X25519PublicKey>, // Static public key of the other party
    static_shared: [u8; KEY_LEN], // A shared key = DH(static_private, peer_static_public)
    sending_mac1_key: [u8; KEY_LEN], // A pre-computation of HASH("mac1----", peer_static_public) for this peer
    preshared_key: Option<[u8; KEY_LEN]>, // An optional preshared key
}

#[derive(Debug)]
struct HandshakeInitSentState {
    local_index: u32,
    hash: [u8; KEY_LEN],
    chaining_key: [u8; KEY_LEN],
    ephemeral_private: X25519SecretKey,
    time_sent: Instant,
}

#[derive(Debug)]
enum HandshakeState {
    None,                             // No handshake in process
    InitSent(HandshakeInitSentState), // We initiated the handshake
    InitReceived {
        hash: [u8; KEY_LEN],
        chaining_key: [u8; KEY_LEN],
        peer_ephemeral_public: X25519PublicKey,
        peer_index: u32,
    }, // Handshake initiated by peer
    Expired, // Handshake was established too long ago (implies no handshake is in progress)
}

pub struct Handshake {
    params: NoiseParams,
    next_index: u32,          // Index of the next session
    previous: HandshakeState, // Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    state: HandshakeState,    // Current handshake state
    cookies: Cookies,
    last_handshake_timestamp: Tai64N, // The timestamp of the last handshake we received
    stamper: TimeStamper,             // TODO: make TimeStamper a singleton
    pub(super) last_rtt: Option<u32>,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 16]>,
    index: u32,
    write_cookie: Option<[u8; 16]>,
}

#[derive(Debug)]
pub struct HalfHandshake {
    pub peer_index: u32,
    pub peer_static_public: [u8; 32],
}

pub fn parse_handshake_anon(
    static_private: &X25519SecretKey,
    static_public: &X25519PublicKey,
    packet: &HandshakeInit,
) -> Result<HalfHandshake, WireGuardError> {
    let peer_index = packet.sender_idx;
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = HASH!(hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = X25519PublicKey::from(packet.unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = HASH!(hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = HMAC!(
        HMAC!(chaining_key, peer_ephemeral_public.as_bytes()),
        [0x01]
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = static_private.shared_key(&peer_ephemeral_public)?;
    let temp = HMAC!(chaining_key, &ephemeral_shared[..]);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = HMAC!(temp, [0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = HMAC!(temp, chaining_key, [0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    OPEN!(peer_static_public, key, 0, packet.encrypted_static, hash)?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

impl NoiseParams {
    /// New noise params struct from our secret key, peers public key, and optional preshared key
    fn new(
        static_private: Arc<X25519SecretKey>,
        static_public: Arc<X25519PublicKey>,
        peer_static_public: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<NoiseParams, WireGuardError> {
        let static_shared = static_private.shared_key(&peer_static_public)?;

        let initial_sending_mac_key = HASH!(LABEL_MAC1, peer_static_public.as_bytes());

        Ok(NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key,
        })
    }

    /// Set a new private key
    fn set_static_private(
        &mut self,
        static_private: Arc<X25519SecretKey>,
        static_public: Arc<X25519PublicKey>,
    ) -> Result<(), WireGuardError> {
        // Check that the public key indeed matches the private key
        let check_key = static_private.public_key();
        assert_eq!(check_key.as_bytes(), static_public.as_bytes());

        self.static_private = static_private;
        self.static_public = static_public;

        self.static_shared = self.static_private.shared_key(&self.peer_static_public)?;
        Ok(())
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: Arc<X25519SecretKey>,
        static_public: Arc<X25519PublicKey>,
        peer_static_public: Arc<X25519PublicKey>,
        global_idx: u32,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<Handshake, WireGuardError> {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        )?;

        Ok(Handshake {
            params,
            next_index: global_idx,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(),
            cookies: Default::default(),
            last_rtt: None,
        })
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        !matches!(self.state, HandshakeState::None | HandshakeState::Expired)
    }

    pub(crate) fn timer(&self) -> Option<Instant> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState { time_sent, .. }) => Some(time_sent),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) fn has_cookie(&self) -> bool {
        self.cookies.write_cookie.is_some()
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index as u8;
        self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1));
        self.next_index
    }

    pub(crate) fn set_static_private(
        &mut self,
        private_key: Arc<X25519SecretKey>,
        public_key: Arc<X25519PublicKey>,
    ) -> Result<(), WireGuardError> {
        self.params.set_static_private(private_key, public_key)
    }

    pub(super) fn receive_handshake_initialization<'a>(
        &mut self,
        packet: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = HASH!(hash, self.params.static_public.as_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = X25519PublicKey::from(packet.unencrypted_ephemeral);
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, peer_ephemeral_public.as_bytes());
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(
            HMAC!(chaining_key, peer_ephemeral_public.as_bytes()),
            [0x01]
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = self
            .params
            .static_private
            .shared_key(&peer_ephemeral_public)?;
        let temp = HMAC!(chaining_key, ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);

        let mut peer_static_public_decrypted = [0u8; KEY_LEN];
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        OPEN!(
            peer_static_public_decrypted,
            key,
            0,
            packet.encrypted_static,
            hash
        )?;

        self.params
            .peer_static_public
            .constant_time_is_equal(&X25519PublicKey::from(&peer_static_public_decrypted[..]))?;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = HASH!(hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = HMAC!(chaining_key, self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        OPEN!(timestamp, key, 0, packet.encrypted_timestamp, hash)?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(WireGuardError::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = HASH!(hash, packet.encrypted_timestamp);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
            },
        );

        self.format_handshake_response(dst)
    }

    pub(super) fn receive_handshake_response(
        &mut self,
        packet: HandshakeResponse,
    ) -> Result<Session, WireGuardError> {
        // Check if there is a handshake awaiting a response and return the correct one
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.receiver_idx => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = X25519PublicKey::from(packet.unencrypted_ephemeral);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = HASH!(state.hash, unencrypted_ephemeral.as_bytes());
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = HMAC!(state.chaining_key, unencrypted_ephemeral.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = state.ephemeral_private.shared_key(&unencrypted_ephemeral)?;
        let temp = HMAC!(chaining_key, &ephemeral_shared[..]);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = HMAC!(
            chaining_key,
            &self
                .params
                .static_private
                .shared_key(&unencrypted_ephemeral)?[..]
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = HMAC!(
            chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..]
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = HMAC!(temp, chaining_key, [0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = HMAC!(temp, temp2, [0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = HASH!(hash, temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        OPEN!([], key, 0, packet.encrypted_nothing, hash)?;

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = HASH!(hash, buf[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = HMAC!(chaining_key, []);
        let temp2 = HMAC!(temp1, [0x01]);
        let temp3 = HMAC!(temp1, temp2, [0x02]);

        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(rtt_time.as_millis() as u32);

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: PacketCookieReply,
    ) -> Result<(), WireGuardError> {
        let mac1 = match self.cookies.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(WireGuardError::UnexpectedPacket);
            }
        };

        let local_index = self.cookies.index;
        if packet.receiver_idx != local_index {
            return Err(WireGuardError::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = HASH!(LABEL_COOKIE, self.params.peer_static_public.as_bytes()); // TODO: pre-compute
        let mut cookie = [0u8; 16];
        ChaCha20Poly1305::new_aead(&key).xopen(
            packet.nonce,
            &mac1[0..16],
            packet.encrypted_cookie,
            &mut cookie,
        )?;
        self.cookies.write_cookie = Some(cookie);
        Ok(())
    }

    // Compute and append mac1 and mac2 to a handshake message
    fn append_mac1_and_mac2<'a>(
        &mut self,
        local_index: u32,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let mac1_off = dst.len() - 32;
        let mac2_off = dst.len() - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1: [u8; 16] = make_array(
            &Blake2s::new_mac(&self.params.sending_mac1_key)
                .hash(&dst[..mac1_off])
                .finalize()[..],
        );

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 16] = if let Some(cookie) = self.cookies.write_cookie {
            make_array(&Blake2s::new_mac(&cookie).hash(&dst[..mac2_off]).finalize()[..])
        } else {
            [0u8; 16]
        };

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
        Ok(dst)
    }

    pub(super) fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::HANDSHAKE_INIT_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (mut encrypted_static, rest) = rest.split_at_mut(32 + 16);
        let (mut encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

        let local_index = self.inc_index();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = HASH!(hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = X25519SecretKey::new();
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_INIT.to_le_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        //msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(&ephemeral_private.public_key().as_bytes());
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(HMAC!(chaining_key, unencrypted_ephemeral), [0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = ephemeral_private.shared_key(&self.params.peer_static_public)?;
        let temp = HMAC!(chaining_key, ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        SEAL!(
            encrypted_static,
            key,
            0,
            self.params.static_public.as_bytes(),
            hash
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = HASH!(hash, encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = HMAC!(chaining_key, self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp();
        SEAL!(encrypted_timestamp, key, 0, timestamp, hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = HASH!(hash, encrypted_timestamp);

        let time_now = Instant::now();
        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: time_now,
            }),
        );

        self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_INIT_SZ])
    }

    fn format_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        if dst.len() < super::HANDSHAKE_RESP_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let (mut chaining_key, mut hash, peer_ephemeral_public, peer_index) = match state {
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
            } => (chaining_key, hash, peer_ephemeral_public, peer_index),
            _ => {
                panic!("Unexpected attempt to call send_handshake_response");
            }
        };

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (mut encrypted_nothing, _) = rest.split_at_mut(16);

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = X25519SecretKey::new();
        let local_index = self.inc_index();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::HANDSHAKE_RESP.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral.copy_from_slice(&ephemeral_private.public_key().as_bytes());
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = HMAC!(chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = ephemeral_private.shared_key(&peer_ephemeral_public)?;
        let temp = HMAC!(chaining_key, &ephemeral_shared[..]);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = HMAC!(
            chaining_key,
            &ephemeral_private.shared_key(&self.params.peer_static_public)?[..]
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = HMAC!(
            chaining_key,
            &self.params.preshared_key.unwrap_or([0u8; 32])[..]
        );
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = HMAC!(temp, chaining_key, [0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = HMAC!(temp, temp2, [0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = HASH!(hash, temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        SEAL!(encrypted_nothing, key, 0, [], hash);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = HMAC!(chaining_key, []);
        let temp2 = HMAC!(temp1, [0x01]);
        let temp3 = HMAC!(temp1, temp2, [0x02]);

        let dst = self.append_mac1_and_mac2(local_index, &mut dst[..super::HANDSHAKE_RESP_SZ])?;

        Ok((dst, Session::new(local_index, peer_index, temp2, temp3)))
    }
}
