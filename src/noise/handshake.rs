use crypto::blake2s::{constant_time_mac_check, Blake2s};
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::x25519::{x25519_public_key, x25519_shared_key};
use noise::errors::WireGuardError;
use noise::make_array;
use noise::session::Session;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant, SystemTime};

// static CONSTRUCTION: &'static [u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
// static IDENTIFIER: &'static [u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
static LABEL_MAC1: &'static [u8] = b"mac1----";
static LABEL_COOKIE: &'static [u8] = b"cookie--";
const KEY_LEN: usize = 32;

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
struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug)]
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    pub fn new() -> TimeStamper {
        TimeStamper {
            duration_at_start: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
            instant_at_start: Instant::now(),
        }
    }

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
    pub fn zero() -> Tai64N {
        Tai64N { secs: 0, nano: 0 }
    }

    pub fn parse(buf: &[u8]) -> Result<Tai64N, WireGuardError> {
        if buf.len() < 12 {
            return Err(WireGuardError::InvalidTai64nTimestamp);
        }

        let secs = u64::from_be_bytes(make_array(&buf[0..]));
        let nano = u32::from_be_bytes(make_array(&buf[8..]));

        // wireguard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(WireGuardError::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(WireGuardError::InvalidTai64nTimestamp);
        //}

        return Ok(Tai64N { secs, nano });
    }

    pub fn after(&self, other: &Tai64N) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

#[derive(Debug)]
struct NoiseParams {
    static_public: [u8; KEY_LEN],
    static_private: [u8; KEY_LEN],
    peer_static_public: [u8; KEY_LEN],
    static_shared: [u8; KEY_LEN],
    sending_mac1_key: [u8; KEY_LEN],
    receiving_mac1_key: [u8; KEY_LEN],
    preshared_key: Option<[u8; KEY_LEN]>,
}

#[derive(Debug)]
pub enum HandshakeState {
    None, // No handshake in process
    InitSent {
        hash: [u8; KEY_LEN],
        chaining_key: [u8; KEY_LEN],
        ephemeral_private: [u8; KEY_LEN],
        local_index: u32,
        time_sent: Instant,
        mac1: [u8; 32],
    }, // We initiated the handshake
    InitReceived {
        hash: [u8; KEY_LEN],
        chaining_key: [u8; KEY_LEN],
        peer_ephemeral_public: [u8; KEY_LEN],
        peer_index: u32,
    }, // Handshake initiated by peer
    Expired,
}

#[derive(Debug)]
pub struct Handshake {
    params: NoiseParams,
    next_index: u32,
    rng: OsRng,
    state: HandshakeState,
    cookie: Option<[u8; 16]>,
    last_handshake_timestamp: Tai64N,
    stamper: TimeStamper,
}

#[derive(Debug)]
pub struct HalfHandshake {
    pub peer_index: u32,
    pub peer_static_public: [u8; 32],
}

pub fn parse_handshake_anon(
    static_private: &[u8],
    static_public: &[u8],
    src: &[u8],
) -> Result<HalfHandshake, WireGuardError> {
    const MSG_TYPE_OFF: usize = 0;
    const MSG_TYPE_SZ: usize = 4;
    const SND_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
    const SND_IDX_SZ: usize = 4;
    const EPH_OFF: usize = SND_IDX_OFF + SND_IDX_SZ;
    const EPH_SZ: usize = 32;
    const E_STAT_OFF: usize = EPH_OFF + EPH_SZ;
    const E_STAT_SZ: usize = 32 + 16;
    const ENC_TIME_OFF: usize = E_STAT_OFF + E_STAT_SZ;
    const ENC_TIME_SZ: usize = 12 + 16;
    const MAC1_OFF: usize = ENC_TIME_OFF + ENC_TIME_SZ;
    const MAC1_SZ: usize = 16;
    const MAC2_OFF: usize = MAC1_OFF + MAC1_SZ;
    const MAC2_SZ: usize = 16;
    const BUF_SZ: usize = MAC2_OFF + MAC2_SZ;

    let receiving_mac1_key = HASH!(LABEL_MAC1, static_public);

    if src.len() != BUF_SZ {
        return Err(WireGuardError::IncorrectPacketLength);
    }
    // msg.message_type = 1
    // msg.reserved_zero = { 0, 0, 0 }
    let message_type = u32::from_le_bytes(make_array(&src[MSG_TYPE_OFF..]));
    if message_type != 1 {
        return Err(WireGuardError::WrongPacketType);
    }
    // Validating the MAC
    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let msg_mac = Blake2s::new_mac(&receiving_mac1_key)
        .hash(&src[0..MAC1_OFF])
        .finalize();
    constant_time_mac_check(&msg_mac[0..MAC1_SZ], &src[MAC1_OFF..MAC1_OFF + MAC1_SZ])?;
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = HASH!(hash, static_public);
    // msg.sender_index = little_endian(initiator.sender_index)
    let peer_index = u32::from_le_bytes(make_array(&src[SND_IDX_OFF..]));
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = &src[EPH_OFF..EPH_OFF + EPH_SZ];
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = HASH!(hash, src[EPH_OFF..EPH_OFF + EPH_SZ]);
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = HMAC!(HMAC!(chaining_key, src[EPH_OFF..EPH_OFF + EPH_SZ]), [0x01]);
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let epehemeral_shared = x25519_shared_key(peer_ephemeral_public, static_private);
    let temp = HMAC!(chaining_key, epehemeral_shared);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = HMAC!(temp, [0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = HMAC!(temp, chaining_key, [0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    OPEN!(
        peer_static_public,
        key,
        0,
        src[E_STAT_OFF..E_STAT_OFF + E_STAT_SZ],
        hash
    )?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

impl NoiseParams {
    fn new(
        static_private: &[u8],
        peer_static_public: &[u8],
        preshared_key: Option<[u8; 32]>,
    ) -> NoiseParams {
        let static_public = x25519_public_key(static_private);

        if constant_time_zero_key_check(&static_public) {
            panic!("Zero key");
        }

        NoiseParams {
            static_public,
            static_private: make_array(static_private),
            peer_static_public: make_array(peer_static_public),
            static_shared: x25519_shared_key(&peer_static_public, &static_private),
            sending_mac1_key: HASH!(LABEL_MAC1, peer_static_public),
            receiving_mac1_key: HASH!(LABEL_MAC1, static_public),
            preshared_key,
        }
    }

    fn set_static_private(&mut self, static_private: &[u8]) {
        let static_public = x25519_public_key(static_private);
        self.static_public = static_public;
        self.static_private = make_array(static_private);
        self.static_shared = x25519_shared_key(&self.peer_static_public, &static_private);
        self.receiving_mac1_key = HASH!(LABEL_MAC1, static_public);
    }
}

impl Handshake {
    pub fn new(
        static_private: &[u8],
        peer_static_public: &[u8],
        global_idx: u32,
        preshared_key: Option<[u8; 32]>,
    ) -> Handshake {
        let params = NoiseParams::new(static_private, peer_static_public, preshared_key);

        Handshake {
            params: params,
            next_index: global_idx,
            rng: OsRng::new().unwrap(),
            state: HandshakeState::None,
            cookie: None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(),
        }
    }

    pub fn is_in_progress(&self) -> bool {
        match self.state {
            HandshakeState::None | HandshakeState::Expired => false,
            _ => true,
        }
    }

    pub fn timer(&self) -> Option<Instant> {
        match self.state {
            HandshakeState::InitSent { time_sent, .. } => Some(time_sent),
            _ => None,
        }
    }

    pub fn expired(&mut self) {
        self.state = HandshakeState::Expired;
    }

    pub fn is_expired(&self) -> bool {
        match self.state {
            HandshakeState::Expired => true,
            _ => false,
        }
    }

    pub fn has_cookie(&self) -> bool {
        self.cookie.is_some()
    }

    pub fn clear_cookie(&mut self) {
        self.cookie = None;
    }

    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index as u8;
        self.next_index = (index & !0xff) | (idx8.wrapping_add(1)) as u32;
        index
    }

    pub fn set_static_private(&mut self, key: &[u8]) {
        self.params.set_static_private(key)
    }

    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        const MSG_TYPE_OFF: usize = 0;
        const MSG_TYPE_SZ: usize = 4;
        const SND_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
        const SND_IDX_SZ: usize = 4;
        const EPH_OFF: usize = SND_IDX_OFF + SND_IDX_SZ;
        const EPH_SZ: usize = 32;
        const E_STAT_OFF: usize = EPH_OFF + EPH_SZ;
        const E_STAT_SZ: usize = 32 + 16;
        const ENC_TIME_OFF: usize = E_STAT_OFF + E_STAT_SZ;
        const ENC_TIME_SZ: usize = 12 + 16;
        const MAC1_OFF: usize = ENC_TIME_OFF + ENC_TIME_SZ;
        const MAC1_SZ: usize = 16;
        const MAC2_OFF: usize = MAC1_OFF + MAC1_SZ;
        const MAC2_SZ: usize = 16;
        const BUF_SZ: usize = MAC2_OFF + MAC2_SZ;

        if dst.len() < BUF_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        self.state = HandshakeState::None;
        let local_index = self.inc_index();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = HASH!(hash, self.params.peer_static_public);
        // initiator.ephemeral_private = DH_GENERATE()
        let mut ephemeral_private = [0u8; KEY_LEN];
        self.rng.fill_bytes(&mut ephemeral_private[..]);
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        dst[MSG_TYPE_OFF..MSG_TYPE_OFF + 4].copy_from_slice(&1u32.to_le_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        dst[SND_IDX_OFF..SND_IDX_OFF + 4].copy_from_slice(&local_index.to_le_bytes());
        //msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        dst[EPH_OFF..EPH_OFF + EPH_SZ].copy_from_slice(&x25519_public_key(&ephemeral_private));
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, dst[EPH_OFF..EPH_OFF + EPH_SZ]);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(HMAC!(chaining_key, dst[EPH_OFF..EPH_OFF + EPH_SZ]), [0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let epehemeral_shared =
            x25519_shared_key(&self.params.peer_static_public, &ephemeral_private);
        let temp = HMAC!(chaining_key, epehemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        SEAL!(
            dst[E_STAT_OFF..E_STAT_OFF + E_STAT_SZ],
            key,
            0,
            self.params.static_public,
            hash
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = HASH!(hash, dst[E_STAT_OFF..E_STAT_OFF + E_STAT_SZ]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = HMAC!(chaining_key, self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp();
        SEAL!(
            dst[ENC_TIME_OFF..ENC_TIME_OFF + ENC_TIME_SZ],
            key,
            0,
            timestamp,
            hash
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = HASH!(hash, dst[ENC_TIME_OFF..ENC_TIME_OFF + ENC_TIME_SZ]);
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac = Blake2s::new_mac(&self.params.sending_mac1_key)
            .hash(&dst[0..MAC1_OFF])
            .finalize();
        dst[MAC1_OFF..MAC1_OFF + MAC1_SZ].copy_from_slice(&msg_mac[0..MAC1_SZ]);

        let msg_mac2 = if let Some(cookie) = self.cookie {
            Blake2s::new_mac(&cookie).hash(&dst[0..MAC2_OFF]).finalize()
        } else {
            [0u8; 32]
        };
        dst[MAC2_OFF..MAC2_OFF + MAC2_SZ].copy_from_slice(&msg_mac2[0..MAC2_SZ]);

        let time_now = Instant::now();
        self.state = HandshakeState::InitSent {
            chaining_key,
            hash,
            ephemeral_private,
            local_index,
            time_sent: time_now,
            mac1: msg_mac,
        };

        Ok(&mut dst[..BUF_SZ])
    }

    pub fn receive_handshake_response(&mut self, src: &[u8]) -> Result<Session, WireGuardError> {
        const MSG_TYPE_OFF: usize = 0;
        const MSG_TYPE_SZ: usize = 4;
        const SND_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
        const SND_IDX_SZ: usize = 4;
        const RCV_IDX_OFF: usize = SND_IDX_OFF + SND_IDX_SZ;
        const RCV_IDX_SZ: usize = 4;
        const EPH_OFF: usize = RCV_IDX_OFF + RCV_IDX_SZ;
        const EPH_SZ: usize = 32;
        const ENC_NOTHING_OFF: usize = EPH_OFF + EPH_SZ;
        const ENC_NOTHING_SZ: usize = 16;
        const MAC1_OFF: usize = ENC_NOTHING_OFF + ENC_NOTHING_SZ;
        const MAC1_SZ: usize = 16;
        const MAC2_OFF: usize = MAC1_OFF + MAC1_SZ;
        const MAC2_SZ: usize = 16;
        const BUF_SZ: usize = MAC2_OFF + MAC2_SZ;

        if src.len() != BUF_SZ {
            return Err(WireGuardError::IncorrectPacketLength);
        }

        let (mut chaining_key, mut hash, ephemeral_private, local_index) = match self.state {
            HandshakeState::InitSent {
                chaining_key,
                hash,
                ephemeral_private,
                local_index,
                ..
            } => (chaining_key, hash, ephemeral_private, local_index),
            _ => {
                return Err(WireGuardError::UnexpectedPacket);
            }
        };

        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        let message_type = u32::from_le_bytes(make_array(&src[MSG_TYPE_OFF..]));
        if message_type != 2 {
            return Err(WireGuardError::WrongPacketType);
        }

        let peer_index = u32::from_le_bytes(make_array(&src[SND_IDX_OFF..]));
        let rcv_index = u32::from_le_bytes(make_array(&src[RCV_IDX_OFF..]));
        if rcv_index != local_index {
            return Err(WireGuardError::WrongIndex);
        }

        // Validating the MAC
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac = Blake2s::new_mac(&self.params.receiving_mac1_key)
            .hash(&src[0..MAC1_OFF])
            .finalize();
        constant_time_mac_check(&msg_mac[0..MAC1_SZ], &src[MAC1_OFF..MAC1_OFF + MAC1_SZ])?;
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, src[EPH_OFF..EPH_OFF + EPH_SZ]);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = HMAC!(chaining_key, src[EPH_OFF..EPH_OFF + EPH_SZ]);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared =
            x25519_shared_key(&src[EPH_OFF..EPH_OFF + EPH_SZ], &ephemeral_private);
        let temp = HMAC!(chaining_key, ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = HMAC!(
            chaining_key,
            x25519_shared_key(&src[EPH_OFF..EPH_OFF + EPH_SZ], &self.params.static_private)
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
        OPEN!(
            [],
            key,
            0,
            src[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ],
            hash
        )?;

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

        self.state = HandshakeState::None;

        Ok(Session::new(local_index, peer_index, temp3, temp2))
    }

    pub fn receive_cookie_reply<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        const MSG_TYPE_OFF: usize = 0;
        const MSG_TYPE_SZ: usize = 4;
        const RCV_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
        const RCV_IDX_SZ: usize = 4;
        const NONCE_OFF: usize = RCV_IDX_OFF + RCV_IDX_SZ;
        const NONCE_SZ: usize = 24;
        const ENC_COOKIE_OFF: usize = NONCE_OFF + NONCE_SZ;
        const ENC_COOKIE_SZ: usize = 32;
        const BUF_SZ: usize = ENC_COOKIE_OFF + ENC_COOKIE_SZ;

        if src.len() != BUF_SZ {
            return Err(WireGuardError::IncorrectPacketLength);
        }

        let (local_index, mac1) = match self.state {
            // TODO: allow cookies as response to handshake reply
            HandshakeState::InitSent {
                local_index, mac1, ..
            } => (local_index, mac1),
            _ => {
                return Err(WireGuardError::UnexpectedPacket);
            }
        };
        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        let message_type = u32::from_le_bytes(make_array(&src[MSG_TYPE_OFF..]));
        if message_type != 3 {
            return Err(WireGuardError::WrongPacketType);
        }
        // msg.receiver_index = little_endian(initiator.sender_index)
        let rcv_index = u32::from_le_bytes(make_array(&src[RCV_IDX_OFF..]));
        if rcv_index != local_index {
            return Err(WireGuardError::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = HASH!(LABEL_COOKIE, self.params.peer_static_public); // TODO: precompute
        let nonce = &src[NONCE_OFF..NONCE_OFF + NONCE_SZ];
        let encrypted_cookie = &src[ENC_COOKIE_OFF..ENC_COOKIE_OFF + ENC_COOKIE_SZ];
        let mut cookie = [0u8; 16];

        let n = ChaCha20Poly1305::new_aead(&key).xopen(
            &nonce,
            &mac1[0..16],
            &encrypted_cookie,
            &mut cookie,
        )?;
        assert_eq!(n, 16);
        self.cookie = Some(cookie);
        self.format_handshake_initiation(dst)
    }

    pub fn receive_handshake_initialization<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        const MSG_TYPE_OFF: usize = 0;
        const MSG_TYPE_SZ: usize = 4;
        const SND_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
        const SND_IDX_SZ: usize = 4;
        const EPH_OFF: usize = SND_IDX_OFF + SND_IDX_SZ;
        const EPH_SZ: usize = 32;
        const E_STAT_OFF: usize = EPH_OFF + EPH_SZ;
        const E_STAT_SZ: usize = 32 + 16;
        const ENC_TIME_OFF: usize = E_STAT_OFF + E_STAT_SZ;
        const ENC_TIME_SZ: usize = 12 + 16;
        const MAC1_OFF: usize = ENC_TIME_OFF + ENC_TIME_SZ;
        const MAC1_SZ: usize = 16;
        const MAC2_OFF: usize = MAC1_OFF + MAC1_SZ;
        const MAC2_SZ: usize = 16;
        const AEAD_SIZE: usize = 16;
        const BUF_SZ: usize = MAC2_OFF + MAC2_SZ;

        if src.len() != BUF_SZ {
            return Err(WireGuardError::IncorrectPacketLength);
        }

        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        let message_type = u32::from_le_bytes(make_array(&src[MSG_TYPE_OFF..]));
        if message_type != 1 {
            return Err(WireGuardError::WrongPacketType);
        }
        // Validating the MAC
        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac = Blake2s::new_mac(&self.params.receiving_mac1_key)
            .hash(&src[0..MAC1_OFF])
            .finalize();
        constant_time_mac_check(&msg_mac[0..MAC1_SZ], &src[MAC1_OFF..MAC1_OFF + MAC1_SZ])?;
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = HASH!(hash, self.params.static_public);
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = u32::from_le_bytes(make_array(&src[SND_IDX_OFF..]));
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = &src[EPH_OFF..EPH_OFF + EPH_SZ];
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, src[EPH_OFF..EPH_OFF + EPH_SZ]);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(HMAC!(chaining_key, src[EPH_OFF..EPH_OFF + EPH_SZ]), [0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let epehemeral_shared =
            x25519_shared_key(peer_ephemeral_public, &self.params.static_private);
        let temp = HMAC!(chaining_key, epehemeral_shared);
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
            src[E_STAT_OFF..E_STAT_OFF + E_STAT_SZ],
            hash
        )?;
        // Wireguard would use the encrypted public key to lookup the correct peer,
        // this implementation only supports a single peer per connection, therefore
        // we just verify that the keys match
        constant_time_key_check(
            &peer_static_public_decrypted,
            &self.params.peer_static_public,
        )?;
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = HASH!(hash, src[E_STAT_OFF..E_STAT_OFF + E_STAT_SZ]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = HMAC!(chaining_key, self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = HMAC!(temp, chaining_key, [0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; ENC_TIME_SZ - AEAD_SIZE];
        OPEN!(
            timestamp,
            key,
            0,
            src[ENC_TIME_OFF..ENC_TIME_OFF + ENC_TIME_SZ],
            hash
        )?;

        let timestamp = Tai64N::parse(&timestamp)?;
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(WireGuardError::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = HASH!(hash, src[ENC_TIME_OFF..ENC_TIME_OFF + ENC_TIME_SZ]);

        self.state = HandshakeState::InitReceived {
            chaining_key,
            hash,
            peer_ephemeral_public: make_array(&peer_ephemeral_public),
            peer_index,
        };

        return self.format_handshake_response(dst);
    }

    fn format_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        const MSG_TYPE_OFF: usize = 0;
        const MSG_TYPE_SZ: usize = 4;
        const SND_IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
        const SND_IDX_SZ: usize = 4;
        const RCV_IDX_OFF: usize = SND_IDX_OFF + SND_IDX_SZ;
        const RCV_IDX_SZ: usize = 4;
        const EPH_OFF: usize = RCV_IDX_OFF + RCV_IDX_SZ;
        const EPH_SZ: usize = 32;
        const ENC_NOTHING_OFF: usize = EPH_OFF + EPH_SZ;
        const ENC_NOTHING_SZ: usize = 16;
        const MAC1_OFF: usize = ENC_NOTHING_OFF + ENC_NOTHING_SZ;
        const MAC1_SZ: usize = 16;
        const MAC2_OFF: usize = MAC1_OFF + MAC1_SZ;
        const MAC2_SZ: usize = 16;
        const BUF_SZ: usize = MAC2_OFF + MAC2_SZ;

        if dst.len() < BUF_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (mut chaining_key, mut hash, peer_ephemeral_public, peer_index) = match self.state {
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
        // responder.ephemeral_private = DH_GENERATE()
        let mut ephemeral_private = [0u8; KEY_LEN];
        let local_index = self.inc_index();
        self.rng.fill_bytes(&mut ephemeral_private[..]);
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        dst[MSG_TYPE_OFF..MSG_TYPE_OFF + 4].copy_from_slice(&2u32.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        dst[SND_IDX_OFF..SND_IDX_OFF + 4].copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        dst[RCV_IDX_OFF..RCV_IDX_OFF + 4].copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        dst[EPH_OFF..EPH_OFF + EPH_SZ].copy_from_slice(&x25519_public_key(&ephemeral_private));
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = HASH!(hash, dst[EPH_OFF..EPH_OFF + EPH_SZ]);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = HMAC!(chaining_key, dst[EPH_OFF..EPH_OFF + EPH_SZ]);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = x25519_shared_key(&peer_ephemeral_public, &ephemeral_private);
        let temp = HMAC!(chaining_key, ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = HMAC!(temp, [0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let temp = HMAC!(
            chaining_key,
            x25519_shared_key(&self.params.peer_static_public, &ephemeral_private)
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
        SEAL!(
            dst[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ],
            key,
            0,
            [],
            hash
        );

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = HASH!(hash, dst[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac = Blake2s::new_mac(&self.params.sending_mac1_key)
            .hash(&dst[0..MAC1_OFF])
            .finalize();
        dst[MAC1_OFF..MAC1_OFF + MAC1_SZ].copy_from_slice(&msg_mac[..MAC1_SZ]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2 = if let Some(cookie) = self.cookie {
            Blake2s::new_mac(&cookie).hash(&dst[0..MAC2_OFF]).finalize()
        } else {
            [0u8; 32]
        };
        dst[MAC2_OFF..MAC2_OFF + MAC2_SZ].copy_from_slice(&msg_mac2[0..MAC2_SZ]);

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

        self.state = HandshakeState::None;

        Ok((
            &mut dst[..BUF_SZ],
            Session::new(local_index, peer_index, temp2, temp3),
        ))
    }
}

fn constant_time_key_check(key1: &[u8], key2: &[u8]) -> Result<(), WireGuardError> {
    assert!(key1.len() == 32);
    assert!(key2.len() == 32);
    // macro?
    if key1.len() != 32 || key2.len() != 32 {
        return Err(WireGuardError::WrongKey);
    }

    let mut r = 0u8;
    for i in 0..32 {
        r |= key1[i] ^ key2[i];
    }

    if r == 0 {
        Ok(())
    } else {
        Err(WireGuardError::WrongKey)
    }
}

fn constant_time_zero_key_check(key: &[u8]) -> bool {
    assert!(key.len() == 32);

    let mut r = 0u8;

    for b in key {
        r |= b;
    }

    r == 0
}
