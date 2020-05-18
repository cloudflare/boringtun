use super::make_array;
use crate::crypto::blake2s::{constant_time_mac_check, Blake2s};
use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::crypto::x25519::X25519SecretKey;
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::*;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

const RESET_PERIOD: u64 = 1; // How often should reset count in seconds

type Cookie = [u8; COOKIE_SIZE];

// There are two places where WireGuard requires "randomness" for cookies
// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
// * A secret value that changes every two minutes
// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
// we can relax the randomness definition a bit, in order to avoid locking, because using less
// resources is the main goal of any DoS prevention mechanism.
// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
// some counters.
pub struct RateLimiter {
    nonce_key: [u8; 32],  // The key we use to derive the nonce
    secret_key: [u8; 16], // The key we use to derive the cookie
    start_time: Instant,
    nonce_ctr: AtomicU64, // A single 64bit counter should suffice for many years
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    limit: u64,
    count: AtomicU64,           // The counter since last reset
    last_reset: Mutex<Instant>, // The time last reset was performed on this rate limiter
}

impl RateLimiter {
    pub fn new(public_key: &X25519PublicKey, limit: u64) -> Self {
        RateLimiter {
            nonce_key: RateLimiter::rand_bytes(),
            secret_key: make_array(&RateLimiter::rand_bytes()[..16]),
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: Blake2s::new_hash()
                .hash(LABEL_MAC1)
                .hash(public_key.as_bytes())
                .finalize(),
            cookie_key: Blake2s::new_hash()
                .hash(LABEL_COOKIE)
                .hash(public_key.as_bytes())
                .finalize(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        make_array(X25519SecretKey::new().as_bytes()) // Use the randomness of X25519 secret key as a hack
    }

    /// Reset packet count (ideally should be called with a period of 1 second)
    pub fn reset_count(&self) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let current_time = Instant::now();
        let mut last_reset_time = self.last_reset.lock();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
        }
    }

    // Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr) -> Cookie {
        let mut cookie = [0u8; COOKIE_SIZE];
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        cookie[..].copy_from_slice(
            &Blake2s::new_mac(&self.secret_key[..])
                .hash(&cur_counter.to_le_bytes())
                .hash(&addr_bytes[..])
                .finalize()[..COOKIE_SIZE],
        );

        cookie
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let mut nonce = [0u8; COOKIE_NONCE_SIZE];

        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        nonce[..].copy_from_slice(
            &Blake2s::new_mac(&self.nonce_key[..])
                .hash(&ctr.to_le_bytes())
                .finalize()[..COOKIE_NONCE_SIZE],
        );

        nonce
    }

    fn is_under_load(&self) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) >= self.limit
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::COOKIE_REPLY_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (mut encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::COOKIE_REPLY.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        ChaCha20Poly1305::new_aead(&self.cookie_key).xseal(
            &nonce,
            mac1,
            &cookie[..],
            &mut encrypted_cookie,
        );

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    // Verify the MAC fields on the datagram, and apply rate limiting if needed
    pub fn verify_packet<'a, 'b>(
        &self,
        src_addr: Option<IpAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet(src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, mac2) = macs.split_at(16);

            let computed_mac1 = Blake2s::new_mac(&self.mac1_key).hash(msg).finalize();
            constant_time_mac_check(&computed_mac1[..16], mac1).map_err(TunnResult::Err)?;

            if self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = Blake2s::new_mac(&cookie[..])
                    .hash(msg)
                    .hash(mac1)
                    .finalize();

                if constant_time_mac_check(&computed_mac2[..16], mac2).is_err() {
                    let cookie_packet = self
                        .format_cookie_reply(sender_idx, cookie, mac1, dst)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
            }
        }

        Ok(packet)
    }
}
