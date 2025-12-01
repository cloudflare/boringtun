use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use ring::constant_time::verify_slices_are_equal;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
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

    /// Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr) -> Cookie {
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
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
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::COOKIE_REPLY.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
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

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            verify_slices_are_equal(&computed_mac1[..16], mac1)
                .map_err(|_| TunnResult::Err(WireGuardError::InvalidMac))?;

            if self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if verify_slices_are_equal(&computed_mac2[..16], mac2).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread;
    use std::time::Duration;

    fn dummy_public_key() -> crate::x25519::PublicKey {
        crate::x25519::PublicKey::from([42u8; 32])
    }

    #[test]
    fn test_rate_limiter_creation() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        assert_eq!(rate_limiter.limit, 100);
        assert_eq!(rate_limiter.count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_under_load_detection() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 5);
        
        // Should not be under load initially
        assert!(!rate_limiter.is_under_load()); // count: 1
        assert!(!rate_limiter.is_under_load()); // count: 2
        assert!(!rate_limiter.is_under_load()); // count: 3
        assert!(!rate_limiter.is_under_load()); // count: 4
        assert!(!rate_limiter.is_under_load()); // count: 5
        
        // Should be under load now
        assert!(rate_limiter.is_under_load()); // count: 6
        assert!(rate_limiter.is_under_load()); // count: 7
    }

    #[test]
    fn test_reset_count() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 3);
        
        // Fill up the counter
        assert!(!rate_limiter.is_under_load()); // count: 1
        assert!(!rate_limiter.is_under_load()); // count: 2  
        assert!(!rate_limiter.is_under_load()); // count: 3
        assert!(rate_limiter.is_under_load());  // count: 4 (over limit)
        
        // Reset should clear the counter
        rate_limiter.reset_count();
        
        // Should not be under load immediately after reset
        assert!(!rate_limiter.is_under_load()); // count: 1
    }

    #[test]
    fn test_reset_count_timing() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 1);
        
        // Force to be under load
        assert!(!rate_limiter.is_under_load()); // count: 1
        assert!(rate_limiter.is_under_load());  // count: 2
        
        // Reset immediately (should not reset due to timing)
        rate_limiter.reset_count();
        assert!(rate_limiter.is_under_load());  // Still under load
        
        // Manually set last reset time to past  
        // Note: We can't subtract Duration from sleepyinstant::Instant
        // So we'll simulate the timing condition differently
        thread::sleep(Duration::from_millis(50));
        
        // Now reset should work
        rate_limiter.reset_count();
        assert!(!rate_limiter.is_under_load()); // Should reset
    }

    #[test]
    fn test_current_cookie_ipv4() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let addr_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let cookie1 = rate_limiter.current_cookie(addr_v4);
        let cookie2 = rate_limiter.current_cookie(addr_v4);
        
        // Same IP should produce same cookie (within same time window)
        assert_eq!(cookie1, cookie2);
        assert_eq!(cookie1.len(), COOKIE_SIZE);
    }

    #[test]
    fn test_current_cookie_ipv6() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let addr_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let cookie1 = rate_limiter.current_cookie(addr_v6);
        let cookie2 = rate_limiter.current_cookie(addr_v6);
        
        // Same IP should produce same cookie (within same time window)
        assert_eq!(cookie1, cookie2);
        assert_eq!(cookie1.len(), COOKIE_SIZE);
    }

    #[test]
    fn test_current_cookie_different_ips() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let addr_v4_1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr_v4_2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        let cookie1 = rate_limiter.current_cookie(addr_v4_1);
        let cookie2 = rate_limiter.current_cookie(addr_v4_2);
        
        // Different IPs should produce different cookies
        assert_ne!(cookie1, cookie2);
    }

    #[test]
    fn test_nonce_generation() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let nonce1 = rate_limiter.nonce();
        let nonce2 = rate_limiter.nonce();
        
        // Each nonce should be different (counter-based)
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), COOKIE_NONCE_SIZE);
        assert_eq!(nonce2.len(), COOKIE_NONCE_SIZE);
    }

    #[test]
    fn test_nonce_counter_increment() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let initial_counter = rate_limiter.nonce_ctr.load(Ordering::Relaxed);
        let _ = rate_limiter.nonce(); // Should increment counter
        let after_counter = rate_limiter.nonce_ctr.load(Ordering::Relaxed);
        
        assert_eq!(after_counter, initial_counter + 1);
    }

    #[test]
    fn test_format_cookie_reply() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let cookie = [42u8; 16];
        let mac1 = [0x12u8; 16];
        let sender_idx = 0x12345678;
        let mut buffer = [0u8; 64]; // Larger than COOKIE_REPLY_SZ
        
        let result = rate_limiter.format_cookie_reply(sender_idx, cookie, &mac1, &mut buffer);
        assert!(result.is_ok());
        
        let packet = result.unwrap();
        assert_eq!(packet.len(), super::super::COOKIE_REPLY_SZ);
        
        // Check message type (should be 3 for cookie reply)
        let message_type = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(message_type, super::super::COOKIE_REPLY);
    }

    #[test]
    fn test_format_cookie_reply_buffer_too_small() {
        let public_key = dummy_public_key();
        let rate_limiter = RateLimiter::new(&public_key, 100);
        
        let cookie = [42u8; 16];
        let mac1 = [0x12u8; 16];
        let sender_idx = 0x12345678;
        let mut small_buffer = [0u8; 10]; // Too small
        
        let result = rate_limiter.format_cookie_reply(sender_idx, cookie, &mac1, &mut small_buffer);
        assert!(matches!(result, Err(WireGuardError::DestinationBufferTooSmall)));
    }

    #[test]
    fn test_rand_bytes_generation() {
        let bytes1 = RateLimiter::rand_bytes();
        let bytes2 = RateLimiter::rand_bytes();
        
        // Random bytes should be different
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
    }

    #[test]
    fn test_concurrent_access() {
        let public_key = dummy_public_key();
        let rate_limiter = std::sync::Arc::new(RateLimiter::new(&public_key, 10));
        
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let limiter = std::sync::Arc::clone(&rate_limiter);
                thread::spawn(move || {
                    for _ in 0..5 {
                        let _ = limiter.is_under_load();
                        let _ = limiter.nonce();
                        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
                        let _ = limiter.current_cookie(addr);
                    }
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should have processed all requests without panic
        assert!(rate_limiter.count.load(Ordering::SeqCst) >= 20);
    }

    #[test]
    fn test_mac1_key_generation() {
        let public_key = dummy_public_key();
        let rate_limiter1 = RateLimiter::new(&public_key, 100);
        let rate_limiter2 = RateLimiter::new(&public_key, 100);
        
        // Same public key should produce same mac1_key
        assert_eq!(rate_limiter1.mac1_key, rate_limiter2.mac1_key);
        
        // Different public key should produce different mac1_key
        let different_key = crate::x25519::PublicKey::from([99u8; 32]);
        let rate_limiter3 = RateLimiter::new(&different_key, 100);
        assert_ne!(rate_limiter1.mac1_key, rate_limiter3.mac1_key);
    }
}
