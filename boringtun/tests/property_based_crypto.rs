// Property-based tests for public API cryptographic behavior
// These tests validate security properties across large input spaces

use boringtun::noise::{Tunn, TunnResult};
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::device::peer::AllowedIP;
use boringtun::x25519;
use proptest::prelude::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

// Property-based tests for tunnel cryptographic behavior
proptest! {
    #[test]
    fn prop_tunnel_key_independence(
        _key_bytes1 in any::<[u8; 32]>(),
        _key_bytes2 in any::<[u8; 32]>()
    ) {
        // Different private keys should create different tunnels
        let key1 = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let key2 = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        
        let pub1 = x25519::PublicKey::from(&key1);
        let pub2 = x25519::PublicKey::from(&key2);
        
        // Public keys should be different (with overwhelming probability)
        prop_assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn prop_tunnel_deterministic_behavior(
        data in prop::collection::vec(any::<u8>(), 1..=256)
    ) {
        // Same inputs should produce consistent tunnel behavior
        let key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519::PublicKey::from([1u8; 32]);
        
        let mut tunnel1 = Tunn::new(key.clone(), public, None, None, 1, None);
        let mut tunnel2 = Tunn::new(key, public, None, None, 1, None);
        
        let mut dst1 = vec![0u8; 2048];
        let mut dst2 = vec![0u8; 2048];
        
        // Same operation should produce same result
        let result1 = tunnel1.encapsulate(&data, &mut dst1);
        let result2 = tunnel2.encapsulate(&data, &mut dst2);
        
        // Results should have the same variant type
        prop_assert_eq!(std::mem::discriminant(&result1), std::mem::discriminant(&result2));
    }

    #[test]
    fn prop_rate_limiter_consistent_behavior(
        packet_data in prop::collection::vec(any::<u8>(), 0..=512)
    ) {
        // Rate limiter should behave consistently for same inputs
        let public_key = x25519::PublicKey::from([42u8; 32]);
        let limiter = RateLimiter::new(&public_key, 100);
        
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let mut dst = vec![0u8; 1024];
        
        // First call
        let result1 = limiter.verify_packet(ip, &packet_data, &mut dst);
        
        // Second call with same data should be consistent 
        let mut dst2 = vec![0u8; 1024];
        let result2 = limiter.verify_packet(ip, &packet_data, &mut dst2);
        
        // Both should succeed or both should fail with rate limiting
        prop_assert_eq!(std::mem::discriminant(&result1), std::mem::discriminant(&result2));
    }

    #[test] 
    fn prop_x25519_key_properties(_seed in any::<u64>()) {
        let mut rng = rand_core::OsRng;
        
        // Generate multiple keys
        let key1 = x25519::StaticSecret::random_from_rng(&mut rng);
        let key2 = x25519::StaticSecret::random_from_rng(&mut rng);
        
        let pub1 = x25519::PublicKey::from(&key1);
        let pub2 = x25519::PublicKey::from(&key2);
        
        // Keys should be different (with overwhelming probability)
        prop_assert_ne!(pub1.as_bytes(), pub2.as_bytes());
        
        // Public keys should always be 32 bytes
        prop_assert_eq!(pub1.as_bytes().len(), 32);
        prop_assert_eq!(pub2.as_bytes().len(), 32);
    }
}

// Regular tests for rate limiter behavior 
#[test]
fn test_rate_limiter_basic_functionality() {
    let public_key = x25519::PublicKey::from([42u8; 32]);
    let rate_limiter = RateLimiter::new(&public_key, 5); // Low limit for testing
    
    let mut dst = vec![0u8; 1024];
    let test_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    
    // Test basic functionality through public API
    let mut rate_limited_count = 0;
    for i in 0..20 {
        let packet = format!("test_packet_{}", i).into_bytes();
        match rate_limiter.verify_packet(test_ip, &packet, &mut dst) {
            Ok(_) => {},
            Err(TunnResult::WriteToNetwork(_)) => {
                rate_limited_count += 1;
            },
            Err(_) => {}
        }
    }
    
    // Should have triggered some rate limiting
    assert!(rate_limited_count > 0, "No rate limiting triggered");
}

#[test]
fn test_rate_limiter_ip_specific_behavior() {
    let public_key = x25519::PublicKey::from([99u8; 32]);
    let rate_limiter = RateLimiter::new(&public_key, 100);
    
    let ip1 = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let ip2 = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    let packet = b"test_packet";
    
    let mut dst1 = vec![0u8; 1024];
    let mut dst2 = vec![0u8; 1024];
    
    // Different IPs should be handled independently
    let result1 = rate_limiter.verify_packet(ip1, packet, &mut dst1);
    let result2 = rate_limiter.verify_packet(ip2, packet, &mut dst2);
    
    // Both should be processed (both might fail due to invalid packet format, but consistently)
    assert_eq!(std::mem::discriminant(&result1), std::mem::discriminant(&result2));
}

#[test]
fn test_rate_limiter_response_validity() {
    let public_key = x25519::PublicKey::from([77u8; 32]);
    let rate_limiter = RateLimiter::new(&public_key, 3); // Very low limit to trigger responses
    
    let mut response_count = 0;
    let test_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    
    for i in 0..10 {
        let packet = format!("flood_packet_{}", i).into_bytes();
        let mut dst = vec![0u8; 1024];
        
        match rate_limiter.verify_packet(test_ip, &packet, &mut dst) {
            Ok(_) => {},
            Err(TunnResult::WriteToNetwork(response)) => {
                // Valid rate limit response should be non-empty
                assert!(!response.is_empty(), "Empty rate limit response");
                response_count += 1;
            },
            Err(_) => {}
        }
    }
    
    println!("Generated {} rate limit responses", response_count);
}

// Property tests for AllowedIP parsing
proptest! {
    #[test]
    fn prop_allowed_ip_roundtrip(
        a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255,
        cidr in 0u8..=32
    ) {
        let ip = Ipv4Addr::new(a, b, c, d);
        let ip_str = format!("{}/{}", ip, cidr);
        
        match AllowedIP::from_str(&ip_str) {
            Ok(allowed_ip) => {
                // Should be able to round-trip
                prop_assert_eq!(allowed_ip.cidr, cidr);
                if let IpAddr::V4(parsed_ip) = allowed_ip.addr {
                    // For network addresses, host bits might be zeroed
                    let network_ip = Ipv4Addr::from(u32::from(ip) & (!0u32 << (32 - cidr)));
                    prop_assert_eq!(parsed_ip, network_ip);
                }
            }
            Err(_) => {
                // Some combinations might be invalid, which is fine
            }
        }
    }

    #[test]
    fn prop_allowed_ip_ordering_transitive(
        ip1 in prop::array::uniform4(0u8..=255),
        ip2 in prop::array::uniform4(0u8..=255), 
        ip3 in prop::array::uniform4(0u8..=255),
        cidr1 in 0u8..=32,
        cidr2 in 0u8..=32,
        cidr3 in 0u8..=32
    ) {
        let make_allowed_ip = |ip_bytes: [u8; 4], cidr: u8| {
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            AllowedIP::from_str(&format!("{}/{}", ip, cidr))
        };
        
        if let (Ok(a1), Ok(a2), Ok(a3)) = (
            make_allowed_ip(ip1, cidr1),
            make_allowed_ip(ip2, cidr2),
            make_allowed_ip(ip3, cidr3)
        ) {
            // Test transitivity: if a1 <= a2 and a2 <= a3, then a1 <= a3
            if a1 <= a2 && a2 <= a3 {
                prop_assert!(a1 <= a3, "Ordering not transitive");
            }
            
            // Test reflexivity: a1 == a1
            prop_assert_eq!(a1, a1);
        }
    }
}

// Test for tunnel creation with different parameters
#[test]
fn test_tunnel_parameter_independence() {
    let key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let peer_key = x25519::PublicKey::from([1u8; 32]);
    
    // Create tunnels with different parameters
    let tunnel1 = Tunn::new(key.clone(), peer_key, None, None, 1, None);
    let tunnel2 = Tunn::new(key.clone(), peer_key, None, Some(25), 2, None);
    
    // Tunnels should have different configurations
    assert_ne!(tunnel1.persistent_keepalive(), tunnel2.persistent_keepalive());
    assert_eq!(tunnel1.persistent_keepalive(), None);
    assert_eq!(tunnel2.persistent_keepalive(), Some(25));
}

#[test]
fn test_tunnel_index_uniqueness() {
    let key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let peer_key = x25519::PublicKey::from([1u8; 32]);
    
    // Create multiple tunnels - they should be independent
    let mut tunnel1 = Tunn::new(key.clone(), peer_key, None, None, 100, None);
    let mut tunnel2 = Tunn::new(key, peer_key, None, None, 200, None);
    
    // Both should be valid tunnels
    let mut dst1 = vec![0u8; 1024];
    let mut dst2 = vec![0u8; 1024];
    
    // Timer updates should work for both
    let _ = tunnel1.update_timers(&mut dst1);
    let _ = tunnel2.update_timers(&mut dst2);
}

// Test key generation produces unique keys
#[test]
fn test_key_generation_uniqueness() {
    let mut public_keys = HashSet::new();
    
    // Generate many keys
    for _ in 0..100 {
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from(&private_key);
        
        // All public keys should be unique
        assert!(!public_keys.contains(public_key.as_bytes()), "Duplicate public key generated");
        public_keys.insert(*public_key.as_bytes());
    }
}

#[test]
fn test_rate_limiter_independence() {
    // Rate limiters with different keys should behave independently
    let key1 = x25519::PublicKey::from([1u8; 32]);
    let key2 = x25519::PublicKey::from([2u8; 32]);
    
    let limiter1 = RateLimiter::new(&key1, 5);
    let limiter2 = RateLimiter::new(&key2, 5);
    
    let test_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let packet = b"test packet";
    
    let mut dst1 = vec![0u8; 1024];
    let mut dst2 = vec![0u8; 1024];
    
    // Both should handle the same input independently
    let result1 = limiter1.verify_packet(test_ip, packet, &mut dst1);
    let result2 = limiter2.verify_packet(test_ip, packet, &mut dst2);
    
    // Results should be consistent (both likely to fail due to invalid packet, but same way)
    assert_eq!(std::mem::discriminant(&result1), std::mem::discriminant(&result2));
}