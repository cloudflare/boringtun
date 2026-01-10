// Protocol fuzzing tests for packet parsers and handlers
// These tests validate robust handling of malformed and edge-case inputs

use boringtun::noise::{Tunn, TunnResult};
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::device::peer::{AllowedIP, Peer};
use boringtun::x25519;
use proptest::prelude::*;
use std::net::IpAddr;
use std::str::FromStr;

// Generate arbitrary packet-like data for fuzzing
fn arbitrary_packet_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

// Generate packet data that looks like it might be valid WireGuard
fn wireguard_like_packet() -> impl Strategy<Value = Vec<u8>> {
    (1u8..=4, prop::collection::vec(any::<u8>(), 20..=1500))
        .prop_map(|(msg_type, mut data)| {
            // Set first 4 bytes to look like a message type
            if data.len() >= 4 {
                data[0] = msg_type;
                data[1] = 0;
                data[2] = 0; 
                data[3] = 0;
            }
            data
        })
}

proptest! {
    #[test]
    fn fuzz_tunnel_decapsulation(data in arbitrary_packet_data()) {
        // Decapsulation should never panic, even with garbage data
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([1u8; 32]);
        let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
        let mut dst = vec![0u8; 2048];
        
        match tunnel.decapsulate(None, &data, &mut dst) {
            TunnResult::Done | TunnResult::Err(_) | TunnResult::WriteToNetwork(_) | 
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                // Any result is fine - just shouldn't panic
            }
        }
    }

    #[test] 
    fn fuzz_tunnel_encapsulation(data in wireguard_like_packet()) {
        // Encapsulation should handle various data sizes safely
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([2u8; 32]);
        let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
        let mut dst = vec![0u8; 2048];
        
        match tunnel.encapsulate(&data, &mut dst) {
            TunnResult::Done | TunnResult::Err(_) | TunnResult::WriteToNetwork(_) => {
                // Any of these results is acceptable
            }
            _ => {
                // Other results are also fine
            }
        }
    }

    #[test]
    fn fuzz_rate_limiter_verify_packet(
        packet_data in arbitrary_packet_data(),
        ip_bytes in prop::option::of(prop::array::uniform4(any::<u8>()))
    ) {
        let public_key = x25519::PublicKey::from([42u8; 32]);
        let rate_limiter = RateLimiter::new(&public_key, 10);
        
        let src_addr = ip_bytes.map(|bytes| {
            IpAddr::V4(std::net::Ipv4Addr::from(bytes))
        });
        
        let mut dst = vec![0u8; 2048];
        
        // Rate limiter should handle any packet data safely
        match rate_limiter.verify_packet(src_addr, &packet_data, &mut dst) {
            Ok(_) => {
                // Verification succeeded
            }
            Err(_) => {
                // Verification failed, which is fine for random data
            }
        }
    }

    #[test]
    fn fuzz_allowed_ip_parsing(ip_str in ".*") {
        // AllowedIP parsing should handle any string safely
        match AllowedIP::from_str(&ip_str) {
            Ok(allowed_ip) => {
                // If parsing succeeds, validate the result
                prop_assert!(allowed_ip.cidr <= 128); // Valid CIDR range
                match allowed_ip.addr {
                    IpAddr::V4(_) => prop_assert!(allowed_ip.cidr <= 32),
                    IpAddr::V6(_) => prop_assert!(allowed_ip.cidr <= 128),
                }
            }
            Err(_) => {
                // Parsing failure is expected for most random strings
            }
        }
    }

    #[test]
    fn fuzz_tunnel_operations(
        packet_data in arbitrary_packet_data(),
        dst_size in 100usize..=2048
    ) {
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([99u8; 32]);
        let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
        
        let mut dst = vec![0u8; dst_size];
        
        // All tunnel operations should be robust against malformed input
        
        // Test encapsulation with random data
        match tunnel.encapsulate(&packet_data, &mut dst) {
            TunnResult::Done => {},
            TunnResult::Err(_) => {},
            TunnResult::WriteToNetwork(_) => {},
            _ => prop_assert!(false, "Unexpected encapsulate result"),
        }
        
        // Test decapsulation with random data
        match tunnel.decapsulate(None, &packet_data, &mut dst) {
            TunnResult::Done => {},
            TunnResult::Err(_) => {},
            TunnResult::WriteToNetwork(_) => {},
            TunnResult::WriteToTunnelV4(_, _) => {},
            TunnResult::WriteToTunnelV6(_, _) => {},
        }
        
        // Test timer updates
        match tunnel.update_timers(&mut dst) {
            TunnResult::Done => {},
            TunnResult::Err(_) => {},
            TunnResult::WriteToNetwork(_) => {},
            _ => prop_assert!(false, "Unexpected timer result"),
        }
    }

    #[test]
    fn fuzz_peer_ip_filtering(
        ip_bytes in prop::array::uniform16(any::<u8>()),
        test_ip_bytes in prop::array::uniform4(any::<u8>())
    ) {
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([1u8; 32]);
        let tunnel = Tunn::new(private_key, public_key, None, None, 0, None);
        
        // Create allowed IPs that might be valid
        let allowed_ips = vec![
            AllowedIP::from_str("0.0.0.0/0").unwrap(),    // Allow all IPv4
            AllowedIP::from_str("::/0").unwrap(),          // Allow all IPv6  
        ];
        
        let peer = Peer::new(tunnel, 1, None, &allowed_ips, None);
        
        // Test with various IP addresses
        let test_ipv4 = IpAddr::V4(std::net::Ipv4Addr::from(test_ip_bytes));
        let test_ipv6 = IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes));
        
        // These should always be allowed due to our 0.0.0.0/0 and ::/0 rules
        prop_assert!(peer.is_allowed_ip(test_ipv4));
        prop_assert!(peer.is_allowed_ip(test_ipv6));
    }
}

// Specific edge case tests
#[test]
fn test_empty_packet() {
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    let mut dst = vec![0u8; 1024];
    
    let empty = vec![];
    // Should handle empty packets gracefully
    let _ = tunnel.decapsulate(None, &empty, &mut dst);
}

#[test]
fn test_single_byte_packets() {
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    let mut dst = vec![0u8; 1024];
    
    for byte in 0u8..=255 {
        let packet = vec![byte];
        // Should not panic
        let _ = tunnel.decapsulate(None, &packet, &mut dst);
    }
}

#[test]
fn test_oversized_packet() {
    let huge_packet = vec![0u8; 100000]; // Much larger than MTU
    
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    
    let mut dst = vec![0u8; 2048];
    
    // Should handle gracefully, not panic
    match tunnel.encapsulate(&huge_packet, &mut dst) {
        TunnResult::Done => {},
        TunnResult::Err(_) => {}, // Expected for oversized packet
        _ => {}
    }
}

#[test]
fn test_malformed_message_types() {
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    let mut dst = vec![0u8; 1024];
    
    // Test various invalid message type values
    for msg_type in [0u8, 5, 255] {
        let mut packet = vec![0u8; 32];
        packet[0] = msg_type;
        
        // Should not panic, handle gracefully
        let _ = tunnel.decapsulate(None, &packet, &mut dst);
    }
}

#[test]
fn test_truncated_packets() {
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    let mut dst = vec![0u8; 1024];
    
    // Test packets that claim to be valid types but are too short
    let message_types = [1u8, 2, 3, 4]; // Valid WireGuard message types
    
    for &msg_type in &message_types {
        for len in 1..=20 { // Various short lengths
            let mut packet = vec![0u8; len];
            if !packet.is_empty() {
                packet[0] = msg_type;
            }
            
            // Should handle truncated packets gracefully
            let _ = tunnel.decapsulate(None, &packet, &mut dst);
        }
    }
}

#[test]
fn test_rate_limiter_with_invalid_ips() {
    let public_key = x25519::PublicKey::from([42u8; 32]);
    let rate_limiter = RateLimiter::new(&public_key, 5);
    
    let mut dst = vec![0u8; 1024];
    
    // Test with various edge case IPs
    let test_ips = [
        None,
        Some(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        Some(IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255))),
        Some(IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
        Some(IpAddr::V6(std::net::Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff))),
    ];
    
    for ip in test_ips {
        let packet = vec![1, 0, 0, 0]; // Minimal packet
        let _ = rate_limiter.verify_packet(ip, &packet, &mut dst);
    }
}

#[test]
fn test_concurrent_fuzzing() {
    use std::sync::Arc;
    use std::thread;
    
    let public_key = x25519::PublicKey::from([99u8; 32]);
    let rate_limiter = Arc::new(RateLimiter::new(&public_key, 100));
    
    let handles: Vec<_> = (0..4).map(|_| {
        let limiter = Arc::clone(&rate_limiter);
        thread::spawn(move || {
            for i in 0..50 {
                let packet = vec![i as u8; (i % 100) + 10];
                let mut dst = vec![0u8; 1024];
                let ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    192, 168, (i % 256) as u8, 1
                )));
                
                // Should handle concurrent access safely
                let _ = limiter.verify_packet(ip, &packet, &mut dst);
            }
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_memory_exhaustion_resistance() {
    let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
    let public_key = x25519::PublicKey::from([1u8; 32]);
    let mut tunnel = Tunn::new(private_key, public_key, None, None, 1, None);
    
    // Test with many operations to check for memory leaks
    for i in 0..1000 {
        let packet = vec![(i % 256) as u8; 64];
        let mut dst = vec![0u8; 1024];
        
        let _ = tunnel.encapsulate(&packet, &mut dst);
        let _ = tunnel.decapsulate(None, &packet, &mut dst);
        let _ = tunnel.update_timers(&mut dst);
    }
    
    // If we get here without OOM, the test passes
}