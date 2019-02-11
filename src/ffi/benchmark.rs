use super::super::crypto::blake2s::*;
use super::super::crypto::x25519::*;
use ring::aead::*;
use ring::{agreement, rand};

use std::time::Instant;

fn bench_blake2s(name: bool, n: usize) -> String {
    if name {
        return format!("Blake2s {}B: ", n);
    }

    let buf_in = vec![0u8; n];
    let mut hashed = 0;

    let start_time = Instant::now();

    loop {
        for _i in 0..100 {
            hashed += n;
            Blake2s::new_hash().hash(&buf_in).finalize();
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let hashed = (hashed as f64) / (1024. * 1024.);

    format!("{:.2} MiB/sec", hashed / duration_in_seconds)
}

fn bench_chacha20poly1305(name: bool, n: usize) -> String {
    if name {
        return format!("AEAD Seal {}B: ", n);
    }

    let mut buf_out = vec![0u8; n + 16];
    let mut enced = 0;

    let start_time = Instant::now();
    let key = SealingKey::new(&CHACHA20_POLY1305, &[0u8; 32]).unwrap();

    loop {
        for _i in 0..100 {
            enced += seal_in_place(
                &key,
                Nonce::assume_unique_for_key([0u8; 12]),
                Aad::from(&[]),
                &mut buf_out,
                16,
            )
            .unwrap();
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let enced = (enced as f64) / (1024. * 1024.);

    format!("{:.2} MiB/sec", enced / duration_in_seconds)
}

fn bench_blake2s_128(name: bool) -> String {
    bench_blake2s(name, 128)
}

fn bench_blake2s_8192(name: bool) -> String {
    bench_blake2s(name, 8192)
}

fn bench_chacha20poly1305_128(name: bool) -> String {
    bench_chacha20poly1305(name, 128)
}

fn bench_chacha20poly1305_192(name: bool) -> String {
    bench_chacha20poly1305(name, 192)
}

fn bench_chacha20poly1305_1300(name: bool) -> String {
    bench_chacha20poly1305(name, 1300)
}

fn bench_chacha20poly1305_8192(name: bool) -> String {
    bench_chacha20poly1305(name, 8192)
}

fn bench_x25519_shared_key(name: bool) -> String {
    if name {
        return "X25519 Shared Key: ".to_string();
    }

    let mut x255 = 0;
    let mut key = [0u8; 32];
    let key2 = [0u8; 32];

    let start_time = Instant::now();

    loop {
        for _i in 0..100 {
            key = x25519_shared_key(&key, &key2);
            x255 += 1;
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let x255 = f64::from(x255);

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

fn bench_ring_shared_key(name: bool) -> String {
    if name {
        return "RING shared key: ".to_string();
    }

    let mut x255 = 0;
    let rng = rand::SystemRandom::new();

    let peer_public_key = {
        let peer_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        peer_private_key.compute_public_key().unwrap()
    };
    let peer_public_key = untrusted::Input::from(peer_public_key.as_ref());

    let peer_public_key_alg = &agreement::X25519;

    let start_time = Instant::now();

    // Make `my_public_key` a byte slice containing my public key. In a real
    // application, this would be sent to the peer in an encoded protocol
    // message.

    loop {
        for _i in 0..100 {
            let my_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();

            agreement::agree_ephemeral(
                my_private_key,
                peer_public_key_alg,
                peer_public_key,
                ring::error::Unspecified,
                |_key_material| {
                    // In a real application, we'd apply a KDF to the key material and the
                    // public keys (as recommended in RFC 7748) and then derive session
                    // keys from the result. We omit all that here.
                    Ok(())
                },
            )
            .unwrap();
            x255 += 1;
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let x255 = f64::from(x255);

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

fn bench_ring_pub_key(name: bool) -> String {
    if name {
        return "RING public key: ".to_string();
    }

    let mut x255 = 0;
    let rng = rand::SystemRandom::new();

    let start_time = Instant::now();

    loop {
        for _i in 0..100 {
            let my_private_key =
                agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            my_private_key.compute_public_key().unwrap();
            x255 += 1;
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let x255 = f64::from(x255);

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

fn bench_x25519_pub_key(name: bool) -> String {
    if name {
        return "X25519 Public Key: ".to_string();
    }

    let mut x255 = 0;
    let mut key = [0u8; 32];

    let start_time = Instant::now();

    loop {
        for _i in 0..100 {
            key = x25519_public_key(&key);
            x255 += 1;
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + f64::from(total_duration.subsec_nanos()) * 1e-9;
    let x255 = f64::from(x255);

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

pub fn do_benchmark(name: bool, idx: usize) -> Option<String> {
    let benchmarks: Vec<fn(bool) -> String> = vec![
        bench_x25519_pub_key,
        bench_x25519_shared_key,
        bench_ring_pub_key,
        bench_ring_shared_key,
        bench_blake2s_128,
        bench_blake2s_8192,
        bench_chacha20poly1305_128,
        bench_chacha20poly1305_192,
        bench_chacha20poly1305_1300,
        bench_chacha20poly1305_8192,
    ];

    if idx >= benchmarks.len() {
        return None;
    }

    Some(benchmarks[idx](name))
}
