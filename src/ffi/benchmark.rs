use crypto::blake2s::*;
use crypto::chacha20poly1305::*;
use crypto::x25519::*;
use ring::aead::*;
use ring::{agreement, rand};

use std::time::Instant;

const ITR_DURATION: u64 = 1;
const ITRS: u64 = 3;

// Format f64 with US locale decimal separators
// We don't care about speed or efficiency here
// Assumes that f64 in this context is always smaller than u64::MAX and larger than 0
fn format_float(number: f64) -> String {
    let fract = number.fract();
    let mut integer = number.trunc() as u64;

    let mut formatted = format!("{:.2}", fract);
    if integer == 0 {
        // Return with the leading 0
        return formatted;
    }
    // Strip the 0
    formatted = formatted[1..].to_string();

    loop {
        let remainder = integer % 1000;
        integer /= 1000;

        if integer == 0 {
            let mut new_str = format!("{:}", remainder);
            new_str.push_str(&formatted);
            formatted = new_str;
            break;
        }

        let mut new_str = format!(",{:03}", remainder);
        new_str.push_str(&formatted);
        formatted = new_str;
    }

    formatted
}

fn run_bench(test_func: &mut FnMut() -> usize) -> f64 {
    let mut best_time = std::f64::MAX;

    // Take the best result out of ITRS runs
    for _ in 0..ITRS {
        let start_time = Instant::now();
        let mut total_itr = 0;
        loop {
            for _ in 0..300 {
                total_itr += test_func();
            }
            // Check time every 300 iterations
            let time_since_started = Instant::now().duration_since(start_time);
            if time_since_started.as_secs() >= ITR_DURATION {
                // Stop the benchmark after ITR_DURATION
                let total_time = time_since_started.as_secs() as f64
                    + f64::from(time_since_started.subsec_nanos()) * 1e-9;
                best_time = best_time.min((total_itr as f64) / total_time);
                break;
            }
        }
    }

    best_time
}

fn bench_x25519_shared_key(name: bool, _: usize) -> String {
    if name {
        return "X25519 Shared Key: ".to_string();
    }

    let secret_key = [0x0f; 32];
    let public_key = [0xf0; 32];

    let result = run_bench(&mut move || {
        let _ = x25519_shared_key(&secret_key, &public_key);
        1
    });

    format!("{} ops/sec", format_float(result))
}

fn bench_x25519_public_key(name: bool, _: usize) -> String {
    if name {
        return "X25519 Public Key: ".to_string();
    }

    let secret_key = [0x0f; 32];

    let result = run_bench(&mut move || {
        let _ = x25519_public_key(&secret_key);
        1
    });

    format!("{} ops/sec", format_float(result))
}

fn bench_blake2s(name: bool, n: usize) -> String {
    if name {
        return format!("Blake2s {}B: ", n);
    }

    let buf_in = vec![0u8; n];

    let result = run_bench(&mut move || {
        Blake2s::new_hash().hash(&buf_in).finalize();
        buf_in.len()
    });

    format!("{} MiB/s", format_float(result / (1024. * 1024.)))
}

fn bench_chacha20poly1305_ring(name: bool, n: usize) -> String {
    if name {
        return format!("(Ring) AEAD Seal {}B: ", n);
    }

    let key = SealingKey::new(&CHACHA20_POLY1305, &[0x0fu8; 32]).unwrap();
    let mut buf_in = vec![0u8; n + 16];

    let result = run_bench(&mut move || {
        seal_in_place(
            &key,
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf_in,
            16,
        )
        .unwrap()
    });

    format!("{} MiB/s", format_float(result / (1024. * 1024.)))
}

fn bench_chacha20poly1305(name: bool, n: usize) -> String {
    if name {
        return format!("AEAD Seal {}B: ", n);
    }

    let aead = ChaCha20Poly1305::new_aead(&[0u8; 32]);
    let buf_in = vec![0u8; n];
    let mut buf_out = vec![0u8; n + 16];

    let result = run_bench(&mut move || aead.seal_wg(0, &[], &buf_in, &mut buf_out) - 16);

    format!("{} MiB/s", format_float(result / (1024. * 1024.)))
}

fn bench_x25519_shared_key_ring(name: bool, _: usize) -> String {
    if name {
        return "(Ring) X25519 Shared Key: ".to_string();
    }

    let rng = rand::SystemRandom::new();

    let peer_public_key = {
        let peer_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        peer_private_key.compute_public_key().unwrap()
    };
    let peer_public_key = untrusted::Input::from(peer_public_key.as_ref());
    let peer_public_key_alg = &agreement::X25519;

    let result = run_bench(&mut move || {
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();

        agreement::agree_ephemeral(
            my_private_key,
            peer_public_key_alg,
            peer_public_key,
            ring::error::Unspecified,
            |_key_material| Ok(()),
        )
        .unwrap();
        1
    });

    format!("{} ops/sec", format_float(result))
}

fn bench_x25519_public_key_ring(name: bool, _: usize) -> String {
    if name {
        return "(Ring) X25519 Public Key: ".to_string();
    }

    let rng = rand::SystemRandom::new();

    let result = run_bench(&mut move || {
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        my_private_key.compute_public_key().unwrap();
        1
    });
    format!("{} ops/sec", format_float(result))
}

type BenchFnc = fn(bool, usize) -> String;

pub fn do_benchmark(name: bool, idx: usize) -> Option<String> {
    let benchmarks: Vec<(BenchFnc, usize)> = vec![
        (bench_x25519_public_key, 0),
        (bench_x25519_shared_key, 0),
        (bench_x25519_public_key_ring, 0),
        (bench_x25519_shared_key_ring, 0),
        (bench_blake2s, 128),
        (bench_blake2s, 1024),
        (bench_chacha20poly1305, 128),
        (bench_chacha20poly1305, 192),
        (bench_chacha20poly1305, 1400),
        (bench_chacha20poly1305, 8192),
        (bench_chacha20poly1305_ring, 128),
        (bench_chacha20poly1305_ring, 192),
        (bench_chacha20poly1305_ring, 1400),
        (bench_chacha20poly1305_ring, 8192),
    ];

    if idx >= benchmarks.len() {
        return None;
    }

    let fnc = benchmarks[idx].0;
    let param = benchmarks[idx].1;
    Some(fnc(name, param))
}
