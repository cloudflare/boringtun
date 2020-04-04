// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// This module implements benchmarking code for use with the FFI bindings
use crate::crypto::blake2s::Blake2s;
use crate::crypto::chacha20poly1305::*;
use crate::crypto::x25519::*;
#[cfg(not(target_arch = "arm"))]
use ring::aead::*;
#[cfg(not(target_arch = "arm"))]
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

fn run_bench(test_func: &mut dyn FnMut() -> usize) -> f64 {
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

    let secret_key = X25519SecretKey::new();
    let public_key = X25519SecretKey::new().public_key();

    let result = run_bench(&mut move || {
        let _ = secret_key.shared_key(&public_key);
        1
    });

    format!("{} ops/sec", format_float(result))
}

fn bench_x25519_public_key(name: bool, _: usize) -> String {
    if name {
        return "X25519 Public Key: ".to_string();
    }

    let secret_key = X25519SecretKey::new();

    let result = run_bench(&mut move || {
        let _ = secret_key.public_key();
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

#[cfg(not(target_arch = "arm"))]
fn bench_chacha20poly1305_ring(name: bool, n: usize) -> String {
    if name {
        return format!("(Ring) AEAD Seal {}B: ", n);
    }

    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &[0x0fu8; 32]).unwrap());
    let mut buf_in = vec![0u8; n + 16];

    let result = run_bench(&mut move || {
        let tag_len = CHACHA20_POLY1305.tag_len();
        let buf_len = buf_in.len();
        key.seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf_in[..buf_len - tag_len],
        )
        .map(|tag| {
            buf_in[buf_len - tag_len..].copy_from_slice(tag.as_ref());
            buf_len
        })
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

#[cfg(not(target_arch = "arm"))]
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
    let peer_public_key_alg = &agreement::X25519;

    let result = run_bench(&mut move || {
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let my_public_key =
            agreement::UnparsedPublicKey::new(peer_public_key_alg, &peer_public_key);

        agreement::agree_ephemeral(
            my_private_key,
            &my_public_key,
            ring::error::Unspecified,
            |_key_material| Ok(()),
        )
        .unwrap();
        1
    });

    format!("{} ops/sec", format_float(result))
}

#[cfg(not(target_arch = "arm"))]
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
        #[cfg(not(target_arch = "arm"))]
        (bench_x25519_public_key_ring, 0),
        #[cfg(not(target_arch = "arm"))]
        (bench_x25519_shared_key_ring, 0),
        (bench_blake2s, 128),
        (bench_blake2s, 1024),
        (bench_chacha20poly1305, 128),
        (bench_chacha20poly1305, 192),
        (bench_chacha20poly1305, 1400),
        (bench_chacha20poly1305, 8192),
        #[cfg(not(target_arch = "arm"))]
        (bench_chacha20poly1305_ring, 128),
        #[cfg(not(target_arch = "arm"))]
        (bench_chacha20poly1305_ring, 192),
        #[cfg(not(target_arch = "arm"))]
        (bench_chacha20poly1305_ring, 1400),
        #[cfg(not(target_arch = "arm"))]
        (bench_chacha20poly1305_ring, 8192),
    ];

    if idx >= benchmarks.len() {
        return None;
    }

    let fnc = benchmarks[idx].0;
    let param = benchmarks[idx].1;
    Some(fnc(name, param))
}
