use super::super::crypto::blake2s::*;
use super::super::crypto::chacha20poly1305::*;
use super::super::crypto::x25519::*;
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
        total_duration.as_secs() as f64 + total_duration.subsec_nanos() as f64 * 1e-9;
    let hashed = (hashed as f64) / (1024. * 1024.);

    format!("{:.2} MiB/sec", hashed / duration_in_seconds)
}

fn bench_chacha20poly1305(name: bool, n: usize) -> String {
    if name {
        return format!("AEAD Seal {}B: ", n);
    }

    let buf_in = vec![0u8; n];
    let mut buf_out = vec![0u8; n + 16];
    let mut enced = 0;

    let start_time = Instant::now();

    let aead = ChaCha20Poly1305::new_aead(&[0u8; 32]);

    loop {
        for _i in 0..100 {
            enced += aead.seal_wg(0, &[], &buf_in, &mut buf_out) - 16;
        }

        if Instant::now().duration_since(start_time).as_secs() >= 3 {
            break;
        }
    }

    let total_duration = Instant::now().duration_since(start_time);
    let duration_in_seconds =
        total_duration.as_secs() as f64 + total_duration.subsec_nanos() as f64 * 1e-9;
    let enced = (enced as f64) / (1024. * 1024.);

    format!("{:.2} MiB/sec", enced / duration_in_seconds)
}

fn bench_blake2s_128(name: bool) -> String {
    return bench_blake2s(name, 128);
}

fn bench_blake2s_8192(name: bool) -> String {
    return bench_blake2s(name, 8192);
}

fn bench_chacha20poly1305_128(name: bool) -> String {
    return bench_chacha20poly1305(name, 128);
}

fn bench_chacha20poly1305_192(name: bool) -> String {
    return bench_chacha20poly1305(name, 192);
}

fn bench_chacha20poly1305_1300(name: bool) -> String {
    return bench_chacha20poly1305(name, 1300);
}

fn bench_chacha20poly1305_8192(name: bool) -> String {
    return bench_chacha20poly1305(name, 8192);
}

fn bench_x25519_shared_key(name: bool) -> String {
    if name {
        return format!("X25519 Shared Key: ");
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
        total_duration.as_secs() as f64 + total_duration.subsec_nanos() as f64 * 1e-9;
    let x255 = x255 as f64;

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

fn bench_x25519_pub_key(name: bool) -> String {
    if name {
        return format!("X25519 Public Key: ");
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
        total_duration.as_secs() as f64 + total_duration.subsec_nanos() as f64 * 1e-9;
    let x255 = x255 as f64;

    format!("{:.2} ops/sec", x255 / duration_in_seconds)
}

pub fn do_benchmark(name: bool, idx: usize) -> Option<String> {
    let benchmarks: Vec<fn(bool) -> String> = vec![
        bench_blake2s_128,
        bench_blake2s_8192,
        bench_chacha20poly1305_128,
        bench_chacha20poly1305_192,
        bench_chacha20poly1305_1300,
        bench_chacha20poly1305_8192,
        bench_x25519_pub_key,
        bench_x25519_shared_key,
    ];

    if idx >= benchmarks.len() {
        return None;
    }

    Some(benchmarks[idx](name))
}
